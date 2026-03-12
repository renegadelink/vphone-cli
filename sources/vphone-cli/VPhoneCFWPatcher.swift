import Capstone
import FirmwarePatcher
import Foundation

enum VPhoneCFWPatcherError: Error, CustomStringConvertible {
    case notMachO(String)
    case missingSection([String])
    case symbolNotFound(String)
    case patchSiteNotFound(String)
    case invalidAddress(UInt64)

    var description: String {
        switch self {
        case let .notMachO(path):
            return "Not a 64-bit Mach-O: \(path)"
        case let .missingSection(candidates):
            return "Missing Mach-O section: \(candidates.joined(separator: ", "))"
        case let .symbolNotFound(symbol):
            return "Symbol not found: \(symbol)"
        case let .patchSiteNotFound(message):
            return message
        case let .invalidAddress(address):
            return String(format: "Invalid virtual address: 0x%llX", address)
        }
    }
}

private func readLE<T: FixedWidthInteger>(_ data: Data, at offset: Int) -> T {
    precondition(offset >= 0 && offset + MemoryLayout<T>.size <= data.count)
    var value: T = .zero
    _ = Swift.withUnsafeMutableBytes(of: &value) { destination in
        data.copyBytes(to: destination, from: offset ..< offset + MemoryLayout<T>.size)
    }
    return T(littleEndian: value)
}

struct VPhoneCFWPatcher {
    let binaryURL: URL
    let disassembler = ARM64Disassembler.shared

    private(set) var buffer: BinaryBuffer
    private let sections: [String: MachOSectionInfo]
    private let segments: [MachOSegmentInfo]

    init(binaryURL: URL) throws {
        self.binaryURL = binaryURL
        let data = try Data(contentsOf: binaryURL)
        let magic: UInt32 = readLE(data, at: 0)
        guard magic == 0xFEED_FACF else {
            throw VPhoneCFWPatcherError.notMachO(binaryURL.path)
        }
        buffer = BinaryBuffer(data)
        sections = MachOParser.parseSections(from: data)
        segments = MachOParser.parseSegments(from: data)
    }

    mutating func writeBack() throws {
        try buffer.data.write(to: binaryURL)
    }

    mutating func patchLaunchdCacheLoader() throws {
        let text = try requireSection("__TEXT,__text")
        let anchors = ["unsecure_cache", "unsecure", "cache_valid", "validation"]

        for anchor in anchors {
            guard let anchorRange = buffer.data.range(of: Data(anchor.utf8)) else { continue }
            guard let anchorSection = section(containingFileOffset: anchorRange.lowerBound) else { continue }

            let stringStart = findCStringStart(containing: anchorRange.lowerBound, sectionFileOffset: Int(anchorSection.fileOffset))
            let stringStartVA = anchorSection.address + UInt64(stringStart - Int(anchorSection.fileOffset))
            let substringVA = anchorSection.address + UInt64(anchorRange.lowerBound - Int(anchorSection.fileOffset))

            let refFileOffset = findAdrpAddReference(in: text, targetVA: stringStartVA)
                ?? findAdrpAddReference(in: text, targetVA: substringVA)
            guard let refFileOffset else { continue }

            guard let branchOffset = findConditionalBranch(after: refFileOffset, text: text) else { continue }

            let contextStart = max(Int(text.fileOffset), branchOffset - 8)
            print("  Before:")
            logDisassembly(at: contextStart, count: 5, marker: branchOffset)
            buffer.writeBytes(at: branchOffset, bytes: ARM64.nop)
            print("  After:")
            logDisassembly(at: contextStart, count: 5, marker: branchOffset)
            print(String(format: "  [+] NOPped at 0x%X", branchOffset))
            return
        }

        throw VPhoneCFWPatcherError.patchSiteNotFound("Dynamic anchor not found for launchd_cache_loader")
    }

    mutating func patchMobileactivationd() throws {
        var impFileOffset: Int?

        if let impVA = MachOParser.findSymbol(containing: "should_hactivate", in: buffer.data) {
            impFileOffset = MachOParser.vaToFileOffset(impVA, segments: segments)
        }
        if impFileOffset == nil {
            impFileOffset = try findShouldHactivateViaObjCMetadata()
        }

        guard let patchOffset = impFileOffset else {
            throw VPhoneCFWPatcherError.patchSiteNotFound("Dynamic anchor not found for should_hactivate")
        }
        guard patchOffset + 8 <= buffer.count else {
            throw VPhoneCFWPatcherError.patchSiteNotFound(String(format: "IMP offset out of bounds: 0x%X", patchOffset))
        }

        print("  Before:")
        logDisassembly(at: patchOffset, count: 4, marker: patchOffset)
        buffer.writeBytes(at: patchOffset, bytes: ARM64.movX0_1)
        buffer.writeBytes(at: patchOffset + 4, bytes: ARM64.ret)
        print("  After:")
        logDisassembly(at: patchOffset, count: 4, marker: patchOffset)
        print(String(format: "  [+] Patched at 0x%X: mov x0, #1; ret", patchOffset))
    }

    mutating func patchLaunchdJetsam() throws {
        let text = try requireSection("__TEXT,__text")
        let condMnemonics: Set<String> = [
            "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo",
            "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls",
            "b.ge", "b.lt", "b.gt", "b.le", "cbz", "cbnz", "tbz", "tbnz",
        ]
        let anchors = [
            "jetsam property category (Daemon) is not initialized",
            "jetsam property category",
            "initproc exited -- exit reason namespace 7 subcode 0x1",
        ]

        for anchor in anchors {
            guard let hitRange = buffer.data.range(of: Data(anchor.utf8)) else { continue }
            guard let hitSection = section(containingFileOffset: hitRange.lowerBound) else { continue }

            let stringStart = findCStringStart(containing: hitRange.lowerBound, sectionFileOffset: Int(hitSection.fileOffset))
            let stringStartVA = hitSection.address + UInt64(stringStart - Int(hitSection.fileOffset))
            guard let refOffset = findAdrpAddReference(in: text, targetVA: stringStartVA) else { continue }

            print("  Found jetsam anchor '\(anchor)'")
            print(String(format: "    string start: va:0x%llX", stringStartVA))
            print(String(format: "    xref at foff:0x%X", refOffset))

            let scanLowerBound = max(Int(text.fileOffset), refOffset - 0x300)
            var patchOffset: Int?
            var patchTarget: Int?

            for offset in stride(from: refOffset - 4, through: scanLowerBound, by: -4) {
                guard let instruction = instruction(at: offset) else { continue }
                guard condMnemonics.contains(instruction.mnemonic) else { continue }
                guard let targetVA = decodeLastImmediate(from: instruction.operandString) else { continue }
                guard let targetOffset = MachOParser.vaToFileOffset(targetVA, segments: segments) else { continue }
                guard targetOffset >= Int(text.fileOffset),
                      targetOffset < Int(text.fileOffset) + Int(text.size),
                      isReturnBlock(at: targetOffset, text: text)
                else {
                    continue
                }
                patchOffset = offset
                patchTarget = targetOffset
            }

            guard let patchOffset, let patchTarget else { continue }
            guard let branchBytes = ARM64Encoder.encodeB(from: patchOffset, to: patchTarget) else {
                throw VPhoneCFWPatcherError.patchSiteNotFound("Jetsam branch target out of range")
            }

            let contextStart = max(Int(text.fileOffset), patchOffset - 8)
            print("  Before:")
            logDisassembly(at: contextStart, count: 5, marker: patchOffset)
            buffer.writeBytes(at: patchOffset, bytes: branchBytes)
            print("  After:")
            logDisassembly(at: contextStart, count: 5, marker: patchOffset)
            print(String(format: "  [+] Patched at 0x%X: jetsam panic guard bypass", patchOffset))
            return
        }

        throw VPhoneCFWPatcherError.patchSiteNotFound("Dynamic jetsam anchor/xref not found")
    }

    func requireSection(_ candidates: String...) throws -> MachOSectionInfo {
        for candidate in candidates {
            if let section = sections[candidate] {
                return section
            }
        }
        throw VPhoneCFWPatcherError.missingSection(candidates)
    }

    func section(containingFileOffset offset: Int) -> MachOSectionInfo? {
        sections.values.first {
            let start = Int($0.fileOffset)
            let end = start + Int($0.size)
            return offset >= start && offset < end
        }
    }

    func findCStringStart(containing matchOffset: Int, sectionFileOffset: Int) -> Int {
        var cursor = matchOffset - 1
        while cursor >= sectionFileOffset, buffer.data[cursor] != 0 {
            cursor -= 1
        }
        return cursor + 1
    }

    func findAdrpAddReference(in text: MachOSectionInfo, targetVA: UInt64) -> Int? {
        let targetPage = targetVA & ~0xFFF
        let targetPageOffset = UInt32(targetVA & 0xFFF)
        let textStart = Int(text.fileOffset)
        let textEnd = textStart + Int(text.size)
        var adrpCache: [UInt32: (fileOffset: Int, page: UInt64, index: Int)] = [:]
        var index = 0

        for fileOffset in stride(from: textStart, to: textEnd - 3, by: 4) {
            let instruction = buffer.readU32(at: fileOffset)

            if instruction & 0x9F00_0000 == 0x9000_0000 {
                let immhi = (instruction >> 5) & 0x7FFFF
                let immlo = (instruction >> 29) & 0x3
                let imm21 = (immhi << 2) | immlo
                let signedImm = Int64(Int32(bitPattern: imm21 << 11) >> 11)
                let pc = text.address + UInt64(fileOffset - textStart)
                let page = (pc & ~0xFFF) &+ UInt64(bitPattern: signedImm << 12)
                let register = instruction & 0x1F
                adrpCache[register] = (fileOffset, page, index)
            } else if instruction & 0xFF80_0000 == 0x9100_0000 {
                let sourceRegister = (instruction >> 5) & 0x1F
                let imm12 = (instruction >> 10) & 0xFFF
                if let cached = adrpCache[sourceRegister],
                   cached.page == targetPage,
                   imm12 == targetPageOffset,
                   index - cached.index <= 8
                {
                    return cached.fileOffset
                }
            }

            index += 1
        }

        return nil
    }

    func findConditionalBranch(after refFileOffset: Int, text: MachOSectionInfo) -> Int? {
        let branchMnemonics: Set<String> = ["cbz", "cbnz", "tbz", "tbnz"]
        let textEnd = Int(text.fileOffset) + Int(text.size)

        for delta in 0 ..< 16 {
            let checkOffset = refFileOffset + delta * 4
            guard checkOffset < textEnd else { break }
            guard let currentInstruction = instruction(at: checkOffset) else { continue }
            if currentInstruction.mnemonic == "bl" {
                for followDelta in 1 ... 8 {
                    let branchOffset = checkOffset + followDelta * 4
                    guard branchOffset < textEnd else { break }
                    guard let branchInstruction = instruction(at: branchOffset) else { continue }
                    if branchMnemonics.contains(branchInstruction.mnemonic) || branchInstruction.mnemonic.hasPrefix("b.") {
                        return branchOffset
                    }
                }
                break
            }
        }

        for delta in 1 ... 32 {
            let checkOffset = refFileOffset + delta * 4
            guard checkOffset < textEnd else { break }
            guard let currentInstruction = instruction(at: checkOffset) else { continue }
            if branchMnemonics.contains(currentInstruction.mnemonic) || currentInstruction.mnemonic.hasPrefix("b.") {
                return checkOffset
            }
        }

        return nil
    }

    func findShouldHactivateViaObjCMetadata() throws -> Int? {
        guard let selectorRange = buffer.data.range(of: Data("should_hactivate\0".utf8)),
              let selectorSection = section(containingFileOffset: selectorRange.lowerBound)
        else {
            return nil
        }

        let selectorVA = selectorSection.address + UInt64(selectorRange.lowerBound - Int(selectorSection.fileOffset))
        guard let selrefs = sections["__DATA_CONST,__objc_selrefs"]
            ?? sections["__DATA,__objc_selrefs"]
            ?? sections["__AUTH_CONST,__objc_selrefs"]
        else {
            return nil
        }

        var selrefVA: UInt64?
        for offset in stride(from: Int(selrefs.fileOffset), to: Int(selrefs.fileOffset) + Int(selrefs.size) - 7, by: 8) {
            let pointer = buffer.readU64(at: offset)
            if pointer == selectorVA || (pointer & 0x0000_FFFF_FFFF_FFFF) == selectorVA || (pointer & 0xFFFF_FFFF) == (selectorVA & 0xFFFF_FFFF) {
                selrefVA = selrefs.address + UInt64(offset - Int(selrefs.fileOffset))
                break
            }
        }

        guard let selrefVA else { return nil }
        guard let objcConst = sections["__DATA_CONST,__objc_const"]
            ?? sections["__DATA,__objc_const"]
            ?? sections["__AUTH_CONST,__objc_const"]
        else {
            return nil
        }

        let objcConstStart = Int(objcConst.fileOffset)
        let objcConstEnd = objcConstStart + Int(objcConst.size)
        for offset in stride(from: objcConstStart, to: objcConstEnd - 11, by: 4) {
            let entryVA = objcConst.address + UInt64(offset - objcConstStart)
            let relativeName = Int64(readLE(buffer.data, at: offset) as Int32)
            let targetVA = UInt64(Int64(entryVA) + relativeName)
            guard targetVA == selrefVA else { continue }

            let impFieldVA = entryVA + 8
            let relativeIMP = Int64(readLE(buffer.data, at: offset + 8) as Int32)
            let impVA = UInt64(Int64(impFieldVA) + relativeIMP)
            if let impFileOffset = MachOParser.vaToFileOffset(impVA, segments: segments) {
                return impFileOffset
            }
        }

        return nil
    }

    func instruction(at fileOffset: Int) -> Instruction? {
        guard let virtualAddress = fileOffsetToVA(fileOffset) else { return nil }
        return disassembler.disassembleOne(in: buffer.data, at: fileOffset, address: virtualAddress)
    }

    func fileOffsetToVA(_ offset: Int) -> UInt64? {
        for segment in segments {
            let start = Int(segment.fileOffset)
            let end = start + Int(segment.fileSize)
            if offset >= start, offset < end {
                return segment.vmAddr + UInt64(offset - start)
            }
        }
        return nil
    }

    func isReturnBlock(at fileOffset: Int, text: MachOSectionInfo) -> Bool {
        let textEnd = Int(text.fileOffset) + Int(text.size)
        for step in 0 ..< 8 {
            let checkOffset = fileOffset + step * 4
            guard checkOffset < textEnd else { break }
            guard let instruction = instruction(at: checkOffset) else { continue }
            if instruction.mnemonic == "ret" || instruction.mnemonic == "retab" {
                return true
            }
            if ["b", "bl", "br", "blr"].contains(instruction.mnemonic) {
                break
            }
        }
        return false
    }

    func decodeLastImmediate(from operandString: String) -> UInt64? {
        let token = operandString
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .last
        guard let token else { return nil }

        let value = token.hasPrefix("#") ? String(token.dropFirst()) : token
        if value.hasPrefix("0x") || value.hasPrefix("0X") {
            return UInt64(value.dropFirst(2), radix: 16)
        }
        return UInt64(value)
    }

    func logDisassembly(at startFileOffset: Int, count: Int, marker: Int) {
        let byteCount = count * 4
        guard let startVA = fileOffsetToVA(startFileOffset),
              startFileOffset >= 0,
              startFileOffset + byteCount <= buffer.count
        else {
            return
        }
        let instructions = disassembler.disassemble(buffer.readBytes(at: startFileOffset, count: byteCount), at: startVA, count: count)
        for instruction in instructions {
            guard let fileOffset = MachOParser.vaToFileOffset(instruction.address, segments: segments) else { continue }
            let markerPrefix = fileOffset == marker ? " >>>" : "    "
            let line = String(
                format: "  %@ 0x%08X: %@ %@",
                markerPrefix,
                fileOffset,
                instruction.mnemonic.padding(toLength: 8, withPad: " ", startingAt: 0),
                instruction.operandString
            )
            print(line)
        }
    }

}
