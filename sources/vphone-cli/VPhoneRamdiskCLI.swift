import ArgumentParser
import Foundation

struct SendRamdiskCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "send-ramdisk",
        abstract: "Send signed ramdisk components to a device in DFU/recovery mode"
    )

    @Option(name: .customLong("ramdisk-dir"), help: "Path to the Ramdisk directory.", transform: URL.init(fileURLWithPath:))
    var ramdiskDirectory: URL = URL(fileURLWithPath: "Ramdisk", isDirectory: true)

    @Option(name: .customLong("irecovery"), help: "Recovery transport binary path or name.")
    var irecovery: String?

    @Option(name: .customLong("ecid"), help: "Optional ECID selector.")
    var ecid: String?

    @Option(name: .customLong("udid"), help: "Optional UDID for logging context.")
    var udid: String?

    mutating func run() async throws {
        let env = ProcessInfo.processInfo.environment
        let irecovery = irecovery ?? env["IRECOVERY"] ?? "irecovery"
        let udid = udid ?? env["RAMDISK_UDID"] ?? env["RESTORE_UDID"]
        let ecid = try normalizedECID(ecid ?? env["IRECOVERY_ECID"])

        var irecoveryArguments: [String] = []
        if let ecid {
            irecoveryArguments += ["-i", ecid]
            print("[*] Using ECID selector for irecovery: \(ecid)")
        }

        print("[*] Identity context for ramdisk_send:")
        print("    UDID: \(udid ?? "<unset>")")
        print("    ECID: \(ecid ?? "<unset>")")

        guard FileManager.default.fileExists(atPath: ramdiskDirectory.path) else {
            throw ValidationError("Ramdisk directory not found: \(ramdiskDirectory.path). Run 'make ramdisk_build' first.")
        }

        let kernelURL: URL = {
            let ramdiskKernel = ramdiskDirectory.appendingPathComponent("krnl.ramdisk.img4")
            if FileManager.default.fileExists(atPath: ramdiskKernel.path) {
                print("  [*] Using ramdisk kernel variant: \(ramdiskKernel.lastPathComponent)")
                return ramdiskKernel
            }
            return ramdiskDirectory.appendingPathComponent("krnl.img4")
        }()
        try VPhoneHost.requireFile(kernelURL)

        print("[*] Sending ramdisk from \(ramdiskDirectory.path) ...")

        try await sendFile(named: "iBSS.vresearch101.RELEASE.img4", step: "1/8", command: nil, irecovery: irecovery, baseArguments: irecoveryArguments)
        try await sendFile(named: "iBEC.vresearch101.RELEASE.img4", step: "2/8", command: "go", irecovery: irecovery, baseArguments: irecoveryArguments)
        try await Task.sleep(nanoseconds: 1_000_000_000)

        try await sendFile(named: "sptm.vresearch1.release.img4", step: "3/8", command: "firmware", irecovery: irecovery, baseArguments: irecoveryArguments)
        try await sendFile(named: "txm.img4", step: "4/8", command: "firmware", irecovery: irecovery, baseArguments: irecoveryArguments)
        try await sendFile(named: "trustcache.img4", step: "5/8", command: "firmware", irecovery: irecovery, baseArguments: irecoveryArguments)

        try await sendFile(named: "ramdisk.img4", step: "6/8", command: nil, irecovery: irecovery, baseArguments: irecoveryArguments)
        try await Task.sleep(nanoseconds: 2_000_000_000)
        try await sendCommand("ramdisk", irecovery: irecovery, baseArguments: irecoveryArguments)

        try await sendFile(named: "DeviceTree.vphone600ap.img4", step: "7/8", command: "devicetree", irecovery: irecovery, baseArguments: irecoveryArguments)
        try await sendFile(named: "sep-firmware.vresearch101.RELEASE.img4", step: "8/8", command: "firmware", irecovery: irecovery, baseArguments: irecoveryArguments)

        print("  [*] Booting kernel...")
        _ = try await VPhoneHost.runCommand(
            irecovery,
            arguments: irecoveryArguments + ["-f", kernelURL.path],
            requireSuccess: true
        )
        try await sendCommand("bootx", irecovery: irecovery, baseArguments: irecoveryArguments)

        print("[+] Boot sequence complete. Device should be booting into ramdisk.")
    }
}

private extension SendRamdiskCLI {
    func normalizedECID(_ rawValue: String?) throws -> String? {
        guard var rawValue, !rawValue.isEmpty else {
            return nil
        }
        rawValue = rawValue.replacingOccurrences(of: "0x", with: "", options: [.caseInsensitive])
        guard rawValue.range(of: #"^[0-9A-Fa-f]{1,16}$"#, options: .regularExpression) != nil else {
            throw ValidationError("Invalid IRECOVERY_ECID: \(rawValue)")
        }
        return "0x\(rawValue.uppercased())"
    }

    func sendFile(
        named fileName: String,
        step: String,
        command: String?,
        irecovery: String,
        baseArguments: [String]
    ) async throws {
        let fileURL = ramdiskDirectory.appendingPathComponent(fileName)
        try VPhoneHost.requireFile(fileURL)
        print("  [\(step)] Loading \(fileName)...")
        _ = try await VPhoneHost.runCommand(
            irecovery,
            arguments: baseArguments + ["-f", fileURL.path],
            requireSuccess: true
        )
        if let command {
            try await sendCommand(command, irecovery: irecovery, baseArguments: baseArguments)
        }
    }

    func sendCommand(_ command: String, irecovery: String, baseArguments: [String]) async throws {
        _ = try await VPhoneHost.runCommand(
            irecovery,
            arguments: baseArguments + ["-c", command],
            requireSuccess: true
        )
    }
}
