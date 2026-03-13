import CommonCrypto
import Crypto
import Foundation
import NIOCore
import NIOSSH

enum VPhoneSSHTransportError: Error, CustomStringConvertible {
    case invalidKeySize(expected: Int, actual: Int)
    case invalidIVSize(expected: Int, actual: Int)
    case cryptorCreateFailed(CCCryptorStatus)
    case cryptorUpdateFailed(CCCryptorStatus)
    case invalidPacket
    case invalidMAC

    var description: String {
        switch self {
        case let .invalidKeySize(expected, actual):
            return "invalid SSH key size: expected \(expected), got \(actual)"
        case let .invalidIVSize(expected, actual):
            return "invalid SSH IV size: expected \(expected), got \(actual)"
        case let .cryptorCreateFailed(status):
            return "failed to create SSH AES-CTR cryptor: \(status)"
        case let .cryptorUpdateFailed(status):
            return "failed to update SSH AES-CTR cryptor: \(status)"
        case .invalidPacket:
            return "invalid SSH packet"
        case .invalidMAC:
            return "invalid SSH packet MAC"
        }
    }
}

class AESCTRTransportProtectionBase: NIOSSHTransportProtection {
    class var cipherName: String { fatalError("Override cipherName") }
    class var macName: String? { fatalError("Override macName") }
    class var keySizes: ExpectedKeySizes { fatalError("Override keySizes") }
    class var macAlgorithm: CCHmacAlgorithm { fatalError("Override macAlgorithm") }
    class var macLength: Int { fatalError("Override macLength") }

    static var cipherBlockSize: Int { 16 }

    var macBytes: Int { Self.macLength }
    var lengthEncrypted: Bool { true }

    private var inboundCipher: AESCTRStreamCipher
    private var outboundCipher: AESCTRStreamCipher
    private var inboundMACKey: Data
    private var outboundMACKey: Data

    required init(initialKeys: NIOSSHSessionKeys) throws {
        let configured = try Self.makeState(from: initialKeys)
        self.inboundCipher = configured.inboundCipher
        self.outboundCipher = configured.outboundCipher
        self.inboundMACKey = configured.inboundMACKey
        self.outboundMACKey = configured.outboundMACKey
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        let configured = try Self.makeState(from: newKeys)
        self.inboundCipher = configured.inboundCipher
        self.outboundCipher = configured.outboundCipher
        self.inboundMACKey = configured.inboundMACKey
        self.outboundMACKey = configured.outboundMACKey
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        let start = source.readerIndex
        guard let encrypted = source.getBytes(at: start, length: Self.cipherBlockSize) else {
            throw VPhoneSSHTransportError.invalidPacket
        }
        let plaintext = try inboundCipher.update(encrypted)
        source.setBytes(plaintext, at: start)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        let packetByteCount = source.readableBytes - Self.macLength
        guard packetByteCount >= Self.cipherBlockSize else {
            throw VPhoneSSHTransportError.invalidPacket
        }

        let remainingCiphertextCount = packetByteCount - Self.cipherBlockSize
        if remainingCiphertextCount > 0 {
            let offset = source.readerIndex + Self.cipherBlockSize
            guard let encrypted = source.getBytes(at: offset, length: remainingCiphertextCount) else {
                throw VPhoneSSHTransportError.invalidPacket
            }
            let plaintext = try inboundCipher.update(encrypted)
            source.setBytes(plaintext, at: offset)
        }

        let packetStart = source.readerIndex
        guard let plaintextPacket = source.getBytes(at: packetStart, length: packetByteCount),
              let receivedMAC = source.getBytes(at: packetStart + packetByteCount, length: Self.macLength)
        else {
            throw VPhoneSSHTransportError.invalidPacket
        }

        let expectedMAC = Self.computeMAC(
            key: inboundMACKey,
            sequenceNumber: sequenceNumber,
            packet: plaintextPacket
        )
        guard Self.constantTimeEqual(expectedMAC, receivedMAC) else {
            throw VPhoneSSHTransportError.invalidMAC
        }

        guard var packetBuffer = source.readSlice(length: packetByteCount) else {
            throw VPhoneSSHTransportError.invalidPacket
        }
        source.moveReaderIndex(forwardBy: Self.macLength)
        return try Self.payloadBuffer(fromPlaintextPacket: &packetBuffer)
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let packetStart = destination.readerIndex
        let packetByteCount = destination.readableBytes
        guard let plaintextPacket = destination.getBytes(at: packetStart, length: packetByteCount) else {
            throw VPhoneSSHTransportError.invalidPacket
        }

        let mac = Self.computeMAC(
            key: outboundMACKey,
            sequenceNumber: sequenceNumber,
            packet: plaintextPacket
        )
        let ciphertext = try outboundCipher.update(plaintextPacket)
        destination.setBytes(ciphertext, at: packetStart)
        destination.writeBytes(mac)
    }

    private static func makeState(
        from keys: NIOSSHSessionKeys
    ) throws -> (
        inboundCipher: AESCTRStreamCipher,
        outboundCipher: AESCTRStreamCipher,
        inboundMACKey: Data,
        outboundMACKey: Data
    ) {
        let inboundEncryptionKey = Data(keys.inboundEncryptionKey.withUnsafeBytes { Array($0) })
        let outboundEncryptionKey = Data(keys.outboundEncryptionKey.withUnsafeBytes { Array($0) })
        let inboundMACKey = Data(keys.inboundMACKey.withUnsafeBytes { Array($0) })
        let outboundMACKey = Data(keys.outboundMACKey.withUnsafeBytes { Array($0) })

        guard inboundEncryptionKey.count == Self.keySizes.encryptionKeySize else {
            throw VPhoneSSHTransportError.invalidKeySize(
                expected: Self.keySizes.encryptionKeySize,
                actual: inboundEncryptionKey.count
            )
        }
        guard outboundEncryptionKey.count == Self.keySizes.encryptionKeySize else {
            throw VPhoneSSHTransportError.invalidKeySize(
                expected: Self.keySizes.encryptionKeySize,
                actual: outboundEncryptionKey.count
            )
        }
        guard inboundMACKey.count == Self.keySizes.macKeySize else {
            throw VPhoneSSHTransportError.invalidKeySize(
                expected: Self.keySizes.macKeySize,
                actual: inboundMACKey.count
            )
        }
        guard outboundMACKey.count == Self.keySizes.macKeySize else {
            throw VPhoneSSHTransportError.invalidKeySize(
                expected: Self.keySizes.macKeySize,
                actual: outboundMACKey.count
            )
        }
        guard keys.initialInboundIV.count == Self.keySizes.ivSize else {
            throw VPhoneSSHTransportError.invalidIVSize(
                expected: Self.keySizes.ivSize,
                actual: keys.initialInboundIV.count
            )
        }
        guard keys.initialOutboundIV.count == Self.keySizes.ivSize else {
            throw VPhoneSSHTransportError.invalidIVSize(
                expected: Self.keySizes.ivSize,
                actual: keys.initialOutboundIV.count
            )
        }

        return (
            inboundCipher: try AESCTRStreamCipher(key: inboundEncryptionKey, iv: keys.initialInboundIV),
            outboundCipher: try AESCTRStreamCipher(key: outboundEncryptionKey, iv: keys.initialOutboundIV),
            inboundMACKey: inboundMACKey,
            outboundMACKey: outboundMACKey
        )
    }

    private static func computeMAC(key: Data, sequenceNumber: UInt32, packet: [UInt8]) -> [UInt8] {
        var sequenceNumber = sequenceNumber.bigEndian
        var mac = [UInt8](repeating: 0, count: Self.macLength)

        key.withUnsafeBytes { keyBuffer in
            withUnsafeBytes(of: &sequenceNumber) { sequenceBuffer in
                packet.withUnsafeBytes { packetBuffer in
                    CCHmacInitBuffer(Self.macAlgorithm, keyBuffer.baseAddress, keyBuffer.count) { context in
                        CCHmacUpdate(context, sequenceBuffer.baseAddress, sequenceBuffer.count)
                        CCHmacUpdate(context, packetBuffer.baseAddress, packetBuffer.count)
                        mac.withUnsafeMutableBytes { outputBuffer in
                            CCHmacFinal(context, outputBuffer.baseAddress)
                        }
                    }
                }
            }
        }

        return mac
    }

    private static func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for index in lhs.indices {
            diff |= lhs[index] ^ rhs[index]
        }
        return diff == 0
    }

    private static func payloadBuffer(fromPlaintextPacket packetBuffer: inout ByteBuffer) throws -> ByteBuffer {
        packetBuffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)
        guard let paddingLength = packetBuffer.readInteger(as: UInt8.self) else {
            throw VPhoneSSHTransportError.invalidPacket
        }
        let payloadLength = packetBuffer.readableBytes - Int(paddingLength)
        guard payloadLength >= 0,
              let payload = packetBuffer.readSlice(length: payloadLength),
              packetBuffer.readerIndex + Int(paddingLength) == packetBuffer.writerIndex
        else {
            throw VPhoneSSHTransportError.invalidPacket
        }
        packetBuffer.moveReaderIndex(forwardBy: Int(paddingLength))
        return payload
    }
}

final class AES128CTRHMACSHA256TransportProtection: AESCTRTransportProtectionBase {
    override class var cipherName: String { "aes128-ctr" }
    override class var macName: String? { "hmac-sha2-256" }
    override class var keySizes: ExpectedKeySizes {
        .init(ivSize: 16, encryptionKeySize: 16, macKeySize: Int(CC_SHA256_DIGEST_LENGTH))
    }
    override class var macAlgorithm: CCHmacAlgorithm { CCHmacAlgorithm(kCCHmacAlgSHA256) }
    override class var macLength: Int { Int(CC_SHA256_DIGEST_LENGTH) }
}

final class AES256CTRHMACSHA256TransportProtection: AESCTRTransportProtectionBase {
    override class var cipherName: String { "aes256-ctr" }
    override class var macName: String? { "hmac-sha2-256" }
    override class var keySizes: ExpectedKeySizes {
        .init(ivSize: 16, encryptionKeySize: 32, macKeySize: Int(CC_SHA256_DIGEST_LENGTH))
    }
    override class var macAlgorithm: CCHmacAlgorithm { CCHmacAlgorithm(kCCHmacAlgSHA256) }
    override class var macLength: Int { Int(CC_SHA256_DIGEST_LENGTH) }
}

final class AES128CTRHMACSHA1TransportProtection: AESCTRTransportProtectionBase {
    override class var cipherName: String { "aes128-ctr" }
    override class var macName: String? { "hmac-sha1" }
    override class var keySizes: ExpectedKeySizes {
        .init(ivSize: 16, encryptionKeySize: 16, macKeySize: Int(CC_SHA1_DIGEST_LENGTH))
    }
    override class var macAlgorithm: CCHmacAlgorithm { CCHmacAlgorithm(kCCHmacAlgSHA1) }
    override class var macLength: Int { Int(CC_SHA1_DIGEST_LENGTH) }
}

final class AES256CTRHMACSHA1TransportProtection: AESCTRTransportProtectionBase {
    override class var cipherName: String { "aes256-ctr" }
    override class var macName: String? { "hmac-sha1" }
    override class var keySizes: ExpectedKeySizes {
        .init(ivSize: 16, encryptionKeySize: 32, macKeySize: Int(CC_SHA1_DIGEST_LENGTH))
    }
    override class var macAlgorithm: CCHmacAlgorithm { CCHmacAlgorithm(kCCHmacAlgSHA1) }
    override class var macLength: Int { Int(CC_SHA1_DIGEST_LENGTH) }
}

final class AESCTRStreamCipher {
    private var cryptor: CCCryptorRef?

    init(key: Data, iv: [UInt8]) throws {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress,
                    keyBuffer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard status == kCCSuccess, let cryptor else {
            throw VPhoneSSHTransportError.cryptorCreateFailed(status)
        }
        self.cryptor = cryptor
    }

    deinit {
        if let cryptor {
            CCCryptorRelease(cryptor)
        }
    }

    func update(_ input: [UInt8]) throws -> [UInt8] {
        guard let cryptor else {
            throw VPhoneSSHTransportError.invalidPacket
        }
        if input.isEmpty {
            return []
        }

        let outputCount = input.count
        var output = [UInt8](repeating: 0, count: outputCount)
        var bytesMoved = 0
        let status = input.withUnsafeBytes { inputBuffer in
            output.withUnsafeMutableBytes { outputBuffer in
                CCCryptorUpdate(
                    cryptor,
                    inputBuffer.baseAddress,
                    input.count,
                    outputBuffer.baseAddress,
                    outputCount,
                    &bytesMoved
                )
            }
        }
        guard status == kCCSuccess, bytesMoved == input.count else {
            throw VPhoneSSHTransportError.cryptorUpdateFailed(status)
        }
        return output
    }
}

private func CCHmacInitBuffer(
    _ algorithm: CCHmacAlgorithm,
    _ key: UnsafeRawPointer?,
    _ keyLength: Int,
    body: (UnsafeMutablePointer<CCHmacContext>) -> Void
) {
    var context = CCHmacContext()
    CCHmacInit(&context, algorithm, key, keyLength)
    body(&context)
}
