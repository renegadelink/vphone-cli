import Foundation
import NIOCore
import NIOPosix
import NIOSSH

struct VPhoneSSHCommandResult {
    let exitStatus: Int32
    let standardOutput: Data
    let standardError: Data

    var standardOutputString: String {
        String(decoding: standardOutput, as: UTF8.self)
    }

    var standardErrorString: String {
        String(decoding: standardError, as: UTF8.self)
    }
}

enum VPhoneSSHError: Error, CustomStringConvertible {
    case notConnected
    case invalidChannelType
    case commandFailed(String)
    case timeout(String)

    var description: String {
        switch self {
        case .notConnected:
            return "SSH client is not connected"
        case .invalidChannelType:
            return "Invalid SSH channel type"
        case let .commandFailed(message):
            return message
        case let .timeout(context):
            return "SSH timeout: \(context)"
        }
    }
}

final class VPhoneSSHClient: @unchecked Sendable {
    let host: String
    let port: Int
    let username: String
    let password: String

    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var channel: Channel?
    private var sshHandler: NIOSSHHandler?
    private var shutDown = false
    private var debugEnabled: Bool {
        ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1"
    }

    init(host: String, port: Int, username: String, password: String) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    }

    deinit {
        try? shutdown()
    }

    func connect() throws {
        guard channel == nil else { return }
        let connectionState = VPhoneSSHConnectionState(eventLoop: group.next())
        debug("connect begin host=\(host) port=\(port) user=\(username)")

        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { [username, password] channel in
                let configuration = SSHClientConfiguration(
                    userAuthDelegate: SimplePasswordDelegate(username: username, password: password),
                    serverAuthDelegate: AcceptAllHostKeysDelegate(),
                    transportProtectionSchemes: [
                        AES256CTRHMACSHA256TransportProtection.self,
                        AES128CTRHMACSHA256TransportProtection.self,
                        AES256CTRHMACSHA1TransportProtection.self,
                        AES128CTRHMACSHA1TransportProtection.self,
                    ]
                )
                let ssh = NIOSSHHandler(
                    role: .client(configuration),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                )
                connectionState.sshHandler = ssh
                return channel.pipeline.addHandler(ssh).flatMap {
                    channel.pipeline.addHandler(VPhoneSSHConnectionHandler(readyPromise: connectionState.readyPromise))
                }.flatMap {
                    channel.pipeline.addHandler(VPhoneSSHErrorHandler())
                }
            }
            .connectTimeout(.seconds(5))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

        let connectedChannel = try waitForFuture(
            bootstrap.connect(host: host, port: port),
            timeout: .seconds(8),
            context: "tcp connect to \(host):\(port)"
        )
        debug("tcp connected")
        channel = connectedChannel
        _ = try waitForFuture(
            connectionState.readyPromise.futureResult,
            timeout: .seconds(8),
            context: "SSH authentication"
        )
        debug("ssh authenticated")
        guard let sshHandler = connectionState.sshHandler else {
            throw VPhoneSSHError.notConnected
        }
        self.sshHandler = sshHandler
    }

    func shutdown() throws {
        guard !shutDown else { return }
        shutDown = true
        if let channel {
            try? channel.close().wait()
            self.channel = nil
            self.sshHandler = nil
        }
        try group.syncShutdownGracefully()
    }

    func execute(_ command: String, stdin: Data? = nil, requireSuccess: Bool = true) throws -> VPhoneSSHCommandResult {
        guard let channel, let sshHandler else {
            throw VPhoneSSHError.notConnected
        }
        debug("execute command=\(command)")

        let resultBox = VPhoneSSHCommandResultBox(eventLoop: channel.eventLoop)
        let childPromise = channel.eventLoop.makePromise(of: Channel.self)
        let createChannelPromise = channel.eventLoop.makePromise(of: Void.self)
        let commandTimeout: TimeAmount
        if let stdin, stdin.count > 1_000_000 {
            commandTimeout = .seconds(600)
        } else if stdin != nil {
            commandTimeout = .seconds(120)
        } else {
            commandTimeout = .seconds(30)
        }
        channel.eventLoop.execute {
            sshHandler.createChannel(childPromise) { childChannel, channelType in
                guard channelType == .session else {
                    return channel.eventLoop.makeFailedFuture(VPhoneSSHError.invalidChannelType)
                }

                return childChannel.pipeline.addHandler(
                    VPhoneSSHExecHandler(command: command, stdinData: stdin, resultBox: resultBox)
                )
            }
            createChannelPromise.succeed(())
        }

        childPromise.futureResult.whenFailure { error in
            resultBox.fail(error)
        }

        let result: VPhoneSSHCommandResult
        do {
            _ = try waitForFuture(
                createChannelPromise.futureResult,
                timeout: .seconds(2),
                context: "schedule exec channel open"
            )
            debug("exec channel scheduled")
            let childChannel = try waitForFuture(
                childPromise.futureResult,
                timeout: .seconds(8),
                context: "open exec channel"
            )
            debug("exec channel active")
            result = try waitForFuture(
                resultBox.futureResult,
                timeout: commandTimeout,
                context: "command result"
            )
            debug("command result exit=\(result.exitStatus)")
            childChannel.close(promise: nil)
        } catch {
            resultBox.fail(error)
            throw error
        }
        if requireSuccess, result.exitStatus != 0 {
            let stderr = result.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw VPhoneSSHError.commandFailed(
                stderr.isEmpty
                    ? "SSH command failed with status \(result.exitStatus): \(command)"
                    : "SSH command failed with status \(result.exitStatus): \(command)\n\(stderr)"
            )
        }
        return result
    }

    func uploadFile(localURL: URL, remotePath: String) throws {
        let resolvedRemotePath = try resolveRemoteUploadPath(remotePath, localName: localURL.lastPathComponent)
        _ = try execute("/bin/cat > \(shellQuote(resolvedRemotePath))", stdin: try Data(contentsOf: localURL))
        try applyPOSIXPermissionsIfPresent(for: localURL, remotePath: resolvedRemotePath)
    }

    func uploadData(_ data: Data, remotePath: String) throws {
        _ = try execute("/bin/cat > \(shellQuote(remotePath))", stdin: data)
    }

    func downloadFile(remotePath: String, localURL: URL) throws {
        let result = try execute("/bin/cat \(shellQuote(remotePath))")
        try result.standardOutput.write(to: localURL)
    }

    func uploadDirectory(localURL: URL, remotePath: String) throws {
        let tarData = try VPhoneArchive.createTarArchive(from: localURL)
        _ = try execute(
            "/bin/rm -rf \(shellQuote(remotePath)) && /bin/mkdir -p \(shellQuote(remotePath)) && /usr/bin/tar -xf - -C \(shellQuote(remotePath))",
            stdin: tarData
        )
        try applyPOSIXPermissionsIfPresent(for: localURL, remotePath: remotePath)
    }

    func uploadDirectoryContents(localURL: URL, remotePath: String) throws {
        try createRemoteDirectory(remotePath)
        let tarData = try VPhoneArchive.createTarArchive(from: localURL)
        _ = try execute("/usr/bin/tar -xf - -C \(shellQuote(remotePath))", stdin: tarData)
    }

    static func probe(host: String, port: Int, username: String, password: String) -> Bool {
        do {
            let client = VPhoneSSHClient(host: host, port: port, username: username, password: password)
            defer { try? client.shutdown() }
            try client.connect()
            let result = try client.execute("echo ready", requireSuccess: false)
            return result.exitStatus == 0 && result.standardOutputString.trimmingCharacters(in: .whitespacesAndNewlines) == "ready"
        } catch {
            if ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1" {
                let message = "[ssh probe] \(error)\n"
                FileHandle.standardError.write(Data(message.utf8))
            }
            return false
        }
    }

    private func shellQuote(_ string: String) -> String {
        "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func uploadItem(localURL: URL, remotePath: String) throws {
        let fileManager = FileManager.default
        let values = try localURL.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])

        if values.isDirectory == true {
            try createRemoteDirectory(remotePath)
            try applyPOSIXPermissionsIfPresent(for: localURL, remotePath: remotePath)
            let children = try fileManager.contentsOfDirectory(
                at: localURL,
                includingPropertiesForKeys: nil,
                options: []
            ).sorted { $0.lastPathComponent < $1.lastPathComponent }
            for child in children {
                try uploadItem(localURL: child, remotePath: remotePath + "/" + child.lastPathComponent)
            }
            return
        }

        if values.isSymbolicLink == true {
            let destination = try fileManager.destinationOfSymbolicLink(atPath: localURL.path)
            let parent = (remotePath as NSString).deletingLastPathComponent
            try createRemoteDirectory(parent)
            _ = try execute(
                "/bin/rm -rf \(shellQuote(remotePath)) && /bin/ln -s \(shellQuote(destination)) \(shellQuote(remotePath))"
            )
            return
        }

        guard values.isRegularFile == true else {
            return
        }
        let resolvedRemotePath = try resolveRemoteUploadPath(remotePath, localName: localURL.lastPathComponent)
        let parent = (resolvedRemotePath as NSString).deletingLastPathComponent
        try createRemoteDirectory(parent)
        try uploadFile(localURL: localURL, remotePath: resolvedRemotePath)
    }

    private func createRemoteDirectory(_ path: String) throws {
        guard !path.isEmpty, path != "." else { return }
        _ = try execute("/bin/mkdir -p \(shellQuote(path))")
    }

    private func applyPOSIXPermissionsIfPresent(for localURL: URL, remotePath: String) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: localURL.path)
        guard let permissions = attributes[.posixPermissions] as? NSNumber else {
            return
        }
        let mode = String(permissions.intValue, radix: 8)
        _ = try execute("/bin/chmod \(mode) \(shellQuote(remotePath))")
    }

    private func resolveRemoteUploadPath(_ remotePath: String, localName: String) throws -> String {
        if remotePath.hasSuffix("/") {
            return (remotePath as NSString).appendingPathComponent(localName)
        }

        let result = try execute("test -d \(shellQuote(remotePath))", requireSuccess: false)
        if result.exitStatus == 0 {
            return (remotePath as NSString).appendingPathComponent(localName)
        }
        return remotePath
    }

    private func waitForFuture<Value>(
        _ future: EventLoopFuture<Value>,
        timeout: TimeAmount,
        context: String
    ) throws -> Value {
        let promise = future.eventLoop.makePromise(of: Value.self)
        let scheduled = future.eventLoop.scheduleTask(in: timeout) {
            promise.fail(VPhoneSSHError.timeout(context))
        }
        future.whenComplete { result in
            scheduled.cancel()
            switch result {
            case let .success(value):
                promise.succeed(value)
            case let .failure(error):
                promise.fail(error)
            }
        }
        return try promise.futureResult.wait()
    }

    private func debug(_ message: String) {
        guard debugEnabled else { return }
        FileHandle.standardError.write(Data("[ssh] \(message)\n".utf8))
    }
}

private final class VPhoneSSHExecHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    let command: String
    let stdinData: Data?
    let resultBox: VPhoneSSHCommandResultBox
    let stdinChunkSize = 256 * 1024

    var standardOutput = Data()
    var standardError = Data()
    var exitStatus: Int32 = 0
    var completed = false
    var stdinOffset = 0

    init(command: String, stdinData: Data?, resultBox: VPhoneSSHCommandResultBox) {
        self.command = command
        self.stdinData = stdinData
        self.resultBox = resultBox
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            self.fail(error, context: loopBoundContext.value)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        if ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1" {
            FileHandle.standardError.write(Data("[ssh] exec handler active command=\(command)\n".utf8))
        }
        let request = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
        context.triggerUserOutboundEvent(request).whenComplete { result in
            switch result {
            case .success:
                self.sendStandardInput(context: loopBoundContext.value)
            case .failure(let error):
                self.fail(error, context: loopBoundContext.value)
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        guard case .byteBuffer(var bytes) = message.data,
              let chunk = bytes.readData(length: bytes.readableBytes)
        else {
            return
        }

        switch message.type {
        case .channel:
            standardOutput.append(chunk)
        case .stdErr:
            standardError.append(chunk)
        default:
            break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let exit = event as? SSHChannelRequestEvent.ExitStatus {
            exitStatus = Int32(exit.exitStatus)
            if ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1" {
                FileHandle.standardError.write(Data("[ssh] exit status=\(exit.exitStatus)\n".utf8))
            }
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1" {
            FileHandle.standardError.write(Data("[ssh] exec handler inactive command=\(command)\n".utf8))
        }
        succeedIfNeeded()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(error, context: context)
    }

    private func sendStandardInput(context: ChannelHandlerContext) {
        guard let stdinData, !stdinData.isEmpty else {
            context.close(mode: .output, promise: nil)
            return
        }
        writeNextStandardInputChunk(context: context, stdinData: stdinData)
    }

    private func writeNextStandardInputChunk(context: ChannelHandlerContext, stdinData: Data) {
        if stdinOffset >= stdinData.count {
            context.close(mode: .output, promise: nil)
            return
        }

        let nextOffset = min(stdinOffset + stdinChunkSize, stdinData.count)
        let chunk = stdinData[stdinOffset..<nextOffset]
        stdinOffset = nextOffset

        var buffer = context.channel.allocator.buffer(capacity: chunk.count)
        buffer.writeBytes(chunk)
        let payload = SSHChannelData(type: .channel, data: .byteBuffer(buffer))
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(payload)).whenComplete { result in
            switch result {
            case .success:
                self.writeNextStandardInputChunk(context: loopBoundContext.value, stdinData: stdinData)
            case .failure(let error):
                self.fail(error, context: loopBoundContext.value)
            }
        }
    }

    private func succeedIfNeeded() {
        guard !completed else { return }
        completed = true
        resultBox.succeed(
            VPhoneSSHCommandResult(
                exitStatus: exitStatus,
                standardOutput: standardOutput,
                standardError: standardError
            )
        )
    }

    private func fail(_ error: Error, context: ChannelHandlerContext) {
        guard !completed else { return }
        completed = true
        resultBox.fail(error)
        context.close(promise: nil)
    }
}

private final class VPhoneSSHCommandResultBox: @unchecked Sendable {
    let futureResult: EventLoopFuture<VPhoneSSHCommandResult>

    private let promise: EventLoopPromise<VPhoneSSHCommandResult>
    private let lock = NSLock()
    private var completed = false

    init(eventLoop: EventLoop) {
        promise = eventLoop.makePromise(of: VPhoneSSHCommandResult.self)
        futureResult = promise.futureResult
    }

    func succeed(_ value: VPhoneSSHCommandResult) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        promise.succeed(value)
    }

    func fail(_ error: Error) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        promise.fail(error)
    }
}

private final class VPhoneSSHConnectionState: @unchecked Sendable {
    let readyPromise: EventLoopPromise<Void>
    var sshHandler: NIOSSHHandler?

    init(eventLoop: EventLoop) {
        readyPromise = eventLoop.makePromise(of: Void.self)
    }
}

private final class VPhoneSSHConnectionHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Any

    let readyPromise: EventLoopPromise<Void>
    var completed = false

    init(readyPromise: EventLoopPromise<Void>) {
        self.readyPromise = readyPromise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent {
            if ProcessInfo.processInfo.environment["VPHONE_SSH_DEBUG"] == "1" {
                FileHandle.standardError.write(Data("[ssh] auth success event\n".utf8))
            }
            succeedIfNeeded()
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failIfNeeded(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        failIfNeeded(VPhoneSSHError.notConnected)
        context.fireChannelInactive()
    }

    private func succeedIfNeeded() {
        guard !completed else { return }
        completed = true
        readyPromise.succeed(())
    }

    private func failIfNeeded(_ error: Error) {
        guard !completed else { return }
        completed = true
        readyPromise.fail(error)
    }
}

private final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

private final class VPhoneSSHErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
