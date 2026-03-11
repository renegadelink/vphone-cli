import Darwin
import Foundation
import Subprocess

struct VPhoneCommandResult: Sendable {
    let terminationStatus: TerminationStatus
    let standardOutput: String
    let standardError: String

    var combinedOutput: String {
        if standardError.isEmpty {
            return standardOutput
        }
        if standardOutput.isEmpty {
            return standardError
        }
        return "\(standardOutput)\n\(standardError)"
    }
}

enum VPhoneHostError: Error, CustomStringConvertible {
    case missingFile(String)
    case invalidArgument(String)
    case commandFailed(executable: String, arguments: [String], status: TerminationStatus, output: String)

    var description: String {
        switch self {
        case let .missingFile(path):
            return "Missing file: \(path)"
        case let .invalidArgument(message):
            return message
        case let .commandFailed(executable, arguments, status, output):
            let commandLine = ([executable] + arguments).joined(separator: " ")
            if output.isEmpty {
                return "Command failed: \(commandLine) -> \(status)"
            }
            return "Command failed: \(commandLine) -> \(status)\n\(output)"
        }
    }
}

enum VPhoneHost {
    static let defaultSudoPassword = "alpine"

    static func runCommand(
        _ executable: String,
        arguments: [String] = [],
        environment: [String: String?] = [:],
        requireSuccess: Bool = false
    ) async throws -> VPhoneCommandResult {
        let environmentOverrides = Dictionary(uniqueKeysWithValues: environment.map {
            (Environment.Key(stringLiteral: $0.key), $0.value)
        })
        let result = try await run(
            executableReference(for: executable),
            arguments: Arguments(arguments),
            environment: environment.isEmpty ? .inherit : .inherit.updating(environmentOverrides),
            output: .string(limit: 10 * 1024 * 1024),
            error: .string(limit: 10 * 1024 * 1024)
        )
        let commandResult = VPhoneCommandResult(
            terminationStatus: result.terminationStatus,
            standardOutput: (result.standardOutput ?? "").trimmingCharacters(in: CharacterSet.newlines),
            standardError: (result.standardError ?? "").trimmingCharacters(in: CharacterSet.newlines)
        )
        if requireSuccess, !commandResult.terminationStatus.isSuccess {
            throw VPhoneHostError.commandFailed(
                executable: executable,
                arguments: arguments,
                status: commandResult.terminationStatus,
                output: commandResult.combinedOutput
            )
        }
        return commandResult
    }

    static func runPrivileged(
        _ executable: String,
        arguments: [String] = [],
        requireSuccess: Bool = false
    ) async throws -> VPhoneCommandResult {
        if geteuid() == 0 {
            return try await runCommand(executable, arguments: arguments, requireSuccess: requireSuccess)
        }

        let fullCommand = [executable] + arguments
        let probe = try await runCommand("sudo", arguments: ["-n", "true"])
        if probe.terminationStatus.isSuccess {
            return try await runCommand("sudo", arguments: fullCommand, requireSuccess: requireSuccess)
        }

        let password = ProcessInfo.processInfo.environment["VPHONE_SUDO_PASSWORD"] ?? defaultSudoPassword
        let result = try await run(
            .name("sudo"),
            arguments: Arguments(["-S", "-p", ""] + fullCommand),
            input: .string("\(password)\n"),
            output: .string(limit: 10 * 1024 * 1024),
            error: .string(limit: 10 * 1024 * 1024)
        )
        let commandResult = VPhoneCommandResult(
            terminationStatus: result.terminationStatus,
            standardOutput: (result.standardOutput ?? "").trimmingCharacters(in: CharacterSet.newlines),
            standardError: (result.standardError ?? "").trimmingCharacters(in: CharacterSet.newlines)
        )
        if requireSuccess, !commandResult.terminationStatus.isSuccess {
            throw VPhoneHostError.commandFailed(
                executable: "sudo \(executable)",
                arguments: arguments,
                status: commandResult.terminationStatus,
                output: commandResult.combinedOutput
            )
        }
        return commandResult
    }

    static func executableReference(for executable: String) -> Executable {
        return .name(executable)
    }

    static func currentDirectoryURL() -> URL {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    }

    static func tempDirectory(prefix: String) throws -> URL {
        let fileManager = FileManager.default
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("\(prefix).\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func requireFile(_ url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw VPhoneHostError.missingFile(url.path)
        }
    }

    static func createSparseFile(at url: URL, size: UInt64) throws {
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: url.path) {
            fileManager.createFile(atPath: url.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: size)
        try handle.close()
    }

    static func createZeroFilledFile(at url: URL, size: Int) throws {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: url.path) {
            return
        }
        let data = Data(repeating: 0, count: size)
        try data.write(to: url)
    }

    static func copyIfDifferent(from sourceURL: URL, to destinationURL: URL) throws -> Bool {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: destinationURL.path),
           fileManager.contentsEqual(atPath: sourceURL.path, andPath: destinationURL.path)
        {
            return false
        }
        if fileManager.fileExists(atPath: destinationURL.path) {
            try fileManager.removeItem(at: destinationURL)
        }
        try fileManager.copyItem(at: sourceURL, to: destinationURL)
        return true
    }

    static func writeEmptyFile(at url: URL) throws {
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: url.path) {
            try Data().write(to: url)
        }
    }

    static func stringValue(_ result: VPhoneCommandResult) -> String {
        result.combinedOutput.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func outputLines(_ result: VPhoneCommandResult, limit: Int = 40) -> [String] {
        let lines = result.combinedOutput
            .split(whereSeparator: \.isNewline)
            .map(String.init)
        return Array(lines.prefix(limit))
    }

    static func exitCode(from status: TerminationStatus) -> Int32 {
        switch status {
        case let .exited(code):
            code
        case let .unhandledException(code):
            code
        }
    }
}
