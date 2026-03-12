import ArgumentParser
import Foundation

struct SetupToolsCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup-tools",
        abstract: "Install required host tools without shell wrappers"
    )

    @Option(help: "Project root path", transform: URL.init(fileURLWithPath:))
    var projectRoot: URL = VPhoneHost.currentDirectoryURL()

    mutating func run() async throws {
        let projectRoot = projectRoot.standardizedFileURL
        let toolsPrefix = resolveToolsPrefix(projectRoot: projectRoot)

        try await installBrewPackages([
            ("ldid-procursus", "ldid"),
            ("git-lfs", "git-lfs"),
        ])

        try await installInject(toolsPrefix: toolsPrefix)

        print("")
        print("Tools installed in \(toolsPrefix.path)")
    }

    func resolveToolsPrefix(projectRoot: URL) -> URL {
        if let override = ProcessInfo.processInfo.environment["TOOLS_PREFIX"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return projectRoot.appendingPathComponent(".tools", isDirectory: true)
    }

    func requireCommand(_ command: String) throws {
        let result = FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/\(command)")
            || FileManager.default.isExecutableFile(atPath: "/usr/local/bin/\(command)")
            || which(command) != nil
        if !result {
            throw ValidationError("Missing required command: \(command)")
        }
    }

    func which(_ command: String) -> String? {
        ProcessInfo.processInfo.environment["PATH"]?
            .split(separator: ":")
            .map(String.init)
            .map { URL(fileURLWithPath: $0).appendingPathComponent(command).path }
            .first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    func installBrewPackages(_ packages: [(package: String, command: String)]) async throws {
        print("[1/2] Checking Homebrew packages...")
        var missingPackages: [String] = []

        for package in packages {
            if which(package.command) != nil {
                continue
            }
            missingPackages.append(package.package)
        }

        if missingPackages.isEmpty {
            print("  All brew packages installed")
            return
        }

        guard which("brew") != nil || FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/brew") || FileManager.default.isExecutableFile(atPath: "/usr/local/bin/brew") else {
            throw ValidationError("Missing Homebrew. Install it or provide these tools manually: \(missingPackages.joined(separator: ", "))")
        }

        print("  Installing: \(missingPackages.joined(separator: ", "))")
        _ = try await VPhoneHost.runCommand("brew", arguments: ["install"] + missingPackages, requireSuccess: true)
    }

    func installInject(toolsPrefix: URL) async throws {
        let injectBinary = toolsPrefix.appendingPathComponent("bin/inject")
        print("[2/2] inject")
        if FileManager.default.isExecutableFile(atPath: injectBinary.path) {
            print("  Already built: \(injectBinary.path)")
            return
        }

        let sourceURL = projectRoot.appendingPathComponent("vendor/inject", isDirectory: true)
        guard FileManager.default.fileExists(atPath: sourceURL.appendingPathComponent("Package.swift").path) else {
            throw ValidationError("Missing vendored inject source at \(sourceURL.path). Update submodules first.")
        }

        _ = try await VPhoneHost.runCommand(
            "swift",
            arguments: ["build", "-c", "release", "--product", "inject", "--package-path", sourceURL.path],
            requireSuccess: true
        )

        let builtBinary = sourceURL.appendingPathComponent(".build/release/inject")
        try FileManager.default.createDirectory(at: toolsPrefix.appendingPathComponent("bin", isDirectory: true), withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: injectBinary.path) {
            try FileManager.default.removeItem(at: injectBinary)
        }
        try FileManager.default.copyItem(at: builtBinary, to: injectBinary)
        print("  Installed: \(injectBinary.path)")
    }
}
