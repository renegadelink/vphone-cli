import ArgumentParser
import Foundation

struct BuildVphonedCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "build-vphoned",
        abstract: "Build and sign the guest-side vphoned daemon with system clang"
    )

    @Option(name: .customLong("project-root"), help: "Project root path.", transform: URL.init(fileURLWithPath:))
    var projectRoot: URL = VPhoneHost.currentDirectoryURL()

    @Option(name: .customLong("vm-directory"), help: "Optional VM directory for the signed copy.", transform: URL.init(fileURLWithPath:))
    var vmDirectory: URL?

    @Option(name: .customLong("signed-copy"), help: "Optional explicit output path for the signed copy.", transform: URL.init(fileURLWithPath:))
    var signedCopy: URL?

    mutating func run() async throws {
        let builder = VphonedBuilder(projectRoot: projectRoot.standardizedFileURL)
        let result = try await builder.build(
            signedCopyURL: resolvedSignedCopyURL(),
            gitHash: try await builder.currentGitHash()
        )
        print("[+] Built vphoned: \(result.binaryURL.path)")
        if let signedCopyURL = result.signedCopyURL {
            print("[+] Signed copy: \(signedCopyURL.path)")
        }
    }

    func resolvedSignedCopyURL() -> URL? {
        if let signedCopy {
            return signedCopy.standardizedFileURL
        }
        if let vmDirectory {
            return vmDirectory.standardizedFileURL.appendingPathComponent(".vphoned.signed")
        }
        return nil
    }
}

struct VphonedBuildResult {
    let binaryURL: URL
    let signedCopyURL: URL?
}

struct VphonedBuilder {
    let projectRoot: URL

    var sourceDirectory: URL {
        projectRoot.appendingPathComponent("scripts/vphoned", isDirectory: true)
    }

    var binaryURL: URL {
        sourceDirectory.appendingPathComponent("vphoned")
    }

    var entitlementsURL: URL {
        sourceDirectory.appendingPathComponent("entitlements.plist")
    }

    var certificateURL: URL {
        sourceDirectory.appendingPathComponent("signcert.p12")
    }

    var vendoredLibarchiveIncludeURL: URL {
        sourceDirectory.appendingPathComponent("vendor/libarchive", isDirectory: true)
    }

    func build(signedCopyURL: URL?, gitHash: String) async throws -> VphonedBuildResult {
        let sourceFiles = try FileManager.default.contentsOfDirectory(at: sourceDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "m" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        guard !sourceFiles.isEmpty else {
            throw ValidationError("No Objective-C sources found in \(sourceDirectory.path)")
        }

        let clang = VPhoneHost.stringValue(
            try await VPhoneHost.runCommand(
                "xcrun",
                arguments: ["--sdk", "iphoneos", "-f", "clang"],
                requireSuccess: true
            )
        )
        let sdk = VPhoneHost.stringValue(
            try await VPhoneHost.runCommand(
                "xcrun",
                arguments: ["--sdk", "iphoneos", "--show-sdk-path"],
                requireSuccess: true
            )
        )
        guard !clang.isEmpty else {
            throw ValidationError("xcrun did not return a clang path")
        }
        guard !sdk.isEmpty else {
            throw ValidationError("xcrun did not return an iphoneos SDK path")
        }

        let arguments = [
            "-isysroot", sdk,
            "-arch", "arm64",
            "-miphoneos-version-min=15.0",
            "-Os",
            "-fobjc-arc",
            "-I.",
            "-I\(vendoredLibarchiveIncludeURL.path)",
            "-DVPHONED_BUILD_HASH=\"\(gitHash)\"",
            "-o", binaryURL.path,
        ] + sourceFiles.map(\.path) + [
            "-larchive",
            "-lsqlite3",
            "-framework", "Foundation",
            "-framework", "Security",
            "-framework", "CoreServices",
        ]

        _ = try await VPhoneHost.runCommand(
            clang,
            arguments: arguments,
            requireSuccess: true
        )

        var signedURL: URL?
        if let signedCopyURL {
            let destinationDirectory = signedCopyURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: signedCopyURL.path) {
                try FileManager.default.removeItem(at: signedCopyURL)
            }
            try FileManager.default.copyItem(at: binaryURL, to: signedCopyURL)
            try await sign(binaryURL: signedCopyURL)
            signedURL = signedCopyURL
        }

        return VphonedBuildResult(binaryURL: binaryURL, signedCopyURL: signedURL)
    }

    func sign(binaryURL: URL) async throws {
        let ldid = try VPhoneHost.resolveExecutableURL(
            explicit: nil,
            name: "ldid",
            additionalSearchDirectories: [projectRoot.appendingPathComponent(".tools/bin", isDirectory: true)]
        )
        _ = try await VPhoneHost.runCommand(
            ldid.path,
            arguments: [
                "-S\(entitlementsURL.path)",
                "-M",
                "-K\(certificateURL.path)",
                binaryURL.path,
            ],
            requireSuccess: true
        )
    }

    func currentGitHash() async throws -> String {
        try VPhoneGit.currentShortHash(projectRoot: projectRoot)
    }
}
