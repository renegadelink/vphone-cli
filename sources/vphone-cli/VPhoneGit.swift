import Foundation

enum VPhoneGit {
    static func currentShortHash(projectRoot: URL, length: Int = 7) throws -> String {
        let gitDirectory = try resolveGitDirectory(projectRoot: projectRoot)
        let head = try readText(at: gitDirectory.appendingPathComponent("HEAD"))
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let fullHash: String
        if head.hasPrefix("ref: ") {
            let reference = String(head.dropFirst(5))
            fullHash = try resolveReference(reference, in: gitDirectory)
        } else {
            fullHash = head
        }

        guard !fullHash.isEmpty else {
            return "unknown"
        }
        return String(fullHash.prefix(length))
    }

    static func cleanGeneratedArtifacts(projectRoot: URL) throws {
        let fileManager = FileManager.default
        let removablePaths = [
            ".build",
            ".tools",
            "setup_logs",
            "Package.resolved",
            "sources/vphone-cli/VPhoneBuildInfo.swift",
            "scripts/patchers",
            "scripts/patches",
        ]

        for relativePath in removablePaths {
            let url = projectRoot.appendingPathComponent(relativePath)
            if fileManager.fileExists(atPath: url.path) {
                try fileManager.removeItem(at: url)
            }
        }
    }

    private static func resolveGitDirectory(projectRoot: URL) throws -> URL {
        let gitEntry = projectRoot.appendingPathComponent(".git")
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: gitEntry.path, isDirectory: &isDirectory), isDirectory.boolValue {
            return gitEntry
        }

        let contents = try readText(at: gitEntry).trimmingCharacters(in: .whitespacesAndNewlines)
        guard contents.hasPrefix("gitdir:") else {
            throw VPhoneHostError.invalidArgument("Unable to resolve .git directory in \(projectRoot.path)")
        }
        let rawPath = contents.dropFirst("gitdir:".count).trimmingCharacters(in: .whitespaces)
        let candidate = URL(fileURLWithPath: rawPath, relativeTo: projectRoot).standardizedFileURL
        return candidate
    }

    private static func resolveReference(_ reference: String, in gitDirectory: URL) throws -> String {
        let directReference = gitDirectory.appendingPathComponent(reference)
        if FileManager.default.fileExists(atPath: directReference.path) {
            return try readText(at: directReference).trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let packedRefs = gitDirectory.appendingPathComponent("packed-refs")
        if FileManager.default.fileExists(atPath: packedRefs.path) {
            let lines = try readText(at: packedRefs).split(separator: "\n")
            for line in lines {
                if line.hasPrefix("#") || line.hasPrefix("^") { continue }
                let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
                if parts.count == 2, parts[1] == reference {
                    return parts[0]
                }
            }
        }

        throw VPhoneHostError.invalidArgument("Git reference not found: \(reference)")
    }

    private static func readText(at url: URL) throws -> String {
        try String(contentsOf: url, encoding: .utf8)
    }
}
