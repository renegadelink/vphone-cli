import AppKit
import ArgumentParser
import Foundation

@main
struct VPhoneMain {
    static func main() async {
        do {
            let command = try VPhoneCLI.parseAsRoot()

            switch command {
            case let boot as VPhoneBootCLI:
                let app = NSApplication.shared
                let delegate = VPhoneAppDelegate(cli: boot)
                app.delegate = delegate
                app.run()

            case var patch as PatchFirmwareCLI:
                try patch.run()

            case var patch as PatchComponentCLI:
                try patch.run()

            case var command as VMCreateCLI:
                try await command.run()

            case var command as GenerateVMManifestCLI:
                try command.run()

            case var command as BootHostPreflightCLI:
                try await command.run()

            case var command as StartAmfidontCLI:
                try await command.run()

            case var command as GenerateFirmwareManifestCLI:
                try command.run()

            case var command as PrepareFirmwareCLI:
                try await command.run()

            case var command as BuildRamdiskCLI:
                try await command.run()

            case var command as SendRamdiskCLI:
                try await command.run()

            case var command as SetupToolsCLI:
                try await command.run()

            case var command as CFWInstallCLI:
                try await command.run()

            case var command as CFWCryptexPathsCLI:
                try command.run()

            case var command as CFWPatchSeputilCLI:
                try command.run()

            case var command as CFWPatchLaunchdCacheLoaderCLI:
                try command.run()

            case var command as CFWPatchMobileactivationdCLI:
                try command.run()

            case var command as CFWPatchLaunchdJetsamCLI:
                try command.run()

            case var command as CFWInjectDaemonsCLI:
                try await command.run()

            case var command as CFWInjectLaunchDaemonCLI:
                try command.run()

            case var command as CFWInjectDylibCLI:
                try await command.run()

            default:
                break
            }
        } catch {
            VPhoneCLI.exit(withError: error)
        }
    }
}
