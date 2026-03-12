import ArgumentParser
import Foundation

struct WorkflowHelpCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "workflow-help",
        abstract: "Print the Make target overview for the Swift-only host workflow"
    )

    mutating func run() throws {
        print(WorkflowHelpText.render())
    }
}

struct CleanProjectCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "clean-project",
        abstract: "Remove generated project artifacts while preserving IPSWs"
    )

    @Option(name: .customLong("project-root"), help: "Project root path.", transform: URL.init(fileURLWithPath:))
    var projectRoot: URL = VPhoneHost.currentDirectoryURL()

    mutating func run() async throws {
        let projectRoot = projectRoot.standardizedFileURL
        print("=== Cleaning all untracked files (preserving IPSWs) ===")
        try VPhoneGit.cleanGeneratedArtifacts(projectRoot: projectRoot)
    }
}

enum WorkflowHelpText {
    static func render() -> String {
        """
        vphone-cli — Virtual iPhone boot tool

        LazyCat (AIO):
          make setup_machine                   Full setup through First Boot
            Options: JB=1                      Jailbreak firmware/CFW path
                     DEV=1                     Dev firmware/CFW path (dev TXM + cfw_install_dev)
                     CPU=8 MEMORY=8192         VM sizing passed to vm-create
                     DISK_SIZE=64              VM disk size in GB
                     IPHONE_SOURCE=...         Override iPhone IPSW URL/path
                     CLOUDOS_SOURCE=...        Override cloudOS IPSW URL/path
                     IPSW_DIR=...              Override IPSW cache directory
                     SKIP_PROJECT_SETUP=1      Skip setup_tools/build
                     NONE_INTERACTIVE=1        Auto-continue prompts + boot analysis
                     SUDO_PASSWORD=...         Preload sudo credential for setup flow

        Setup (one-time):
          make setup_tools             Install required host tools (vendored ldid, git-lfs, inject)

        Build:
          make build                   Build + sign vphone-cli
          make vphoned                 Cross-compile + sign vphoned for iOS
          make clean                   Remove all build artifacts (keeps IPSWs)

        VM management:
          make vm_new                  Create VM directory with manifest (config.plist)
            Options: VM_DIR=vm         VM directory name
                     CPU=8             CPU cores (stored in manifest)
                     MEMORY=8192       Memory in MB (stored in manifest)
                     DISK_SIZE=64      Disk size in GB (stored in manifest)
          make boot_host_preflight     Diagnose whether host can launch signed PV=3 binary
          make boot                    Boot VM (reads from config.plist)
          make boot_dfu                Boot VM in DFU mode (reads from config.plist)

        Firmware pipeline:
          make fw_prepare              Download IPSWs, extract, merge
            Options: LIST_FIRMWARES=1  List downloadable iPhone IPSWs for IPHONE_DEVICE and exit
                     IPHONE_DEVICE=    Device identifier for firmware lookup (default: iPhone17,3)
                     IPHONE_VERSION=   Resolve a downloadable iPhone version to an IPSW URL
                     IPHONE_BUILD=     Resolve a downloadable iPhone build to an IPSW URL
                     IPHONE_SOURCE=    URL or local path to iPhone IPSW
                     CLOUDOS_SOURCE=   URL or local path to cloudOS IPSW
          make fw_patch                Patch boot chain with Swift pipeline (regular variant)
          make fw_patch_dev            Patch boot chain with Swift pipeline (dev mode TXM patches)
          make fw_patch_jb             Patch boot chain with Swift pipeline (dev + JB extensions)

        Restore:
          make restore_get_shsh        Request restore personalization data
          make restore                 Restore firmware to the connected device

        Ramdisk:
          make ramdisk_build           Build signed SSH ramdisk
          make ramdisk_send            Send ramdisk to device

        CFW:
          make cfw_install             Install CFW mods via SSH
          make cfw_install_dev         Install CFW mods via SSH (dev mode)
          make cfw_install_jb          Install CFW + JB extensions (jetsam/procursus/basebin)

        Variables: VM_DIR=vm CPU=8 MEMORY=8192 DISK_SIZE=64
        """
    }
}
