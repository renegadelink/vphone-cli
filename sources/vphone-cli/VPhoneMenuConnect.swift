import AppKit

// MARK: - Connect Menu

extension VPhoneMenuController {
    func buildConnectMenu() -> NSMenuItem {
        let item = NSMenuItem()
        let menu = NSMenu(title: "Connect")
        menu.autoenablesItems = false

        let fileBrowser = makeItem("File Browser", action: #selector(openFiles))
        fileBrowser.isEnabled = false
        connectFileBrowserItem = fileBrowser
        menu.addItem(fileBrowser)

        let keychainBrowser = makeItem("Keychain Browser", action: #selector(openKeychain))
        keychainBrowser.isEnabled = false
        connectKeychainBrowserItem = keychainBrowser
        menu.addItem(keychainBrowser)

        menu.addItem(NSMenuItem.separator())

        let devModeStatus = makeItem("Developer Mode Status", action: #selector(devModeStatus))
        devModeStatus.isEnabled = false
        connectDevModeStatusItem = devModeStatus
        menu.addItem(devModeStatus)

        menu.addItem(NSMenuItem.separator())

        let ping = makeItem("Ping", action: #selector(sendPing))
        ping.isEnabled = false
        connectPingItem = ping
        menu.addItem(ping)

        let guestVersion = makeItem("Guest Version", action: #selector(queryGuestVersion))
        guestVersion.isEnabled = false
        connectGuestVersionItem = guestVersion
        menu.addItem(guestVersion)

        menu.addItem(NSMenuItem.separator())

        let clipGet = makeItem("Get Clipboard", action: #selector(getClipboard))
        clipGet.isEnabled = false
        clipboardGetItem = clipGet
        menu.addItem(clipGet)

        let clipSet = makeItem("Set Clipboard Text...", action: #selector(setClipboardText))
        clipSet.isEnabled = false
        clipboardSetItem = clipSet
        menu.addItem(clipSet)

        menu.addItem(NSMenuItem.separator())

        let settingsGet = makeItem("Read Setting...", action: #selector(readSetting))
        settingsGet.isEnabled = false
        settingsGetItem = settingsGet
        menu.addItem(settingsGet)

        let settingsSet = makeItem("Write Setting...", action: #selector(writeSetting))
        settingsSet.isEnabled = false
        settingsSetItem = settingsSet
        menu.addItem(settingsSet)

        menu.addItem(NSMenuItem.separator())

        menu.addItem(buildLocationSubmenu())
        menu.addItem(buildBatterySubmenu())

        item.submenu = menu
        return item
    }

    func updateSettingsAvailability(available: Bool) {
        settingsGetItem?.isEnabled = available
        settingsSetItem?.isEnabled = available
    }

    func updateConnectAvailability(available: Bool) {
        connectFileBrowserItem?.isEnabled = available
        connectKeychainBrowserItem?.isEnabled = available
        connectDevModeStatusItem?.isEnabled = available
        connectPingItem?.isEnabled = available
        connectGuestVersionItem?.isEnabled = available
    }

    @objc func openFiles() {
        onFilesPressed?()
    }

    @objc func openKeychain() {
        onKeychainPressed?()
    }

    @objc func devModeStatus() {
        Task {
            do {
                let status = try await control.sendDevModeStatus()
                showAlert(
                    title: "Developer Mode",
                    message: status.enabled ? "Developer Mode is enabled." : "Developer Mode is disabled.",
                    style: .informational
                )
            } catch {
                showAlert(title: "Developer Mode", message: "\(error)", style: .warning)
            }
        }
    }

    @objc func sendPing() {
        Task {
            do {
                try await control.sendPing()
                showAlert(title: "Ping", message: "pong", style: .informational)
            } catch {
                showAlert(title: "Ping", message: "\(error)", style: .warning)
            }
        }
    }

    @objc func queryGuestVersion() {
        Task {
            do {
                let hash = try await control.sendVersion()
                showAlert(title: "Guest Version", message: "build: \(hash)", style: .informational)
            } catch {
                showAlert(title: "Guest Version", message: "\(error)", style: .warning)
            }
        }
    }

    func updateClipboardAvailability(available: Bool) {
        clipboardGetItem?.isEnabled = available
        clipboardSetItem?.isEnabled = available
    }

    // MARK: - Clipboard

    @objc func getClipboard() {
        Task {
            do {
                let content = try await control.clipboardGet()
                var message = ""
                if let text = content.text {
                    let truncated = text.count > 500 ? String(text.prefix(500)) + "..." : text
                    message += "Text: \(truncated)\n"
                }
                message += "Types: \(content.types.joined(separator: ", "))\n"
                message += "Has Image: \(content.hasImage)\n"
                message += "Change Count: \(content.changeCount)"
                showAlert(title: "Clipboard Content", message: message, style: .informational)
            } catch {
                showAlert(title: "Clipboard", message: "\(error)", style: .warning)
            }
        }
    }

    @objc func setClipboardText() {
        let alert = NSAlert()
        alert.messageText = "Set Clipboard Text"
        alert.informativeText = "Enter text to set on the guest clipboard:"
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Set")
        alert.addButton(withTitle: "Cancel")

        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 80))
        input.placeholderString = "Text to copy to clipboard"
        alert.accessoryView = input

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let text = input.stringValue
        guard !text.isEmpty else { return }

        Task {
            do {
                try await control.clipboardSet(text: text)
                showAlert(title: "Clipboard", message: "Text set successfully.", style: .informational)
            } catch {
                showAlert(title: "Clipboard", message: "\(error)", style: .warning)
            }
        }
    }

    // MARK: - Settings

    @objc func readSetting() {
        let alert = NSAlert()
        alert.messageText = "Read Setting"
        alert.informativeText = "Enter preference domain and key:"
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Read")
        alert.addButton(withTitle: "Cancel")

        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: 350, height: 56))
        stack.orientation = .vertical
        stack.spacing = 8

        let domainField = NSTextField(frame: .zero)
        domainField.placeholderString = "com.apple.springboard"
        domainField.translatesAutoresizingMaskIntoConstraints = false
        domainField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        let keyField = NSTextField(frame: .zero)
        keyField.placeholderString = "Key (leave empty for all keys)"
        keyField.translatesAutoresizingMaskIntoConstraints = false
        keyField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        stack.addArrangedSubview(domainField)
        stack.addArrangedSubview(keyField)
        alert.accessoryView = stack

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let domain = domainField.stringValue
        guard !domain.isEmpty else { return }
        let key: String? = keyField.stringValue.isEmpty ? nil : keyField.stringValue

        Task {
            do {
                let value = try await control.settingsGet(domain: domain, key: key)
                let display: String
                if let dict = value as? [String: Any] {
                    let data = try JSONSerialization.data(
                        withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]
                    )
                    display = String(data: data, encoding: .utf8) ?? "\(dict)"
                } else {
                    display = "\(value ?? "nil")"
                }
                let truncated = display.count > 2000 ? String(display.prefix(2000)) + "\n..." : display
                showAlert(
                    title: "Setting: \(domain)\(key.map { ".\($0)" } ?? "")",
                    message: truncated,
                    style: .informational
                )
            } catch {
                showAlert(title: "Read Setting", message: "\(error)", style: .warning)
            }
        }
    }

    @objc func writeSetting() {
        let alert = NSAlert()
        alert.messageText = "Write Setting"
        alert.informativeText = "Enter preference domain, key, type, and value:"
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Write")
        alert.addButton(withTitle: "Cancel")

        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: 350, height: 116))
        stack.orientation = .vertical
        stack.spacing = 8

        let domainField = NSTextField(frame: .zero)
        domainField.placeholderString = "com.apple.springboard"
        domainField.translatesAutoresizingMaskIntoConstraints = false
        domainField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        let keyField = NSTextField(frame: .zero)
        keyField.placeholderString = "Key"
        keyField.translatesAutoresizingMaskIntoConstraints = false
        keyField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        let typeField = NSTextField(frame: .zero)
        typeField.placeholderString = "Type: boolean | string | integer | float"
        typeField.translatesAutoresizingMaskIntoConstraints = false
        typeField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        let valueField = NSTextField(frame: .zero)
        valueField.placeholderString = "Value"
        valueField.translatesAutoresizingMaskIntoConstraints = false
        valueField.widthAnchor.constraint(equalToConstant: 350).isActive = true

        stack.addArrangedSubview(domainField)
        stack.addArrangedSubview(keyField)
        stack.addArrangedSubview(typeField)
        stack.addArrangedSubview(valueField)
        alert.accessoryView = stack

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let domain = domainField.stringValue
        let key = keyField.stringValue
        let type = typeField.stringValue
        let rawValue = valueField.stringValue
        guard !domain.isEmpty, !key.isEmpty else { return }

        let value: Any =
            switch type.lowercased() {
            case "boolean", "bool":
                rawValue.lowercased() == "true" || rawValue == "1"
            case "integer", "int":
                Int(rawValue) ?? 0
            case "float", "double":
                Double(rawValue) ?? 0.0
            default:
                rawValue
            }

        Task {
            do {
                try await control.settingsSet(
                    domain: domain, key: key, value: value, type: type.isEmpty ? nil : type
                )
                showAlert(
                    title: "Write Setting", message: "Set \(domain).\(key) = \(rawValue)",
                    style: .informational
                )
            } catch {
                showAlert(title: "Write Setting", message: "\(error)", style: .warning)
            }
        }
    }

    // MARK: - Alert

    func showAlert(title: String, message: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = style
        if let window = NSApp.keyWindow {
            alert.beginSheetModal(for: window)
        } else {
            alert.runModal()
        }
    }
}
