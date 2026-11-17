import Cocoa
import Security

/// Shared path handling for Finder drops, copied paths, and file:// URLs.
enum SigningFilePath {
    static func normalize(_ value: String) -> String {
        var path = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if path.count >= 2, let first = path.first, let last = path.last,
           (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            path = String(path.dropFirst().dropLast())
        }
        if let url = URL(string: path), url.isFileURL { return url.path }
        return (path as NSString).expandingTildeInPath
    }

    static func paths(from pasteboard: NSPasteboard) -> [String] {
        if let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL], !urls.isEmpty {
            return urls.map { $0.path }
        }
        if let paths = pasteboard.propertyList(forType: .init("NSFilenamesPboardType")) as? [String], !paths.isEmpty {
            return paths
        }
        if let text = pasteboard.string(forType: .string) {
            return [normalize(text)]
        }
        if let text = pasteboard.string(forType: .URL) { return [normalize(text)] }
        return []
    }
}

final class SigningPathField: NSTextField {
    var allowedExtensions: [String] = []
    var onFileDrop: ((String) -> Void)?

    init(placeholder: String, extensions: [String]) {
        super.init(frame: .zero)
        placeholderString = placeholder
        allowedExtensions = extensions
        font = .systemFont(ofSize: 12)
        lineBreakMode = .byTruncatingMiddle
        cell?.isScrollable = true
        registerForDraggedTypes([.fileURL, .URL, .string, .init("NSFilenamesPboardType")])
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func acceptedPath(_ sender: NSDraggingInfo) -> String? {
        guard isEnabled, let path = SigningFilePath.paths(from: sender.draggingPasteboard).first,
              allowedExtensions.contains(URL(fileURLWithPath: path).pathExtension.lowercased()),
              FileManager.default.fileExists(atPath: path) else { return nil }
        return path
    }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        acceptedPath(sender) == nil ? [] : .copy
    }

    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation { draggingEntered(sender) }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard let path = acceptedPath(sender) else { return false }
        onFileDrop?(path)
        return true
    }
}

enum SigningCertificateFile {
    /// The caller supplies the destination, allowing imports to be verified in an isolated keychain.
    static func importData(_ data: Data, filename: String, password: String, keychain: SecKeychain) -> (status: OSStatus, names: [String]) {
        var items: CFArray?
        let status: OSStatus
        var names: [String] = []
        if ["p12", "pfx"].contains(filename.pathExtension.lowercased()) {
            // SecPKCS12Import supports modern encrypted P12 files that SecItemImport rejects.
            let options = [
                kSecImportExportPassphrase as String: password,
                kSecImportExportKeychain as String: keychain
            ] as CFDictionary
            status = SecPKCS12Import(data as CFData, options, &items)
            for entry in (items as? [[String: Any]]) ?? [] {
                if let identity = entry[kSecImportItemIdentity as String] {
                    var certificate: SecCertificate?
                    _ = SecIdentityCopyCertificate(identity as! SecIdentity, &certificate)
                    if let certificate, let name = SecCertificateCopySubjectSummary(certificate) as String? { names.append(name) }
                }
            }
        } else {
            var format: SecExternalFormat = .formatUnknown
            var itemType: SecExternalItemType = .itemTypeUnknown
            status = SecItemImport(data as CFData, filename as CFString, &format, &itemType, [], nil, keychain, &items)
            if status == errSecDuplicateItem {
                _ = SecItemImport(data as CFData, filename as CFString, &format, &itemType, [], nil, nil, &items)
            }
            for item in (items as? [AnyObject]) ?? [] {
                if CFGetTypeID(item) == SecCertificateGetTypeID(),
                   let name = SecCertificateCopySubjectSummary(item as! SecCertificate) as String? { names.append(name) }
            }
        }
        return (status, names)
    }
}

final class SigningDocumentView: NSView {
    override var isFlipped: Bool { true }
}

extension MainView {
    func configureSigningLayout() {
        guard let window else { return }
        // Reuse the nib's controls and actions; replace its fixed, compact layout.
        NSLayoutConstraint.deactivate(constraints)
        subviews.forEach { $0.removeFromSuperview() }
        window.maxSize = NSSize(width: 10000, height: 10000)
        window.contentMinSize = NSSize(width: 900, height: 600)
        let screen = window.screen?.visibleFrame.size ?? NSSize(width: 1440, height: 1000)
        window.setContentSize(NSSize(width: min(1100, screen.width - 60), height: min(900, screen.height - 80)))
        window.autorecalculatesKeyViewLoop = true
        window.center()

        let header = verticalStack(spacing: 5)
        header.addArrangedSubview(uiLabel("iOS App Signer", size: 23, weight: .semibold))
        header.addArrangedSubview(uiLabel("选择签名材料，核对权限，再导出签名后的应用。", size: 12, secondary: true))
        addSubview(header)
        for label in header.arrangedSubviews { label.widthAnchor.constraint(equalTo: header.widthAnchor).isActive = true }

        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        addSubview(scroll)
        let document = SigningDocumentView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        let content = verticalStack(spacing: 16)
        document.addSubview(content)
        NSLayoutConstraint.activate([
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            content.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 24),
            content.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -24),
            content.topAnchor.constraint(equalTo: document.topAnchor, constant: 4),
            content.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -20)
        ])

        let topCards = horizontalStack(spacing: 16)
        topCards.alignment = .top
        content.addArrangedSubview(topCards)
        topCards.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
        let materials = verticalStack(spacing: 8)
        materials.addArrangedSubview(sectionHeading("签名材料", subtitle: "支持选择文件、拖入文件或粘贴完整路径。"))
        BrowseButton.title = "选择应用…"
        InputFileText.placeholderString = "拖入 IPA / App，或粘贴路径 / 下载地址"
        materials.addArrangedSubview(labeledRow("应用文件", views: [InputFileText, BrowseButton]))
        CodesigningCertsPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        materials.addArrangedSubview(labeledRow("签名证书", views: [CodesigningCertsPopup]))
        certificatePathField = pathField("拖入 .p12 / .pfx / .cer，或粘贴证书路径", extensions: MainView.certificateFileTypes)
        certificatePathField?.onFileDrop = { [weak self] in self?.loadCertificateFile($0) }
        let certButton = NSButton(title: "导入证书…", target: self, action: #selector(chooseCertificateFile(_:)))
        certificateBrowseButton = certButton
        materials.addArrangedSubview(labeledRow("证书文件", views: [certificatePathField!, certButton]))
        certificateHintLabel = uiLabel("使用钥匙串中的签名身份；导入 P12 / PFX 时需包含私钥。", size: 11, secondary: true)
        materials.addArrangedSubview(indented(certificateHintLabel!))
        ProvisioningProfilesPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        materials.addArrangedSubview(labeledRow("描述文件", views: [ProvisioningProfilesPopup]))
        profilePathField = pathField("拖入 .mobileprovision，或粘贴描述文件路径", extensions: ["mobileprovision"])
        profilePathField?.onFileDrop = { [weak self] in self?.loadProfileFile($0) }
        let profileButton = NSButton(title: "选择文件…", target: self, action: #selector(chooseProfileFile(_:)))
        profileBrowseButton = profileButton
        materials.addArrangedSubview(labeledRow("文件路径", views: [profilePathField!, profileButton]))
        profileDetailsLabel = uiLabel("未选择描述文件，将尝试使用应用内嵌的描述文件。", size: 11, secondary: true)
        materials.addArrangedSubview(indented(profileDetailsLabel!))
        let materialsCard = addCard(materials, to: topCards, fullWidth: false)
        materialsCard.widthAnchor.constraint(equalTo: topCards.widthAnchor, multiplier: 0.62, constant: -8).isActive = true

        let metadata = verticalStack(spacing: 9)
        metadata.addArrangedSubview(sectionHeading("应用信息", subtitle: "可选；留空的字段保留应用原值。"))
        NewApplicationIDTextField.placeholderString = "保留原 Bundle ID"
        appDisplayName.placeholderString = "保留原应用名称"
        appShortVersion.placeholderString = "例如 5.15"
        appVersion.placeholderString = "例如 2026111701"
        for (title, field) in [("Bundle ID", NewApplicationIDTextField!), ("显示名称", appDisplayName!)] {
            let column = verticalStack(spacing: 4)
            column.addArrangedSubview(uiLabel(title, size: 11, secondary: true))
            column.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: column.widthAnchor).isActive = true
            metadata.addArrangedSubview(column)
        }
        let details = horizontalStack(spacing: 12)
        for (title, field) in [("版本号", appShortVersion!), ("构建号", appVersion!)] {
            let column = verticalStack(spacing: 6)
            column.addArrangedSubview(uiLabel(title, size: 11, secondary: true))
            column.addArrangedSubview(field)
            field.widthAnchor.constraint(equalTo: column.widthAnchor).isActive = true
            details.addArrangedSubview(column)
        }
        details.distribution = .fillEqually
        metadata.addArrangedSubview(details)
        ignorePluginsCheckbox.title = "跳过 PlugIns 扩展"
        noGetTaskAllowCheckbox.title = "移除 get-task-allow 调试权限"
        ignorePluginsCheckbox.font = .systemFont(ofSize: 11)
        noGetTaskAllowCheckbox.font = .systemFont(ofSize: 11)
        metadata.addArrangedSubview(ignorePluginsCheckbox)
        metadata.addArrangedSubview(noGetTaskAllowCheckbox)
        let metadataCard = addCard(metadata, to: topCards, fullWidth: false)
        metadataCard.widthAnchor.constraint(equalTo: topCards.widthAnchor, multiplier: 0.38, constant: -8).isActive = true

        let box = NSBox()
        box.translatesAutoresizingMaskIntoConstraints = false
        box.boxType = .custom
        box.borderColor = .separatorColor
        box.borderWidth = 0.5
        box.cornerRadius = 10
        box.fillColor = .controlBackgroundColor
        box.contentViewMargins = NSSize(width: 18, height: 18)
        content.addArrangedSubview(box)
        box.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
        entitlementPanel = box

        let footer = horizontalStack(spacing: 16)
        footer.distribution = .fill
        StatusLabel.font = .systemFont(ofSize: 11)
        StatusLabel.textColor = .secondaryLabelColor
        StatusLabel.lineBreakMode = .byTruncatingMiddle
        StatusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        StatusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        StartButton.title = "开始签名…"
        StartButton.bezelStyle = .rounded
        StartButton.bezelColor = .controlAccentColor
        StartButton.contentTintColor = .white
        StartButton.toolTip = "核对签名材料及最终权限后，选择导出位置并开始签名。"
        StartButton.widthAnchor.constraint(equalToConstant: 120).isActive = true
        footer.addArrangedSubview(StatusLabel)
        downloadProgress.widthAnchor.constraint(equalToConstant: 100).isActive = true
        footer.addArrangedSubview(downloadProgress)
        footer.addArrangedSubview(StartButton)
        addSubview(footer)
        let divider = NSBox()
        divider.boxType = .separator
        divider.translatesAutoresizingMaskIntoConstraints = false
        addSubview(divider)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 26),
            header.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -26),
            header.topAnchor.constraint(equalTo: topAnchor, constant: 16),
            scroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 14),
            scroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: divider.topAnchor, constant: -4),
            divider.leadingAnchor.constraint(equalTo: leadingAnchor),
            divider.trailingAnchor.constraint(equalTo: trailingAnchor),
            footer.topAnchor.constraint(equalTo: divider.bottomAnchor, constant: 12),
            footer.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 26),
            footer.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -26),
            footer.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -14)
        ])
        DispatchQueue.main.async { [weak self, weak scroll] in
            self?.layoutSubtreeIfNeeded()
            scroll?.contentView.scroll(to: .zero)
            if let scroll { scroll.reflectScrolledClipView(scroll.contentView) }
        }
        for field in [InputFileText, NewApplicationIDTextField, appDisplayName, appShortVersion, appVersion] {
            field?.font = .systemFont(ofSize: 12)
            field?.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        }
    }

    func uiLabel(_ text: String, size: CGFloat = 12, weight: NSFont.Weight = .regular, secondary: Bool = false) -> NSTextField {
        let label = NSTextField(wrappingLabelWithString: text)
        label.font = .systemFont(ofSize: size, weight: weight)
        label.textColor = secondary ? .secondaryLabelColor : .labelColor
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return label
    }

    func verticalStack(spacing: CGFloat) -> NSStackView {
        let stack = NSStackView()
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = spacing
        return stack
    }

    func horizontalStack(views: [NSView] = [], spacing: CGFloat = 8) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = spacing
        return stack
    }

    func sectionHeading(_ title: String, subtitle: String) -> NSStackView {
        let heading = verticalStack(spacing: 4)
        heading.addArrangedSubview(uiLabel(title, size: 14, weight: .semibold))
        heading.addArrangedSubview(uiLabel(subtitle, size: 11, secondary: true))
        return heading
    }

    func labeledRow(_ title: String, views: [NSView]) -> NSStackView {
        let label = uiLabel(title, size: 12, secondary: true)
        label.widthAnchor.constraint(equalToConstant: 86).isActive = true
        let row = horizontalStack(views: [label] + views, spacing: 10)
        for view in views { view.translatesAutoresizingMaskIntoConstraints = false }
        if let first = views.first {
            first.setContentHuggingPriority(.defaultLow, for: .horizontal)
            first.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        }
        return row
    }

    func indented(_ view: NSView) -> NSStackView {
        let spacer = NSView()
        spacer.widthAnchor.constraint(equalToConstant: 86).isActive = true
        return horizontalStack(views: [spacer, view], spacing: 10)
    }

    @discardableResult
    func addCard(_ stack: NSStackView, to parent: NSStackView, fullWidth: Bool = true) -> NSBox {
        let card = NSBox()
        card.translatesAutoresizingMaskIntoConstraints = false
        card.boxType = .custom
        card.borderColor = .separatorColor
        card.borderWidth = 0.5
        card.cornerRadius = 10
        card.fillColor = .controlBackgroundColor
        card.contentViewMargins = NSSize(width: 18, height: 18)
        if let interior = card.contentView {
            interior.addSubview(stack)
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: interior.leadingAnchor),
                stack.trailingAnchor.constraint(equalTo: interior.trailingAnchor),
                stack.topAnchor.constraint(equalTo: interior.topAnchor),
                stack.bottomAnchor.constraint(equalTo: interior.bottomAnchor)
            ])
        }
        parent.addArrangedSubview(card)
        if fullWidth { card.widthAnchor.constraint(equalTo: parent.widthAnchor).isActive = true }
        for row in stack.arrangedSubviews { row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        return card
    }

    func pathField(_ placeholder: String, extensions: [String]) -> SigningPathField {
        let field = SigningPathField(placeholder: placeholder, extensions: extensions)
        field.translatesAutoresizingMaskIntoConstraints = false
        field.delegate = self
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }

    @objc func chooseCertificateFile(_ sender: Any?) { chooseSigningFile(extensions: MainView.certificateFileTypes, handler: loadCertificateFile) }
    @objc func chooseProfileFile(_ sender: Any?) { chooseSigningFile(extensions: ["mobileprovision"], handler: loadProfileFile) }

    func chooseSigningFile(extensions: [String], handler: (String) -> Void) {
        let dialog = NSOpenPanel()
        dialog.canChooseDirectories = false
        dialog.allowsMultipleSelection = false
        dialog.allowedFileTypes = extensions
        if dialog.runModal() == .OK, let url = dialog.url { handler(url.path) }
    }

    func showSigningFileError(_ message: String, detail: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = message
        alert.informativeText = detail
        alert.addButton(withTitle: "好")
        alert.runModal()
    }

    func loadProfileFile(_ value: String) {
        guard StartButton.isEnabled else { return }
        let path = SigningFilePath.normalize(value)
        guard path.pathExtension.lowercased() == "mobileprovision", fileManager.fileExists(atPath: path),
              let profile = ProvisioningProfile(filename: path) else {
            showSigningFileError("无法读取描述文件", detail: "请选择有效的 .mobileprovision 文件。\n\(path)")
            profilePathField?.stringValue = profileFilename ?? ""
            return
        }
        guard profile.expires > Date() else {
            showSigningFileError("描述文件已过期", detail: "\(profile.name)\n请选择仍在有效期内的描述文件。")
            profilePathField?.stringValue = profileFilename ?? ""
            return
        }
        ProvisioningProfilesPopup.selectItem(at: 1)
        checkProfileID(profile)
    }

    func updateProfileDetails() {
        let profile = selectedProvisioningProfile
        profilePathField?.stringValue = profile?.filename ?? ""
        profilePathField?.toolTip = profile?.filename
        guard let profile else {
            profileDetailsLabel?.stringValue = "未选择描述文件，将尝试使用应用内嵌的描述文件。"
            return
        }
        let date = DateFormatter()
        date.dateStyle = .medium
        profileDetailsLabel?.stringValue = "\(profile.name)  ·  Team ID: \(profile.teamID)  ·  有效期至 \(date.string(from: profile.expires))"
        profileDetailsLabel?.toolTip = "Bundle ID: \(profile.appID)\n\(profile.filename)"
    }

    func loadCertificateFile(_ value: String) {
        guard signingControlsEnabled, !isImportingCertificate else { return }
        isImportingCertificate = true
        defer { isImportingCertificate = false }
        let path = SigningFilePath.normalize(value)
        guard MainView.certificateFileTypes.contains(path.pathExtension.lowercased()),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            showSigningFileError("无法读取证书文件", detail: "请选择 .p12、.pfx、.cer、.crt 或 .pem 文件。\n\(path)")
            certificatePathField?.stringValue = certificateFilePath ?? ""
            return
        }
        let isPKCS12 = ["p12", "pfx"].contains(path.pathExtension.lowercased())
        var password = ""
        if isPKCS12 {
            let alert = NSAlert()
            alert.messageText = "导入签名证书"
            alert.informativeText = "\(path.lastPathComponent)\n请输入证书密码（无密码可留空）。证书和私钥将导入默认钥匙串。"
            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
            field.placeholderString = "证书密码"
            alert.accessoryView = field
            alert.addButton(withTitle: "导入")
            alert.addButton(withTitle: "取消")
            alert.window.initialFirstResponder = field
            guard alert.runModal() == .alertFirstButtonReturn else {
                certificatePathField?.stringValue = certificateFilePath ?? ""
                return
            }
            password = field.stringValue
            field.stringValue = ""
        }
        var keychain: SecKeychain?
        var status = SecKeychainCopyDefault(&keychain)
        guard status == errSecSuccess, let keychain else {
            showSigningFileError("无法打开默认钥匙串", detail: (SecCopyErrorMessageString(status, nil) as String?) ?? "请在钥匙串访问中检查默认钥匙串。")
            return
        }
        let result = SigningCertificateFile.importData(data, filename: path.lastPathComponent, password: password, keychain: keychain)
        password = ""
        status = result.status
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            showSigningFileError("证书导入失败", detail: "\(isPKCS12 ? "请检查密码和文件是否正确。\n" : "")\((SecCopyErrorMessageString(status, nil) as String?) ?? "无法解析证书")")
            certificatePathField?.stringValue = certificateFilePath ?? ""
            return
        }
        let names = result.names
        let previous = CodesigningCertsPopup.titleOfSelectedItem
        populateCodesigningCerts()
        certificateFilePath = path
        certificatePathField?.stringValue = path
        certificatePathField?.toolTip = path
        if let match = names.first(where: { codesigningCerts.contains($0) }) {
            CodesigningCertsPopup.selectItem(withTitle: match)
            chooseSigningCertificate(CodesigningCertsPopup)
            certificateHintLabel?.stringValue = "已导入并选择：\(match)"
            certificateHintLabel?.textColor = .secondaryLabelColor
            setStatus("已导入签名证书：\(match)")
        } else {
            if let previous { CodesigningCertsPopup.selectItem(withTitle: previous) }
            certificateHintLabel?.stringValue = "文件已导入，但未找到对应的有效签名身份。签名需要匹配的私钥；请导入包含私钥的 P12 / PFX。"
            certificateHintLabel?.textColor = .systemOrange
            setStatus("证书已导入，请检查是否包含有效签名身份")
        }
    }

    func setSigningInputControlsEnabled(_ enabled: Bool) {
        profilePathField?.isEnabled = enabled
        certificatePathField?.isEnabled = enabled
        profileBrowseButton?.isEnabled = enabled
        certificateBrowseButton?.isEnabled = enabled
        entitlementFilePathLabel?.isEnabled = enabled
        entitlementSourcePopup?.isEnabled = enabled
        finalAppGroupsField?.isEnabled = enabled
        finalKeychainGroupsField?.isEnabled = enabled
        chooseEntitlementsFileButton?.isEnabled = enabled
        clearEntitlementsFileButton?.isEnabled = enabled && entitlementFilePath != nil
        appShortVersion.isEnabled = enabled
        appVersion.isEnabled = enabled
        ignorePluginsCheckbox.isEnabled = enabled
        noGetTaskAllowCheckbox.isEnabled = enabled
    }

    func acceptPathEdit(_ field: NSTextField, reportError: Bool) {
        guard signingControlsEnabled else { return }
        let path = SigningFilePath.normalize(field.stringValue)
        guard !path.isEmpty else {
            if field === profilePathField { updateProfileDetails() }
            if field === certificatePathField { field.stringValue = certificateFilePath ?? "" }
            return
        }
        if !reportError, let pathField = field as? SigningPathField,
           !pathField.allowedExtensions.contains(path.pathExtension.lowercased()) { return }
        let exists = fileManager.fileExists(atPath: path)
        if field === profilePathField {
            if path == profileFilename { field.stringValue = path; return }
            if exists || reportError { loadProfileFile(path) }
        } else if field === certificatePathField {
            if path == certificateFilePath { field.stringValue = path; return }
            if exists || reportError { loadCertificateFile(path) }
        } else if field === entitlementFilePathLabel {
            guard exists, MainView.entitlementsFileTypes.contains(path.pathExtension.lowercased()) else {
                if reportError {
                    showSigningFileError("无法读取权限文件", detail: "请选择有效的 .entitlements 或 .plist 文件。")
                    field.stringValue = entitlementFilePath ?? ""
                }
                return
            }
            guard path != entitlementFilePath else { return }
            entitlementFilePath = path
            finalEntitlementSource = .entitlementsFile
            finalEntitlementsUserEdited = true
            scheduleEntitlementInspection()
        }
    }
}
