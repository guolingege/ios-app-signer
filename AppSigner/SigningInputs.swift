import Cocoa
import Security
import CryptoKit

/// Original application values, never signing overrides or profile-derived identifiers.
struct ApplicationMetadata {
    let values: [String: String]
    let sourcePath: String

    static func read(at path: String, sourcePath: String) -> ApplicationMetadata? {
        guard let data = FileManager.default.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let info = plist as? [String: Any] else { return nil }
        func text(_ key: String) -> String? {
            if let value = info[key] as? String, !value.isEmpty { return value }
            return (info[key] as? NSNumber)?.stringValue
        }
        var values: [String: String] = [:]
        for key in ["CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"] {
            values[key] = text(key)
        }
        values["CFBundleDisplayName"] = text("CFBundleDisplayName") ?? text("CFBundleName")
        return ApplicationMetadata(values: values, sourcePath: sourcePath)
    }
}

struct SigningIdentity {
    let fingerprint: String
    let commonName: String
    let displayName: String
    let certificateData: Data?

    static func parse(_ output: String, certificates: [Data]) -> [SigningIdentity] {
        let regex = try! NSRegularExpression(pattern: #"(?m)^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"([^"]+)""#)
        var seen = Set<String>()
        let entries = regex.matches(in: output, range: NSRange(output.startIndex..., in: output)).compactMap { match -> (String, String)? in
            guard let hash = Range(match.range(at: 1), in: output), let name = Range(match.range(at: 2), in: output) else { return nil }
            let fingerprint = String(output[hash]).uppercased()
            guard seen.insert(fingerprint).inserted else { return nil }
            return (fingerprint, String(output[name]))
        }
        let counts = Dictionary(grouping: entries, by: { $0.1 }).mapValues { $0.count }
        return entries.map { fingerprint, name in
            SigningIdentity(fingerprint: fingerprint, commonName: name,
                displayName: counts[name] == 1 ? name : "\(name) [\(fingerprint.suffix(8))]",
                certificateData: certificates.first { SigningCertificateFile.fingerprint($0) == fingerprint })
        }.sorted { $0.displayName < $1.displayName }
    }
}

enum SigningInputSource: Int {
    case existing
    case file
}

/// This policy reads the selected external profile only, never the application's embedded profile.
enum LeagsoftEntitlementPolicy {
    static func values(from profile: ProvisioningProfile) -> (appGroups: [String], keychainGroups: [String], teamID: String)? {
        // A migrated App ID prefix is not necessarily the team's identifier.
        let teamID = (profile.teamIdentifier ?? (profile.entitlements["com.apple.developer.team-identifier"] as? String) ?? profile.teamID)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !teamID.isEmpty, !teamID.contains("*"), !teamID.contains(".") else { return nil }
        return (
            profile.entitlements["com.apple.security.application-groups"] as? [String] ?? [],
            ["\(teamID).com.apple.networkextensionsharing", "\(teamID).com.leagsoft.emm"],
            teamID
        )
    }
}

/// Shared path handling for Finder drops, copied paths, and file:// URLs.
enum SigningFilePath {
    static func normalize(_ value: String) -> String {
        var path = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if path.count >= 2, let first = path.first, let last = path.last,
           (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            path = String(path.dropFirst().dropLast())
        }
        if let url = URL(string: path), url.isFileURL {
            guard url.host == nil || url.host == "" || url.host == "localhost" else { return path }
            return url.path
        }
        // NSString expansion also collapses // and ://, which can disguise remote paths.
        return path.hasPrefix("~") ? (path as NSString).expandingTildeInPath : path
    }

    static func paths(from pasteboard: NSPasteboard) -> [String] {
        if let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL], !urls.isEmpty {
            return urls.map { normalize($0.absoluteString) }
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
              OfflineNetworkPolicy.isLocalPath(path), allowedExtensions.contains(URL(fileURLWithPath: path).pathExtension.lowercased()),
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
    static func fingerprint(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }

    static func fileDigest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined() }

    static func keychainCertificates() -> [Data] {
        var result: CFTypeRef?
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnData as String: true, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return [] }
        return result as? [Data] ?? []
    }

    /// The caller supplies the destination, allowing imports to be verified in an isolated keychain.
    static func importData(_ data: Data, filename: String, password: String, keychain: SecKeychain) -> (status: OSStatus, names: [String], certificates: [Data]) {
        var items: CFArray?
        let status: OSStatus
        var names: [String] = []
        var certificates: [Data] = []
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
                    if let certificate, let name = SecCertificateCopySubjectSummary(certificate) as String? {
                        names.append(name)
                        certificates.append(SecCertificateCopyData(certificate) as Data)
                    }
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
                   let name = SecCertificateCopySubjectSummary(item as! SecCertificate) as String? {
                    names.append(name)
                    certificates.append(SecCertificateCopyData(item as! SecCertificate) as Data)
                }
            }
        }
        return (status, names, certificates)
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

        let header = horizontalStack(spacing: 16)
        let title = verticalStack(spacing: 5)
        title.addArrangedSubview(uiLabel("联软EMM签名", size: 23, weight: .semibold))
        title.addArrangedSubview(uiLabel("离线签名 · 选择本地材料，核对权限，再导出应用。", size: 12, secondary: true))
        header.addArrangedSubview(title)
        let refresh = NSButton(title: "刷新", target: self, action: #selector(refreshSigningInputs(_:)))
        refresh.toolTip = "统一刷新：重新读取应用信息、Mach-O 权限、内嵌 / 外部描述文件、权限文件及证书，包含同一路径被替换的文件。保留已填写的签名新值；Bundle ID 仍受所选描述文件约束。"
        refresh.translatesAutoresizingMaskIntoConstraints = false
        refresh.widthAnchor.constraint(equalToConstant: 76).isActive = true
        refreshInspectionButton = refresh
        header.addArrangedSubview(refresh)
        title.widthAnchor.constraint(equalTo: header.widthAnchor, constant: -92).isActive = true
        addSubview(header)
        for label in title.arrangedSubviews { label.widthAnchor.constraint(equalTo: title.widthAnchor).isActive = true }

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
        materials.addArrangedSubview(sectionHeading("签名材料", subtitle: "证书和描述文件各选一种来源；仅当前方式生效。"))
        BrowseButton.title = "选择应用…"
        InputFileText.placeholderString = "拖入本地 IPA / App，或粘贴本地路径"
        materials.addArrangedSubview(labeledRow("应用文件", views: [InputFileText, BrowseButton]))
        CodesigningCertsPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        certificateSourceControl = sourceControl(labels: ["从钥匙串选择", "使用证书文件"], action: #selector(certificateSourceChanged(_:)))
        materials.addArrangedSubview(labeledRow("签名证书", views: [certificateSourceControl!]))
        certificateExistingRow = labeledRow("钥匙串身份", views: [CodesigningCertsPopup])
        materials.addArrangedSubview(certificateExistingRow!)
        certificatePathField = pathField("拖入 .p12 / .pfx / .cer，或粘贴证书路径", extensions: MainView.certificateFileTypes)
        certificatePathField?.onFileDrop = { [weak self] in self?.loadCertificateFile($0) }
        let certButton = NSButton(title: "导入证书…", target: self, action: #selector(chooseCertificateFile(_:)))
        certificateBrowseButton = certButton
        certificateFileRow = labeledRow("证书文件", views: [certificatePathField!, certButton])
        materials.addArrangedSubview(certificateFileRow!)
        certificateHintLabel = uiLabel("使用钥匙串中的签名身份；导入 P12 / PFX 时需包含私钥。", size: 11, secondary: true)
        materials.addArrangedSubview(indented(certificateHintLabel!))
        ProvisioningProfilesPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        profileSourceControl = sourceControl(labels: ["已安装 / App 内嵌", "指定文件"], action: #selector(profileSourceChanged(_:)))
        materials.addArrangedSubview(labeledRow("描述文件", views: [profileSourceControl!]))
        profileExistingRow = labeledRow("已有配置", views: [ProvisioningProfilesPopup])
        materials.addArrangedSubview(profileExistingRow!)
        profilePathField = pathField("拖入 .mobileprovision，或粘贴描述文件路径", extensions: ["mobileprovision"])
        profilePathField?.onFileDrop = { [weak self] in self?.loadProfileFile($0) }
        let profileButton = NSButton(title: "选择文件…", target: self, action: #selector(chooseProfileFile(_:)))
        profileBrowseButton = profileButton
        profileFileRow = labeledRow("文件路径", views: [profilePathField!, profileButton])
        materials.addArrangedSubview(profileFileRow!)
        profileDetailsLabel = uiLabel("未选择描述文件，将尝试使用应用内嵌的描述文件。", size: 11, secondary: true)
        materials.addArrangedSubview(indented(profileDetailsLabel!))
        certificateMatchLabel = uiLabel("正在检查证书与描述文件…", size: 11, secondary: true)
        materials.addArrangedSubview(indented(certificateMatchLabel!))
        let materialsCard = addCard(materials, to: topCards, fullWidth: false)
        materialsCard.widthAnchor.constraint(equalTo: topCards.widthAnchor, multiplier: 0.62, constant: -8).isActive = true

        let metadata = verticalStack(spacing: 9)
        metadata.addArrangedSubview(sectionHeading("应用信息", subtitle: "当前值来自应用 Info.plist；下方可填写签名新值。"))
        applicationMetadataStatusLabel = uiLabel("未选择应用", size: 11, secondary: true)
        metadata.addArrangedSubview(applicationMetadataStatusLabel!)
        NewApplicationIDTextField.placeholderString = "新 Bundle ID（留空保留）"
        NewApplicationIDTextField.toolTip = "签名使用的 Bundle ID；精确描述文件会自动指定该值。上方“当前”始终显示原应用的 Bundle ID。"
        appDisplayName.placeholderString = "新显示名称（留空保留）"
        appShortVersion.placeholderString = "新版本号（可选）"
        appVersion.placeholderString = "新构建号（可选）"
        metadata.addArrangedSubview(applicationMetadataColumn("Bundle ID", key: "CFBundleIdentifier", field: NewApplicationIDTextField))
        metadata.addArrangedSubview(applicationMetadataColumn("显示名称", key: "CFBundleDisplayName", field: appDisplayName))
        let details = horizontalStack(spacing: 12)
        details.addArrangedSubview(applicationMetadataColumn("版本号", key: "CFBundleShortVersionString", field: appShortVersion))
        details.addArrangedSubview(applicationMetadataColumn("构建号", key: "CFBundleVersion", field: appVersion))
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
        updateSigningInputSources()
    }

    func applicationMetadataColumn(_ title: String, key: String, field: NSTextField) -> NSStackView {
        let column = verticalStack(spacing: 4)
        column.addArrangedSubview(uiLabel(title, size: 11, secondary: true))
        let current = uiLabel("当前：—", size: 12, weight: .medium)
        current.isSelectable = true
        current.maximumNumberOfLines = 2
        current.lineBreakMode = .byTruncatingMiddle
        applicationMetadataLabels[key] = current
        column.addArrangedSubview(current)
        column.addArrangedSubview(field)
        current.widthAnchor.constraint(equalTo: column.widthAnchor).isActive = true
        field.widthAnchor.constraint(equalTo: column.widthAnchor).isActive = true
        return column
    }

    func updateApplicationMetadataDisplay(status: String) {
        applicationMetadataStatusLabel?.stringValue = status
        applicationMetadataStatusLabel?.toolTip = inspectedApplicationMetadata?.sourcePath ?? status
        for (key, label) in applicationMetadataLabels {
            let value = inspectedApplicationMetadata.map { $0.values[key] ?? "未设置" } ?? "—"
            label.stringValue = "当前：\(value)"
            label.toolTip = inspectedApplicationMetadata.map { "\(value)\n来源：\($0.sourcePath)\n\(key == "CFBundleDisplayName" ? "CFBundleDisplayName（缺失时使用 CFBundleName）" : key)" } ?? status
        }
    }

    func sourceControl(labels: [String], action: Selector) -> NSSegmentedControl {
        let control = NSSegmentedControl(labels: labels, trackingMode: .selectOne, target: self, action: action)
        control.selectedSegment = 0
        control.segmentStyle = .rounded
        control.font = .systemFont(ofSize: 11)
        control.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        return control
    }

    @objc func certificateSourceChanged(_ sender: NSSegmentedControl) {
        guard signingControlsEnabled, let source = SigningInputSource(rawValue: sender.selectedSegment) else { return }
        pathEditWorkItem?.cancel()
        certificateInputSource = source
        window?.makeFirstResponder(nil)
        updateSigningInputSources()
    }

    @objc func profileSourceChanged(_ sender: NSSegmentedControl) {
        guard signingControlsEnabled, let source = SigningInputSource(rawValue: sender.selectedSegment) else { return }
        pathEditWorkItem?.cancel()
        profileInputSource = source
        window?.makeFirstResponder(nil)
        applyProfileInputSelection()
    }

    /// The inactive source is retained for switching back, but never participates in signing.
    var currentSigningCertificate: String? {
        if certificateInputSource == .file {
            guard let name = importedCertificateName, let fingerprint = importedCertificateFingerprint,
                  codesigningCerts.contains(name),
                  signingIdentities.contains(where: { $0.fingerprint == fingerprint && $0.displayName == name }) else { return nil }
            return name
        }
        guard let name = CodesigningCertsPopup.titleOfSelectedItem, codesigningCerts.contains(name) else { return nil }
        return name
    }

    var currentSigningIdentity: SigningIdentity? {
        guard let name = currentSigningCertificate else { return nil }
        return signingIdentities.first { $0.displayName == name }
    }

    var currentSigningCertificateFingerprint: String? { currentSigningIdentity?.fingerprint }

    var activeSigningProfile: ProvisioningProfile? {
        guard profileReadError == nil else { return nil }
        if let profile = selectedProvisioningProfile { return profile }
        return !isLeagsoftApp && profileInputSource == .existing ? inspectedEmbeddedProfile : nil
    }

    var certificateFileValidationMessage: String? {
        guard certificateInputSource == .file else { return nil }
        guard let path = certificateFilePath, let digest = importedCertificateFileDigest,
              OfflineNetworkPolicy.isLocalPath(path), let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              SigningCertificateFile.fileDigest(data) == digest else {
            return "证书文件已更改、丢失或尚未导入，请刷新并重新导入；不会沿用旧证书。"
        }
        return nil
    }

    var certificateProfileValidationMessage: String? {
        if let message = profileReadError { return message }
        if let message = certificateFileValidationMessage { return message }
        guard let identity = currentSigningIdentity, let data = identity.certificateData else {
            return "无法读取当前签名身份的证书；请刷新或重新导入包含私钥的证书。"
        }
        guard let profile = activeSigningProfile else { return "尚无可读取的签名描述文件，无法检查证书是否匹配。" }
        guard profile.expires > Date() else { return "签名描述文件已过期。" }
        guard !profile.developerCertificates.isEmpty else { return "描述文件缺少 DeveloperCertificates，无法验证签名证书。" }
        guard profile.developerCertificates.contains(data) else {
            return "证书与描述文件不匹配：DeveloperCertificates 中未包含当前证书（\(identity.fingerprint.suffix(8))）。"
        }
        return nil
    }

    var signingReadinessMessage: String? {
        let path = SigningFilePath.normalize(InputFileText.stringValue)
        guard !path.isEmpty else { return "请选择本地应用文件。" }
        guard OfflineNetworkPolicy.isLocalPath(path) else { return "仅支持本地文件；禁止下载地址和网络路径。" }
        guard fileManager.fileExists(atPath: path), MainView.allowedFileTypes.contains(path.pathExtension.lowercased()) else { return "应用文件不存在或格式不支持。" }
        guard inspectedInputPath == path else { return "应用路径已更改，请刷新检查结果。" }
        if profileInputSource == .file,
           SigningFilePath.normalize(profilePathField?.stringValue ?? "") != (importedProvisioningProfile?.filename ?? unreadableProfilePath ?? "") {
            return "描述文件路径尚未读取，请完成选择或刷新。"
        }
        if certificateInputSource == .file,
           SigningFilePath.normalize(certificatePathField?.stringValue ?? "") != (certificateFilePath ?? "") {
            return "证书路径尚未导入，请完成选择或刷新。"
        }
        if SigningFilePath.normalize(entitlementFilePathLabel?.stringValue ?? "") != (entitlementFilePath ?? "") {
            return "权限文件路径尚未读取，请完成选择或刷新。"
        }
        if case .loading? = inspectedOriginalEntitlements?.status { return "正在重新读取应用和描述文件，检查完成后才能签名。" }
        if let message = signingInputValidationMessage { return message }
        if !isLeagsoftApp {
            for kind in AccessGroupKind.allCases {
                let source = groupSelection(for: kind).source
                if source != .custom, snapshot(for: source)?.isAvailable != true {
                    return "\(kind.title) 选择的来源“\(source.title)”不可读取，请刷新或重新选择最终来源。"
                }
            }
        }
        return nil
    }

    func updateSigningReadiness() {
        guard StartButton != nil else { return }
        let message = signingReadinessMessage
        StartButton.isEnabled = signingControlsEnabled && message == nil
        StartButton.toolTip = message ?? "证书与描述文件匹配，可以开始离线签名。"
        let mismatch = certificateProfileValidationMessage
        certificateMatchLabel?.stringValue = mismatch ?? "✓ 证书与描述文件匹配（已核对 DeveloperCertificates）。"
        certificateMatchLabel?.textColor = mismatch == nil ? .systemGreen : (mismatch!.contains("不匹配") ? .systemRed : .systemOrange)
        certificateMatchLabel?.toolTip = currentSigningIdentity.map { "证书 SHA-1: \($0.fingerprint)\n\(mismatch ?? "匹配")" }
    }

    var signingInputValidationMessage: String? {
        if let message = profileReadError { return message }
        if let message = leagsoftValidationMessage { return message }
        if currentSigningCertificate == nil {
            return certificateInputSource == .file
                ? "当前使用证书文件：请先导入包含私钥的有效签名证书。不会使用钥匙串列表中的其他证书。"
                : "当前从钥匙串选择：请选择可用的签名身份，或切换到“使用证书文件”。"
        }
        if profileInputSource == .file, selectedProvisioningProfile == nil {
            return "当前使用描述文件：请先选择有效的 .mobileprovision 文件。不会使用已安装或 App 内嵌的描述文件。"
        }
        if let profile = selectedProvisioningProfile,
           profile.expires <= Date() || !fileManager.fileExists(atPath: profile.filename) {
            return "当前描述文件已过期或文件已不存在，请重新选择。"
        }
        return certificateProfileValidationMessage
    }

    func validateSigningInputs() -> Bool {
        guard let message = signingReadinessMessage else { return true }
        showSigningFileError("请完善当前方式的签名材料", detail: message)
        return false
    }

    func applyProfileInputSelection() {
        let index = ProvisioningProfilesPopup.indexOfSelectedItem - 2
        let profile = profileInputSource == .file ? importedProvisioningProfile
            : (provisioningProfiles.indices.contains(index) ? provisioningProfiles[index] : nil)
        if let path = profile?.filename ?? (profileInputSource == .file ? unreadableProfilePath : nil) {
            rereadExternalProfile(at: path)
        } else { checkProfileID(nil, inspect: false) }
        scheduleEntitlementInspection()
        updateSigningInputSources()
    }

    private func rereadExternalProfile(at path: String) {
        if let profile = ProvisioningProfile(filename: path), profile.expires > Date() {
            if profileInputSource == .file { importedProvisioningProfile = profile }
            if let index = provisioningProfiles.firstIndex(where: { $0.filename == path }) {
                provisioningProfiles[index] = profile
                let item = ProvisioningProfilesPopup.item(at: index + 2)
                item?.title = "\(profile.name) (\(profile.teamID))"
                item?.toolTip = "\(profile.name)\nTeam ID: \(profile.teamID)\n\(profile.filename)"
            }
            checkProfileID(profile, inspect: false)
        } else {
            checkProfileID(nil, inspect: false)
            if profileInputSource == .file { importedProvisioningProfile = nil }
            profileReadError = "外部描述文件不可读取或已过期，已停用签名。请更换文件或再次刷新。"
            unreadableProfilePath = path
        }
    }

    func updateSigningInputSources() {
        let certificateFile = certificateInputSource == .file
        let profileFile = profileInputSource == .file
        certificateSourceControl?.selectedSegment = certificateInputSource.rawValue
        profileSourceControl?.selectedSegment = profileInputSource.rawValue
        certificateExistingRow?.isHidden = certificateFile
        certificateFileRow?.isHidden = !certificateFile
        profileExistingRow?.isHidden = profileFile
        profileFileRow?.isHidden = !profileFile
        certificateSourceControl?.isEnabled = signingControlsEnabled
        profileSourceControl?.isEnabled = signingControlsEnabled
        CodesigningCertsPopup.isEnabled = signingControlsEnabled && !certificateFile
        ProvisioningProfilesPopup.isEnabled = signingControlsEnabled && !profileFile
        certificatePathField?.isEnabled = signingControlsEnabled && certificateFile
        certificateBrowseButton?.isEnabled = signingControlsEnabled && certificateFile
        profilePathField?.isEnabled = signingControlsEnabled && profileFile
        profileBrowseButton?.isEnabled = signingControlsEnabled && profileFile
        certificateHintLabel?.textColor = currentSigningCertificate == nil ? .systemOrange : .secondaryLabelColor
        if certificateFile {
            certificateHintLabel?.stringValue = currentSigningCertificate.map { "当前生效 · 文件证书：\($0)" }
                ?? "仅使用此处导入的证书；请导入包含私钥的 P12 / PFX。"
        } else {
            certificateHintLabel?.stringValue = currentSigningCertificate.map { "当前生效 · 钥匙串身份：\($0)" }
                ?? "钥匙串中没有可用签名身份，可切换到“使用证书文件”。"
        }
        updateProfileDetails()
        updateSigningReadiness()
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
        guard signingControlsEnabled else { return }
        let path = SigningFilePath.normalize(value)
        guard OfflineNetworkPolicy.isLocalPath(path), path.pathExtension.lowercased() == "mobileprovision", fileManager.fileExists(atPath: path),
              let profile = ProvisioningProfile(filename: path) else {
            showSigningFileError("无法读取描述文件", detail: "请选择有效的 .mobileprovision 文件。\n\(path)")
            profilePathField?.stringValue = importedProvisioningProfile?.filename ?? ""
            return
        }
        guard profile.expires > Date() else {
            showSigningFileError("描述文件已过期", detail: "\(profile.name)\n请选择仍在有效期内的描述文件。")
            profilePathField?.stringValue = importedProvisioningProfile?.filename ?? ""
            return
        }
        importedProvisioningProfile = profile
        profileInputSource = .file
        applyProfileInputSelection()
    }

    func updateProfileDetails() {
        let profile = selectedProvisioningProfile
        let path = unreadableProfilePath ?? importedProvisioningProfile?.filename
        profilePathField?.stringValue = path ?? ""
        profilePathField?.toolTip = path
        if let message = profileReadError {
            profileDetailsLabel?.stringValue = message
            profileDetailsLabel?.textColor = .systemRed
            profileDetailsLabel?.toolTip = unreadableProfilePath
            return
        }
        guard let profile else {
            if isLeagsoftApp {
                profileDetailsLabel?.stringValue = "联软应用需选择外部描述文件；不会使用 App 内嵌描述文件。"
                profileDetailsLabel?.textColor = .systemOrange
                profileDetailsLabel?.toolTip = nil
                return
            }
            profileDetailsLabel?.stringValue = profileInputSource == .file
                ? "尚未选择文件；不会使用已安装或 App 内嵌的描述文件。"
                : "当前生效 · App 内嵌描述文件（未内嵌时不使用描述文件）。"
            profileDetailsLabel?.textColor = profileInputSource == .file ? .systemOrange : .secondaryLabelColor
            profileDetailsLabel?.toolTip = nil
            return
        }
        let date = DateFormatter()
        date.dateStyle = .medium
        let source = profileInputSource == .file ? "指定文件" : "已安装配置"
        let teamID = LeagsoftEntitlementPolicy.values(from: profile)?.teamID ?? profile.teamID
        profileDetailsLabel?.stringValue = "当前生效 · \(source)：\(profile.name)  ·  Team ID: \(teamID)  ·  有效期至 \(date.string(from: profile.expires))"
        profileDetailsLabel?.textColor = .secondaryLabelColor
        profileDetailsLabel?.toolTip = "Bundle ID: \(profile.appID)\n\(profile.filename)"
    }

    func loadCertificateFile(_ value: String) {
        guard signingControlsEnabled, !isImportingCertificate else { return }
        isImportingCertificate = true
        defer { isImportingCertificate = false }
        let path = SigningFilePath.normalize(value)
        guard OfflineNetworkPolicy.isLocalPath(path), MainView.certificateFileTypes.contains(path.pathExtension.lowercased()),
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
        finishCertificateImport(path: path, names: result.names, certificates: result.certificates, fileDigest: SigningCertificateFile.fileDigest(data))
    }

    func finishCertificateImport(path: String, names: [String], certificates: [Data] = [], fileDigest: String? = nil) {
        let previous = CodesigningCertsPopup.titleOfSelectedItem
        populateCodesigningCerts()
        if let previous { CodesigningCertsPopup.selectItem(withTitle: previous) }
        certificateFilePath = path
        certificateInputSource = .file
        let fingerprints = Set(certificates.map { SigningCertificateFile.fingerprint($0) })
        let matches = signingIdentities.filter { fingerprints.contains($0.fingerprint) }
        let imported = matches.count == 1 ? matches.first : nil
        importedCertificateName = imported?.displayName
        importedCertificateFingerprint = imported?.fingerprint
        importedCertificateFileDigest = fileDigest ?? (try? Data(contentsOf: URL(fileURLWithPath: path))).map { SigningCertificateFile.fileDigest($0) }
        certificatePathField?.stringValue = path
        certificatePathField?.toolTip = path
        updateSigningInputSources()
        if let match = importedCertificateName {
            setStatus("已导入签名证书：\(match)")
        } else {
            certificateHintLabel?.stringValue = "文件已导入，但未找到对应的有效签名身份。签名需要匹配的私钥；请导入包含私钥的 P12 / PFX。"
            setStatus("证书已导入，请检查是否包含有效签名身份")
        }
    }

    func setSigningInputControlsEnabled(_ enabled: Bool) {
        updateSigningInputSources()
        entitlementFilePathLabel?.isEnabled = enabled
        leagsoftAppCheckbox?.isEnabled = enabled
        refreshInspectionButton?.isEnabled = enabled
        appGroupsSourcePopup?.isEnabled = enabled && !isLeagsoftApp
        keychainGroupsSourcePopup?.isEnabled = enabled && !isLeagsoftApp
        finalAppGroupsField?.isEnabled = enabled
        finalKeychainGroupsField?.isEnabled = enabled
        finalAppGroupsField?.isEditable = !isLeagsoftApp
        finalKeychainGroupsField?.isEditable = !isLeagsoftApp
        chooseEntitlementsFileButton?.isEnabled = enabled
        clearEntitlementsFileButton?.isEnabled = enabled && entitlementFilePath != nil
        appShortVersion.isEnabled = enabled
        appVersion.isEnabled = enabled
        ignorePluginsCheckbox.isEnabled = enabled
        noGetTaskAllowCheckbox.isEnabled = enabled
    }

    /// File paths are not cache keys: re-read the actual bytes, including unchanged paths.
    @objc func refreshSigningInputs(_ sender: Any?) {
        guard signingControlsEnabled, !isImportingCertificate else { return }
        window?.makeFirstResponder(nil)
        pathEditWorkItem?.cancel()
        StartButton.isEnabled = false
        let profilePath = selectedProvisioningProfile?.filename ?? unreadableProfilePath
        populateCodesigningCerts()

        var changedCertificatePath: String?
        if certificateInputSource == .file, let path = certificateFilePath {
            let data = OfflineNetworkPolicy.isLocalPath(path) ? try? Data(contentsOf: URL(fileURLWithPath: path)) : nil
            if data.map({ SigningCertificateFile.fileDigest($0) }) != importedCertificateFileDigest || data == nil {
                // A replaced P12 must be imported again; cancellation must not keep the old identity alive.
                importedCertificateName = nil
                importedCertificateFingerprint = nil
                importedCertificateFileDigest = nil
                if data != nil { changedCertificatePath = path }
            }
        }

        if let path = profilePath {
            rereadExternalProfile(at: path)
        }
        scheduleEntitlementInspection()
        updateSigningInputSources()
        setStatus("已触发刷新，检查结果将按当前文件内容更新。")
        if let path = changedCertificatePath { loadCertificateFile(path) }
    }

    func acceptPathEdit(_ field: NSTextField, reportError: Bool) {
        guard signingControlsEnabled else { return }
        defer { updateSigningReadiness() }
        guard field !== profilePathField || profileInputSource == .file,
              field !== certificatePathField || certificateInputSource == .file else { return }
        let path = SigningFilePath.normalize(field.stringValue)
        guard !path.isEmpty else {
            if field === profilePathField { updateProfileDetails() }
            if field === certificatePathField { field.stringValue = certificateFilePath ?? "" }
            return
        }
        if !reportError, let pathField = field as? SigningPathField,
           !pathField.allowedExtensions.contains(path.pathExtension.lowercased()) { return }
        let exists = OfflineNetworkPolicy.isLocalPath(path) && fileManager.fileExists(atPath: path)
        if field === profilePathField {
            if path == importedProvisioningProfile?.filename { field.stringValue = path; return }
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
            selectEntitlementsFile(path)
        }
    }
}
