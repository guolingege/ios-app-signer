//
//  ViewController.swift
//  AppSigner
//
//  Created by Daniel Radtke on 11/2/15.
//  Copyright © 2015 Daniel Radtke. All rights reserved.
//

import Cocoa
import Foundation

enum EntitlementSnapshotStatus {
    case available
    case unavailable(String)
    case loading
}

struct EntitlementSnapshot {
    let sourceName: String
    let appGroups: [String]
    let keychainGroups: [String]
    let applicationIdentifier: String?
    let teamID: String?
    let status: EntitlementSnapshotStatus

    var isAvailable: Bool {
        if case .available = status { return true }
        return false
    }

    var statusText: String {
        switch status {
        case .available:
            return "可读取"
        case .unavailable(let reason):
            return reason
        case .loading:
            return "读取中…"
        }
    }
}

enum FinalEntitlementSource: Int, CaseIterable {
    case provisioningProfile
    case originalApp
    case entitlementsFile
    case custom

    var title: String {
        switch self {
        case .provisioningProfile:
            return "描述文件（推荐）"
        case .originalApp:
            return "原 App 签名"
        case .entitlementsFile:
            return "Entitlements 文件"
        case .custom:
            return "自定义"
        }
    }
}

class MainView: NSView, URLSessionDataDelegate, URLSessionDelegate, URLSessionDownloadDelegate, NSTextFieldDelegate {
    
    //MARK: IBOutlets
    @IBOutlet var ProvisioningProfilesPopup: NSPopUpButton!
    @IBOutlet var CodesigningCertsPopup: NSPopUpButton!
    @IBOutlet var StatusLabel: NSTextField!
    @IBOutlet var InputFileText: NSTextField!
    @IBOutlet var BrowseButton: NSButton!
    @IBOutlet var StartButton: NSButton!
    @IBOutlet var NewApplicationIDTextField: NSTextField!
    @IBOutlet var downloadProgress: NSProgressIndicator!
    @IBOutlet var appDisplayName: NSTextField!
    @IBOutlet var appShortVersion: NSTextField!
    @IBOutlet var appVersion: NSTextField!
    @IBOutlet var ignorePluginsCheckbox: NSButton!
    @IBOutlet var noGetTaskAllowCheckbox: NSButton!

    
    //MARK: Variables
    var provisioningProfiles:[ProvisioningProfile] = []
    var selectedProvisioningProfile: ProvisioningProfile?
    var inspectedOriginalEntitlements: EntitlementSnapshot?
    var inspectedEntitlementsFile: EntitlementSnapshot?
    var inspectedEmbeddedProfile: ProvisioningProfile?
    var entitlementFilePath: String?
    var finalEntitlementSource: FinalEntitlementSource = .provisioningProfile
    var finalEntitlementsUserEdited = false
    var entitlementInspectorConfigured = false
    var entitlementInspectionGeneration = 0

    var profilePathField: SigningPathField?
    var certificatePathField: SigningPathField?
    var certificateFilePath: String?
    var profileBrowseButton: NSButton?
    var certificateBrowseButton: NSButton?
    var profileDetailsLabel: NSTextField?
    var certificateHintLabel: NSTextField?
    var pathEditWorkItem: DispatchWorkItem?
    var signingControlsEnabled = true
    var isImportingCertificate = false

    var entitlementPanel: NSBox?
    var entitlementContentStack: NSStackView?
    var entitlementWarningLabel: NSTextField?
    var entitlementFilePathLabel: NSTextField?
    var entitlementSourcePopup: NSPopUpButton?
    var finalAppGroupsField: NSTextField?
    var finalKeychainGroupsField: NSTextField?
    var chooseEntitlementsFileButton: NSButton?
    var clearEntitlementsFileButton: NSButton?

    @objc var codesigningCerts: [String] = []
    @objc var profileFilename: String?
    @objc var ReEnableNewApplicationID = false
    @objc var PreviousNewApplicationID = ""
    @objc var outputFile: String?
    var startSize: CGFloat?
    @objc var NibLoaded = false
    var shouldCheckPlugins: Bool!
    var shouldSkipGetTaskAllow: Bool!

    //MARK: Constants
    let signableExtensions = ["dylib","so","0","vis","pvr","framework","appex","app"]
    @objc let defaults = UserDefaults()
    @objc let fileManager = FileManager.default
    @objc let bundleID = Bundle.main.bundleIdentifier
    @objc let arPath = "/usr/bin/ar"
    @objc let mktempPath = "/usr/bin/mktemp"
    @objc let tarPath = "/usr/bin/tar"
    @objc let unzipPath = "/usr/bin/unzip"
    @objc let zipPath = "/usr/bin/zip"
    @objc let defaultsPath = "/usr/bin/defaults"
    @objc let codesignPath = "/usr/bin/codesign"
    @objc let securityPath = "/usr/bin/security"
    @objc let chmodPath = "/bin/chmod"
//    let plistbuddyPath = "/usr/libexec/plistbuddy"
    
    //MARK: Drag / Drop
    static let urlFileTypes = ["ipa", "deb"]
    static let allowedFileTypes = urlFileTypes + ["app", "appex", "xcarchive"]
    static let entitlementsFileTypes = ["entitlements", "plist"]
    static let certificateFileTypes = ["p12", "pfx", "cer", "crt", "pem"]
    static let fileTypes = allowedFileTypes + ["mobileprovision"] + entitlementsFileTypes + certificateFileTypes
    @objc var fileTypeIsOk = false
    
    @objc func fileDropped(_ filename: String){
        guard signingControlsEnabled else { return }
        let filename = SigningFilePath.normalize(filename)
        switch filename.pathExtension.lowercased() {
        case let ext where MainView.allowedFileTypes.contains(ext):
            InputFileText.stringValue = filename
            scheduleEntitlementInspection()
        case "mobileprovision":
            loadProfileFile(filename)
        case let ext where MainView.certificateFileTypes.contains(ext):
            loadCertificateFile(filename)
        case let ext where MainView.entitlementsFileTypes.contains(ext):
            entitlementFilePath = filename
            finalEntitlementSource = .entitlementsFile
            finalEntitlementsUserEdited = true
            scheduleEntitlementInspection()
        default:
            break
        }
    }
    
    @objc func urlDropped(_ url: NSURL){
        if let urlString = url.absoluteString {
            InputFileText.stringValue = urlString
            scheduleEntitlementInspection()
        }
    }
    
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        if checkExtension(sender) == true {
            self.fileTypeIsOk = true
            return .copy
        } else {
            self.fileTypeIsOk = false
            return NSDragOperation()
        }
    }
    
    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation {
        if self.fileTypeIsOk {
            return .copy
        } else {
            return NSDragOperation()
        }
    }
    
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard signingControlsEnabled else { return false }
        let paths = SigningFilePath.paths(from: sender.draggingPasteboard)
        var handled = false
        for path in paths {
            if MainView.fileTypes.contains(path.pathExtension.lowercased()), fileManager.fileExists(atPath: path) {
                fileDropped(path)
                handled = true
            } else if let url = URL(string: path), ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
                      MainView.urlFileTypes.contains(url.pathExtension.lowercased()) {
                urlDropped(url as NSURL)
                handled = true
            }
        }
        return handled
    }

    @objc func checkExtension(_ drag: NSDraggingInfo) -> Bool {
        guard signingControlsEnabled else { return false }
        return SigningFilePath.paths(from: drag.draggingPasteboard).contains { path in
            if fileManager.fileExists(atPath: path) { return MainView.fileTypes.contains(path.pathExtension.lowercased()) }
            guard let url = URL(string: path), ["http", "https"].contains(url.scheme?.lowercased() ?? "") else { return false }
            return MainView.urlFileTypes.contains(url.pathExtension.lowercased())
        }
    }

    //MARK: Functions
    
    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        registerForDraggedTypes([.fileURL, .URL, .string, .init("NSFilenamesPboardType"), .init("NSURLPboardType")])
    }
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        registerForDraggedTypes([.fileURL, .URL, .string, .init("NSFilenamesPboardType"), .init("NSURLPboardType")])
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
        super.draw(dirtyRect)
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window != nil {
            configureEntitlementInspector()
        }
    }

    override func awakeFromNib() {
        super.awakeFromNib()
        
        if NibLoaded == false {
            NibLoaded = true

            InputFileText.delegate = self
            configureEntitlementInspector()
            DispatchQueue.main.async { [weak self] in
                self?.configureEntitlementInspector()
            }

            // Do any additional setup after loading the view.
            populateProvisioningProfiles()
            populateCodesigningCerts()
            if let defaultCert = defaults.string(forKey: "signingCertificate") {
                if codesigningCerts.contains(defaultCert) {
                    Log.write("Loaded Codesigning Certificate from Defaults: \(defaultCert)")
                    CodesigningCertsPopup.selectItem(withTitle: defaultCert)
                }
            }
            setStatus("就绪")
            if checkXcodeCLI() == false {
                if #available(OSX 10.10, *) {
                    let _ = installXcodeCLI()
                } else {
                    let alert = NSAlert()
                    alert.messageText = "Please install the Xcode command line tools and re-launch this application."
                    alert.runModal()
                }
                
                NSApplication.shared.terminate(self)
            }
            UpdatesController.checkForUpdate()
        }
    }
    
    func installXcodeCLI() -> AppSignerTaskOutput {
        return Process().execute("/usr/bin/xcode-select", workingDirectory: nil, arguments: ["--install"])
    }
    
    @objc func checkXcodeCLI() -> Bool {
        if #available(OSX 10.10, *) {
            if Process().execute("/usr/bin/xcode-select", workingDirectory: nil, arguments: ["-p"]).status   != 0 {
                return false
            }
        } else {
            if Process().execute("/usr/sbin/pkgutil", workingDirectory: nil, arguments: ["--pkg-info=com.apple.pkg.DeveloperToolsCLI"]).status != 0 {
                // Command line tools not available
                return false
            }
        }
        
        return true
    }
    
    @objc func makeTempFolder()->String?{
        let tempTask = Process().execute(mktempPath, workingDirectory: nil, arguments: ["-d","-t",bundleID!])
        if tempTask.status != 0 {
            return nil
        }
        return tempTask.output.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }
    
    @objc func setStatus(_ status: String){
        if (!Thread.isMainThread){
            DispatchQueue.main.sync{
                setStatus(status)
            }
        }
        else{
            StatusLabel.stringValue = status
            Log.write(status)
        }
    }
    
    //MARK: - Entitlement inspection UI

    func configureEntitlementInspector() {
        guard !entitlementInspectorConfigured else { return }
        guard NibLoaded, window != nil, StartButton != nil else { return }
        entitlementInspectorConfigured = true
        configureSigningLayout()
        rebuildEntitlementInspectorContent()
    }

    func rebuildEntitlementInspectorContent() {
        guard let contentView = entitlementPanel?.contentView else { return }
        let previousAppGroups = finalAppGroupsField?.stringValue
        let previousKeychainGroups = finalKeychainGroupsField?.stringValue
        contentView.subviews.forEach { $0.removeFromSuperview() }

        let stack = verticalStack(spacing: 8)
        contentView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            stack.topAnchor.constraint(equalTo: contentView.topAnchor),
            stack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor)
        ])
        entitlementContentStack = stack
        stack.addArrangedSubview(sectionHeading("权限对比", subtitle: "红色表示与描述文件不同；组值可选中复制，较多时可在单元格内滚动查看。"))
        stack.addArrangedSubview(makeEntitlementsFilePickerRow())

        let profile = selectedProfileSnapshot()
        let referenceTeam = profile?.teamID ?? inspectedOriginalEntitlements?.teamID ?? inspectedEntitlementsFile?.teamID
        let table = verticalStack(spacing: 0)
        table.addArrangedSubview(makeEntitlementTableRow(
            values: ["权限来源", "App Groups", "Keychain Access Groups", "对比状态"],
            colors: Array(repeating: .secondaryLabelColor, count: 4), bold: true, unavailable: false))
        for (title, snapshot) in [
            ("原 App 签名", inspectedOriginalEntitlements),
            ("权限文件", inspectedEntitlementsFile),
            (selectedProvisioningProfile == nil && inspectedEmbeddedProfile != nil ? "内嵌描述文件" : "所选描述文件", profile)
        ] {
            let separator = NSBox()
            separator.boxType = .separator
            table.addArrangedSubview(separator)
            table.addArrangedSubview(makeSnapshotRow(title: title, snapshot: snapshot, reference: profile, teamID: referenceTeam))
        }
        stack.addArrangedSubview(table)
        for row in table.arrangedSubviews { constrainInspectorRow(row, to: table) }

        let warning = uiLabel("", size: 11, weight: .medium)
        warning.maximumNumberOfLines = 0
        entitlementWarningLabel = warning
        stack.addArrangedSubview(warning)
        let separator = NSBox()
        separator.boxType = .separator
        stack.addArrangedSubview(separator)
        stack.addArrangedSubview(sectionHeading("最终签名值", subtitle: "选择来源后可直接编辑。多个组用英文逗号分隔，留空表示不设置该项。"))

        // Do not change the user's source while its inspection is in flight.
        if finalEntitlementSource == .custom && !finalEntitlementsUserEdited {
            finalEntitlementSource = defaultFinalEntitlementSource()
        }
        let selectedSnapshot: EntitlementSnapshot?
        switch finalEntitlementSource {
        case .originalApp: selectedSnapshot = inspectedOriginalEntitlements
        case .entitlementsFile: selectedSnapshot = inspectedEntitlementsFile
        case .provisioningProfile: selectedSnapshot = profile
        case .custom: selectedSnapshot = nil
        }
        let isLoading: Bool
        if case .loading? = selectedSnapshot?.status { isLoading = true } else { isLoading = false }
        if !isLoading, finalEntitlementSource != .custom, valuesForFinalSource(finalEntitlementSource) == nil {
            finalEntitlementSource = defaultFinalEntitlementSource()
        }
        let popup = NSPopUpButton(frame: .zero, pullsDown: false)
        popup.autoenablesItems = false
        popup.target = self
        popup.action = #selector(entitlementSourceChanged(_:))
        for source in FinalEntitlementSource.allCases {
            popup.addItem(withTitle: source.title)
            popup.lastItem?.tag = source.rawValue
            popup.lastItem?.isEnabled = source == .custom || valuesForFinalSource(source) != nil
        }
        popup.selectItem(withTag: finalEntitlementSource.rawValue)
        entitlementSourcePopup = popup
        stack.addArrangedSubview(labeledRow("使用来源", views: [popup]))
        let values = finalEntitlementSource == .custom || isLoading
            ? (appGroups: splitGroupList(previousAppGroups ?? ""), keychainGroups: splitGroupList(previousKeychainGroups ?? ""))
            : valuesForFinalSource(finalEntitlementSource) ?? ([], [])
        finalAppGroupsField = makeFinalGroupsField(title: "App Groups", text: values.appGroups.joined(separator: ", "), placeholder: "例如 group.com.example.app")
        finalKeychainGroupsField = makeFinalGroupsField(title: "Keychain Groups", text: values.keychainGroups.joined(separator: ", "), placeholder: "例如 TEAMID.com.example.shared")
        for row in stack.arrangedSubviews { constrainInspectorRow(row, to: stack) }
        updateEntitlementWarning()
        setSigningInputControlsEnabled(signingControlsEnabled)
    }

    func makeSnapshotRow(title: String, snapshot: EntitlementSnapshot?, reference: EntitlementSnapshot?, teamID: String?) -> NSStackView {
        guard let snapshot else {
            return makeEntitlementTableRow(values: [title, "—", "—", "未选择"], colors: [.labelColor, .tertiaryLabelColor, .tertiaryLabelColor, .secondaryLabelColor], bold: false, unavailable: true)
        }
        var appColor = NSColor.labelColor
        var keychainColor = NSColor.labelColor
        var result = snapshot.statusText
        var color = NSColor.secondaryLabelColor
        let appGroups = expandedGroups(snapshot.appGroups, teamID: snapshot.teamID ?? teamID)
        let keychainGroups = expandedGroups(snapshot.keychainGroups, teamID: snapshot.teamID ?? teamID)
        if snapshot.isAvailable {
            if title == "所选描述文件" || title == "内嵌描述文件" {
                result = "比较基准"
                color = .controlAccentColor
            } else if let reference, reference.isAvailable {
                let appMatches = setsEqual(appGroups, expandedGroups(reference.appGroups, teamID: reference.teamID))
                let keychainMatches = setsEqual(keychainGroups, expandedGroups(reference.keychainGroups, teamID: reference.teamID))
                appColor = appMatches ? .labelColor : .systemRed
                keychainColor = keychainMatches ? .labelColor : .systemRed
                result = appMatches && keychainMatches ? "✓ 一致" : "⚠ 存在差异"
                color = appMatches && keychainMatches ? .systemGreen : .systemRed
            } else {
                result = "等待比较基准"
            }
        }
        let row = makeEntitlementTableRow(
            values: [title, snapshot.isAvailable ? formattedGroups(appGroups) : "—", snapshot.isAvailable ? formattedGroups(keychainGroups) : "—", result],
            colors: [.labelColor, appColor, keychainColor, color], bold: false, unavailable: !snapshot.isAvailable)
        row.toolTip = "\(snapshot.sourceName)\nTeam ID: \(snapshot.teamID ?? "未知")\nApplication ID: \(snapshot.applicationIdentifier ?? "未知")\n\(snapshot.statusText)"
        return row
    }

    func makeEntitlementTableRow(values: [String], colors: [NSColor], bold: Bool, unavailable: Bool) -> NSStackView {
        let row = horizontalStack(spacing: 14)
        row.alignment = .top
        row.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10)
        if bold { row.wantsLayer = true; row.layer?.backgroundColor = NSColor.quaternaryLabelColor.withAlphaComponent(0.18).cgColor }
        let proportions: [CGFloat] = [0.17, 0.31, 0.35, 0.17]
        for (index, value) in values.enumerated() {
            let cell: NSView
            if !bold && (index == 1 || index == 2) && value != "—" && value != "未设置" {
                cell = makeScrollableGroupCell(value, color: colors[index], proportion: proportions[index])
            } else {
                let label = uiLabel(value, size: bold ? 11 : 12, weight: bold || index == 3 ? .medium : .regular)
                label.textColor = colors[index]
                label.isSelectable = true
                label.maximumNumberOfLines = 0
                label.lineBreakMode = .byCharWrapping
                cell = label
            }
            cell.translatesAutoresizingMaskIntoConstraints = false
            cell.toolTip = value
            row.addArrangedSubview(cell)
            cell.widthAnchor.constraint(equalTo: row.widthAnchor, multiplier: proportions[index], constant: -62 * proportions[index]).isActive = true
        }
        return row
    }

    func makeScrollableGroupCell(_ value: String, color: NSColor, proportion: CGFloat) -> NSScrollView {
        let width = max(150, (bounds.width - 146) * proportion)
        let textView = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 16))
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = false
        textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.textColor = color
        textView.textContainerInset = .zero
        textView.textContainer?.lineFragmentPadding = 0
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.textContainer?.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
        textView.string = value
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.documentView = textView
        let estimatedLines = value.components(separatedBy: "\n").reduce(0) { $0 + max(1, Int(ceil(CGFloat($1.count) * 6.6 / width))) }
        scroll.heightAnchor.constraint(equalToConstant: min(72, max(16, CGFloat(estimatedLines) * 14 + 2))).isActive = true
        scroll.setAccessibilityLabel("\(value.components(separatedBy: "\n").count) 个组，可滚动查看并复制")
        return scroll
    }

    func constrainInspectorRow(_ row: NSView, to stack: NSStackView) {
        row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
    }

    func makeEntitlementsFilePickerRow() -> NSStackView {
        let path = pathField("可选：拖入 .entitlements / .plist，或粘贴路径", extensions: MainView.entitlementsFileTypes)
        path.stringValue = entitlementFilePath ?? ""
        path.toolTip = entitlementFilePath
        path.onFileDrop = { [weak self] in self?.fileDropped($0) }
        entitlementFilePathLabel = path
        let choose = NSButton(title: "选择文件…", target: self, action: #selector(chooseEntitlementsFile(_:)))
        let clear = NSButton(title: "清除", target: self, action: #selector(clearEntitlementsFile(_:)))
        chooseEntitlementsFileButton = choose
        clearEntitlementsFileButton = clear
        clear.isEnabled = entitlementFilePath != nil
        return labeledRow("权限文件", views: [path, choose, clear])
    }

    func makeFinalGroupsField(title: String, text: String, placeholder: String) -> NSTextField {
        let field = NSTextField(string: text)
        field.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        field.placeholderString = placeholder
        field.delegate = self
        let label = uiLabel(title, size: 11, secondary: true)
        label.widthAnchor.constraint(equalToConstant: 116).isActive = true
        let row = horizontalStack(views: [label, field], spacing: 10)
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        // Retain the row until it is added to the inspector stack.
        entitlementContentStack?.addArrangedSubview(row)
        return field
    }

    @objc func chooseEntitlementsFile(_ sender: Any?) {
        let openDialog = NSOpenPanel()
        openDialog.canChooseFiles = true
        openDialog.canChooseDirectories = false
        openDialog.allowsMultipleSelection = false
        openDialog.allowsOtherFileTypes = false
        openDialog.allowedFileTypes = MainView.entitlementsFileTypes
        openDialog.runModal()
        if let filename = openDialog.urls.first {
            entitlementFilePath = filename.path
            finalEntitlementSource = .entitlementsFile
            finalEntitlementsUserEdited = true
            scheduleEntitlementInspection()
        }
    }

    @objc func clearEntitlementsFile(_ sender: Any?) {
        entitlementFilePath = nil
        inspectedEntitlementsFile = nil
        if finalEntitlementSource == .entitlementsFile {
            finalEntitlementSource = defaultFinalEntitlementSource()
        }
        scheduleEntitlementInspection()
    }

    @objc func entitlementSourceChanged(_ sender: NSPopUpButton) {
        guard let source = FinalEntitlementSource(rawValue: sender.selectedTag()) else {
            return
        }
        finalEntitlementSource = source
        finalEntitlementsUserEdited = true
        rebuildEntitlementInspectorContent()
    }

    func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        if field === finalAppGroupsField || field === finalKeychainGroupsField {
            finalEntitlementSource = .custom
            finalEntitlementsUserEdited = true
            entitlementSourcePopup?.selectItem(withTag: FinalEntitlementSource.custom.rawValue)
            updateEntitlementWarning()
        } else if field === profilePathField || field === certificatePathField || field === entitlementFilePathLabel {
            pathEditWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self, weak field] in
                guard let self, let field, self.signingControlsEnabled else { return }
                self.acceptPathEdit(field, reportError: false)
            }
            pathEditWorkItem = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: work)
        }
    }

    func controlTextDidEndEditing(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        if field === InputFileText {
            let path = SigningFilePath.normalize(field.stringValue)
            field.stringValue = path
            scheduleEntitlementInspection()
        } else if field === profilePathField || field === certificatePathField || field === entitlementFilePathLabel {
            pathEditWorkItem?.cancel()
            acceptPathEdit(field, reportError: true)
        }
    }

    func selectedProfileSnapshot() -> EntitlementSnapshot? {
        if let profile = selectedProvisioningProfile {
            return snapshot(from: profile, sourceName: "所选描述文件")
        }
        if let profile = inspectedEmbeddedProfile {
            return snapshot(from: profile, sourceName: "App 内嵌描述文件")
        }
        return nil
    }

    func snapshot(from profile: ProvisioningProfile, sourceName: String) -> EntitlementSnapshot {
        EntitlementSnapshot(
            sourceName: sourceName,
            appGroups: groups(named: "com.apple.security.application-groups", in: profile.entitlements),
            keychainGroups: groups(named: "keychain-access-groups", in: profile.entitlements),
            applicationIdentifier: profile.entitlements["application-identifier"] as? String,
            teamID: profile.teamID,
            status: .available
        )
    }

    func groups(named key: String, in entitlements: [String: AnyObject]) -> [String] {
        if let groups = entitlements[key] as? [String] {
            return groups
        }
        if let groups = entitlements[key] as? NSArray {
            return groups.compactMap { $0 as? String }
        }
        return []
    }

    func expandedGroups(_ groups: [String], teamID: String?) -> [String] {
        groups.map { expandEntitlementVariables($0, teamID: teamID) }
    }

    func expandEntitlementVariables(_ value: String, teamID: String?) -> String {
        var expanded = value
        if let teamID {
            expanded = expanded.replacingOccurrences(of: "$(AppIdentifierPrefix)", with: "\(teamID).")
            expanded = expanded.replacingOccurrences(of: "$(TeamIdentifierPrefix)", with: "\(teamID).")
        }
        if let appBundleID = inspectedBundleIdentifier() {
            expanded = expanded.replacingOccurrences(of: "$(CFBundleIdentifier)", with: appBundleID)
        }
        return expanded
    }

    func inspectedBundleIdentifier() -> String? {
        let identifiers = [
            selectedProfileSnapshot()?.applicationIdentifier,
            inspectedOriginalEntitlements?.applicationIdentifier,
            inspectedEntitlementsFile?.applicationIdentifier
        ].compactMap { $0 }

        for identifier in identifiers {
            if let period = identifier.firstIndex(of: ".") {
                return String(identifier[identifier.index(after: period)...])
            }
        }
        return nil
    }

    func splitGroupList(_ value: String) -> [String] {
        value.components(separatedBy: CharacterSet(charactersIn: ",\n;"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    func currentFinalAppGroups() -> [String] {
        splitGroupList(finalAppGroupsField?.stringValue ?? "")
    }

    func currentFinalKeychainGroups() -> [String] {
        splitGroupList(finalKeychainGroupsField?.stringValue ?? "")
    }

    func valuesForFinalSource(_ source: FinalEntitlementSource) -> (appGroups: [String], keychainGroups: [String])? {
        let teamID = selectedProfileSnapshot()?.teamID ?? inspectedOriginalEntitlements?.teamID ?? inspectedEntitlementsFile?.teamID
        let snapshot: EntitlementSnapshot?
        switch source {
        case .provisioningProfile:
            snapshot = selectedProfileSnapshot()
        case .originalApp:
            snapshot = inspectedOriginalEntitlements
        case .entitlementsFile:
            snapshot = inspectedEntitlementsFile
        case .custom:
            return (currentFinalAppGroups(), currentFinalKeychainGroups())
        }

        guard let snapshot, snapshot.isAvailable else { return nil }
        return (
            expandedGroups(snapshot.appGroups, teamID: teamID),
            expandedGroups(snapshot.keychainGroups, teamID: teamID)
        )
    }

    func defaultFinalEntitlementSource() -> FinalEntitlementSource {
        if selectedProfileSnapshot()?.isAvailable == true {
            return .provisioningProfile
        }
        if inspectedOriginalEntitlements?.isAvailable == true {
            return .originalApp
        }
        if inspectedEntitlementsFile?.isAvailable == true {
            return .entitlementsFile
        }
        return .custom
    }

    func updateEntitlementWarning() {
        guard let label = entitlementWarningLabel else { return }
        let profile = selectedProfileSnapshot()
        let snapshots = [inspectedOriginalEntitlements, inspectedEntitlementsFile].compactMap { $0 }
        if snapshots.contains(where: { if case .loading = $0.status { return true }; return false }) {
            label.stringValue = "正在读取权限信息，请稍候…"
            label.textColor = .secondaryLabelColor
            return
        }
        var warnings: [String] = []
        if let profile {
            let allowedApp = expandedGroups(profile.appGroups, teamID: profile.teamID)
            let allowedKeychain = expandedGroups(profile.keychainGroups, teamID: profile.teamID)
            for snapshot in snapshots where snapshot.isAvailable {
                let name = snapshot.sourceName.contains("Mach-O") ? "原 App" : "权限文件"
                var differing: [String] = []
                if !setsEqual(expandedGroups(snapshot.appGroups, teamID: snapshot.teamID ?? profile.teamID), allowedApp) { differing.append("App Groups") }
                if !setsEqual(expandedGroups(snapshot.keychainGroups, teamID: snapshot.teamID ?? profile.teamID), allowedKeychain) { differing.append("钥匙串访问组") }
                if !differing.isEmpty { warnings.append("\(name)与描述文件的\(differing.joined(separator: "、"))不同") }
            }
            let finalApp = expandedGroups(currentFinalAppGroups(), teamID: profile.teamID)
            let finalKeychain = expandedGroups(currentFinalKeychainGroups(), teamID: profile.teamID)
            if !finalApp.allSatisfy({ group in allowedApp.contains(where: { entitlementGroup(group, isAllowedBy: $0) }) }) {
                warnings.append("最终 App Groups 包含描述文件未授权的值")
            }
            if !finalKeychain.allSatisfy({ group in allowedKeychain.contains(where: { entitlementGroup(group, isAllowedBy: $0) }) }) {
                warnings.append("最终钥匙串访问组包含描述文件未授权的值")
            }
        }
        if !warnings.isEmpty {
            label.stringValue = "⚠ " + warnings.joined(separator: "；") + "。请核对下方最终签名值。"
            label.textColor = .systemRed
        } else if profile == nil {
            label.stringValue = "尚无描述文件作为比较基准，暂时无法验证最终权限是否获授权。"
            label.textColor = .systemOrange
        } else if let original = inspectedOriginalEntitlements, !original.isAvailable {
            label.stringValue = "原 App 的签名权限不可读取；可使用描述文件或权限文件设置最终值。"
            label.textColor = .systemOrange
        } else if snapshots.contains(where: { !$0.isAvailable }) {
            label.stringValue = "部分来源读取失败，请检查文件；已读取来源未发现权限差异。"
            label.textColor = .systemOrange
        } else if snapshots.contains(where: { $0.isAvailable }) {
            label.stringValue = "✓ 已读取来源与描述文件一致，最终组值在描述文件授权范围内。"
            label.textColor = .systemGreen
        } else {
            label.stringValue = "已读取描述文件。选择应用后，将自动对比原签名权限。"
            label.textColor = .secondaryLabelColor
        }
        label.toolTip = label.stringValue
    }

    func entitlementGroup(_ group: String, isAllowedBy pattern: String) -> Bool {
        if group == pattern { return true }
        guard pattern.hasSuffix("*") else { return false }
        return group.hasPrefix(String(pattern.dropLast()))
    }

    func formattedGroups(_ groups: [String]) -> String {
        if groups.isEmpty { return "未设置" }
        return groups.joined(separator: "\n")
    }

    func setsEqual(_ lhs: [String], _ rhs: [String]) -> Bool {
        Set(lhs) == Set(rhs)
    }

    func scheduleEntitlementInspection() {
        guard entitlementInspectorConfigured else { return }

        entitlementInspectionGeneration += 1
        let generation = entitlementInspectionGeneration
        let inputFile = InputFileText.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let entitlementsFile = entitlementFilePath
        let selectedProfile = selectedProvisioningProfile

        inspectedOriginalEntitlements = EntitlementSnapshot(
            sourceName: "原 App Mach-O 签名",
            appGroups: [],
            keychainGroups: [],
            applicationIdentifier: nil,
            teamID: nil,
            status: .loading
        )
        if entitlementsFile != nil {
            inspectedEntitlementsFile = EntitlementSnapshot(
                sourceName: "Entitlements 文件",
                appGroups: [],
                keychainGroups: [],
                applicationIdentifier: nil,
                teamID: nil,
                status: .loading
            )
        }
        rebuildEntitlementInspectorContent()

        guard !inputFile.isEmpty, !inputFile.lowercased().hasPrefix("http") else {
            inspectedOriginalEntitlements = nil
            inspectedEmbeddedProfile = nil
            if let entitlementsFile {
                inspectedEntitlementsFile = inspectEntitlementsFile(path: entitlementsFile, teamID: selectedProfile?.teamID)
            }
            rebuildEntitlementInspectorContent()
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.inspectOriginalInput(path: inputFile, profileTeamID: selectedProfile?.teamID)
            let fileResult = entitlementsFile.map {
                self.inspectEntitlementsFile(path: $0, teamID: selectedProfile?.teamID ?? result.original?.teamID)
            }

            DispatchQueue.main.async {
                guard generation == self.entitlementInspectionGeneration else { return }
                self.inspectedOriginalEntitlements = result.original
                self.inspectedEmbeddedProfile = result.embeddedProfile
                self.inspectedEntitlementsFile = fileResult
                if self.finalEntitlementSource != .custom, self.valuesForFinalSource(self.finalEntitlementSource) == nil {
                    self.finalEntitlementSource = self.defaultFinalEntitlementSource()
                } else if !self.finalEntitlementsUserEdited, self.finalEntitlementSource == .custom {
                    self.finalEntitlementSource = self.defaultFinalEntitlementSource()
                }
                self.rebuildEntitlementInspectorContent()
            }
        }
    }

    func inspectOriginalInput(path: String, profileTeamID: String?) -> (original: EntitlementSnapshot?, embeddedProfile: ProvisioningProfile?) {
        var temporaryRoot: String?
        defer {
            if let temporaryRoot {
                try? fileManager.removeItem(atPath: temporaryRoot)
            }
        }

        guard let appBundlePath = locateAppBundle(inputPath: path, temporaryRoot: &temporaryRoot) else {
            return (
                EntitlementSnapshot(
                    sourceName: "原 App Mach-O 签名",
                    appGroups: [],
                    keychainGroups: [],
                    applicationIdentifier: nil,
                    teamID: profileTeamID,
                    status: .unavailable("无法定位 App Bundle")
                ),
                nil
            )
        }

        let embeddedProfilePath = appBundlePath.stringByAppendingPathComponent("embedded.mobileprovision")
        let embeddedProfile = fileManager.fileExists(atPath: embeddedProfilePath) ? ProvisioningProfile(filename: embeddedProfilePath) : nil

        let codesignTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-d", "--entitlements", ":-", appBundlePath])
        let entitlements = plistDictionary(fromCodesignOutput: codesignTask.output)
        let displayTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-dvvv", appBundlePath])
        let teamID = teamIdentifier(from: displayTask.output) ?? (entitlements?["application-identifier"] as? String).flatMap { identifier in
            identifier.split(separator: ".", maxSplits: 1).first.map(String.init)
        } ?? profileTeamID

        guard let entitlements else {
            return (
                EntitlementSnapshot(
                    sourceName: "原 App Mach-O 签名",
                    appGroups: [],
                    keychainGroups: [],
                    applicationIdentifier: nil,
                    teamID: teamID,
                    status: .unavailable(codesignTask.status == 0 ? "无 entitlement 数据" : "未签名/签名不可读")
                ),
                embeddedProfile
            )
        }

        return (
            EntitlementSnapshot(
                sourceName: "原 App Mach-O 签名",
                appGroups: groups(named: "com.apple.security.application-groups", in: entitlements),
                keychainGroups: groups(named: "keychain-access-groups", in: entitlements),
                applicationIdentifier: entitlements["application-identifier"] as? String,
                teamID: teamID,
                status: .available
            ),
            embeddedProfile
        )
    }

    func locateAppBundle(inputPath: String, temporaryRoot: inout String?) -> String? {
        let inputURL = URL(fileURLWithPath: inputPath)
        switch inputURL.pathExtension.lowercased() {
        case "app", "appex":
            return inputPath

        case "xcarchive":
            let applications = inputPath.stringByAppendingPathComponent("Products/Applications")
            return firstAppBundle(in: applications)

        case "ipa":
            guard let temp = makeTempFolder() else { return nil }
            temporaryRoot = temp
            let unzipTask = unzip(inputPath, outputPath: temp)
            guard unzipTask.status == 0 else { return nil }
            return firstAppBundle(in: temp.stringByAppendingPathComponent("Payload"))

        default:
            return nil
        }
    }

    func firstAppBundle(in directory: String) -> String? {
        guard let files = try? fileManager.contentsOfDirectory(atPath: directory) else { return nil }
        for file in files where file.pathExtension.lowercased() == "app" {
            let candidate = directory.stringByAppendingPathComponent(file)
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: candidate, isDirectory: &isDirectory), isDirectory.boolValue {
                let infoPlist = candidate.stringByAppendingPathComponent("Info.plist")
                if NSDictionary(contentsOfFile: infoPlist) != nil {
                    return candidate
                }
            }
        }
        return nil
    }

    func inspectEntitlementsFile(path: String, teamID: String?) -> EntitlementSnapshot {
        guard let data = fileManager.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let entitlements = plist as? [String: AnyObject] else {
            return EntitlementSnapshot(
                sourceName: "Entitlements 文件",
                appGroups: [],
                keychainGroups: [],
                applicationIdentifier: nil,
                teamID: teamID,
                status: .unavailable("无法解析 Plist")
            )
        }

        let applicationIdentifier = entitlements["application-identifier"] as? String
        let inferredTeamID = teamID ?? applicationIdentifier.flatMap { identifier in
            identifier.split(separator: ".", maxSplits: 1).first.map(String.init)
        }

        return EntitlementSnapshot(
            sourceName: "Entitlements 文件",
            appGroups: groups(named: "com.apple.security.application-groups", in: entitlements),
            keychainGroups: groups(named: "keychain-access-groups", in: entitlements),
            applicationIdentifier: applicationIdentifier,
            teamID: inferredTeamID,
            status: .available
        )
    }

    func teamIdentifier(from codesignOutput: String) -> String? {
        let pattern = #"(?m)^TeamIdentifier=([A-Z0-9]+)$"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: codesignOutput, range: NSRange(codesignOutput.startIndex..., in: codesignOutput)),
              let range = Range(match.range(at: 1), in: codesignOutput) else {
            return nil
        }
        return String(codesignOutput[range])
    }


    func entitlementsDictionary(fromFile path: String) -> [String: AnyObject]? {
        guard let data = fileManager.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            return nil
        }
        return plist as? [String: AnyObject]
    }

    func entitlementsForSigning(
        profile: ProvisioningProfile?,
        appBundlePath: String,
        bundleID: String?,
        entitlementsFilePath: String?,
        finalSource: FinalEntitlementSource,
        appGroups: [String],
        keychainGroups: [String],
        newApplicationID: String
    ) -> [String: AnyObject]? {
        let originalEntitlements = signedEntitlements(forBundle: appBundlePath)
        let fileEntitlements = entitlementsFilePath.flatMap { entitlementsDictionary(fromFile: $0) }

        var selectedEntitlements: [String: AnyObject]?
        switch finalSource {
        case .provisioningProfile:
            selectedEntitlements = profile?.entitlements
        case .custom:
            selectedEntitlements = profile?.entitlements
        case .originalApp:
            selectedEntitlements = originalEntitlements
        case .entitlementsFile:
            selectedEntitlements = fileEntitlements
        }

        if selectedEntitlements == nil {
            selectedEntitlements = profile?.entitlements ?? fileEntitlements ?? originalEntitlements
        }

        guard var entitlements = selectedEntitlements else {
            return nil
        }

        let applicationIdentifier = entitlements["application-identifier"] as? String
        let teamID = profile?.teamID ?? applicationIdentifier.flatMap { identifier in
            identifier.split(separator: ".", maxSplits: 1).first.map(String.init)
        }
        let expandedAppGroups = appGroups.map { expandEntitlementVariables($0, teamID: teamID) }
        let expandedKeychainGroups = keychainGroups.map { expandEntitlementVariables($0, teamID: teamID) }

        if expandedAppGroups.isEmpty {
            entitlements.removeValue(forKey: "com.apple.security.application-groups")
        } else {
            entitlements["com.apple.security.application-groups"] = expandedAppGroups as AnyObject
        }

        if expandedKeychainGroups.isEmpty {
            entitlements.removeValue(forKey: "keychain-access-groups")
        } else {
            entitlements["keychain-access-groups"] = expandedKeychainGroups as AnyObject
        }

        if shouldSkipGetTaskAllow {
            entitlements.removeValue(forKey: "get-task-allow")
        }

        if !newApplicationID.isEmpty, let teamID {
            entitlements["application-identifier"] = "\(teamID).\(newApplicationID)" as AnyObject
        }

        return entitlements
    }


    @objc func populateProvisioningProfiles(){
        let zeroWidthSpace = "​"
        self.provisioningProfiles = ProvisioningProfile.getProfiles().sorted {
            ($0.name == $1.name && $0.created.timeIntervalSince1970 > $1.created.timeIntervalSince1970) || $0.name < $1.name
        }
        setStatus("Found \(provisioningProfiles.count) Provisioning Profile\(provisioningProfiles.count>1 || provisioningProfiles.count<1 ? "s":"")")
        ProvisioningProfilesPopup.removeAllItems()
        ProvisioningProfilesPopup.addItems(withTitles: [
            "仅重签（使用内嵌描述文件）",
            "自定义描述文件…",
            "––––––––––––––––––––––"
        ])
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        var newProfiles: [ProvisioningProfile] = []
        var zeroWidthPadding: String = ""
        for profile in provisioningProfiles {
            zeroWidthPadding = "\(zeroWidthPadding)\(zeroWidthSpace)"
            if profile.expires.timeIntervalSince1970 > Date().timeIntervalSince1970 {
                newProfiles.append(profile)
                
                ProvisioningProfilesPopup.addItem(withTitle: "\(profile.name)\(zeroWidthPadding) (\(profile.teamID))")
                
                let toolTipItems = [
                    "\(profile.name)",
                    "",
                    "Team ID: \(profile.teamID)",
                    "Created: \(formatter.string(from: profile.created as Date))",
                    "Expires: \(formatter.string(from: profile.expires as Date))"
                ]
                ProvisioningProfilesPopup.lastItem!.toolTip = toolTipItems.joined(separator: "\n")
                setStatus("Added profile \(profile.appID), expires (\(formatter.string(from: profile.expires as Date)))")
            } else {
                setStatus("Skipped profile \(profile.appID), expired (\(formatter.string(from: profile.expires as Date)))")
            }
        }
        self.provisioningProfiles = newProfiles
        chooseProvisioningProfile(ProvisioningProfilesPopup)
    }
    
    @objc func getCodesigningCerts() -> [String] {
        var output: [String] = []
        let securityResult = Process().execute(securityPath, workingDirectory: nil, arguments: ["find-identity","-v","-p","codesigning"])
        if securityResult.output.count < 1 {
            return output
        }
        let rawResult = securityResult.output.components(separatedBy: "\"")
        
        for index in stride(from: 0, through: rawResult.count - 2, by: 2) {
            if !(rawResult.count - 1 < index + 1) {
                output.append(rawResult[index+1])
            }
        }
        return output.sorted()
    }
    
    @objc func showCodesignCertsErrorAlert(){
        let alert = NSAlert()
        alert.messageText = "No codesigning certificates found"
        alert.informativeText = "I can attempt to fix this automatically, would you like me to try?"
        alert.addButton(withTitle: "Yes")
        alert.addButton(withTitle: "No")
        if alert.runModal() == NSApplication.ModalResponse.alertFirstButtonReturn {
            if let tempFolder = makeTempFolder() {
                iASShared.fixSigning(tempFolder)
                try? fileManager.removeItem(atPath: tempFolder)
                populateCodesigningCerts()
            }
        }
    }
    
    @objc func populateCodesigningCerts() {
        CodesigningCertsPopup.removeAllItems()
        self.codesigningCerts = getCodesigningCerts()
        
        setStatus("Found \(self.codesigningCerts.count) Codesigning Certificate\(self.codesigningCerts.count>1 || self.codesigningCerts.count<1 ? "s":"")")
        if self.codesigningCerts.count > 0 {
            for cert in self.codesigningCerts {
                CodesigningCertsPopup.addItem(withTitle: cert)
                setStatus("Added signing certificate \"\(cert)\"")
            }
        } else {
            certificateHintLabel?.stringValue = "未找到可用的签名身份。请拖入或选择包含私钥的 P12 / PFX 证书。"
            certificateHintLabel?.textColor = .systemOrange
        }

    }

    func checkProfileID(_ profile: ProvisioningProfile?){
        defer { updateProfileDetails() }
        if let profile = profile {
            self.profileFilename = profile.filename
            self.selectedProvisioningProfile = profile
            setStatus("已选择描述文件：\(profile.name)")
            if profile.expires.timeIntervalSince1970 < Date().timeIntervalSince1970 {
                ProvisioningProfilesPopup.selectItem(at: 0)
                setStatus("描述文件已过期")
                chooseProvisioningProfile(ProvisioningProfilesPopup)
            }
            if profile.appID.firstIndex(of: "*") == nil {
                // Not a wildcard profile
                NewApplicationIDTextField.stringValue = profile.appID
                NewApplicationIDTextField.isEnabled = false
            } else {
                // Wildcard profile
                if NewApplicationIDTextField.isEnabled == false {
                    NewApplicationIDTextField.stringValue = ""
                    NewApplicationIDTextField.isEnabled = true
                }
            }
            scheduleEntitlementInspection()
        } else {
            ProvisioningProfilesPopup.selectItem(at: 0)
            self.profileFilename = nil
            self.selectedProvisioningProfile = nil
            setStatus("描述文件无效")
            chooseProvisioningProfile(ProvisioningProfilesPopup)
            rebuildEntitlementInspectorContent()
        }
    }
    
    @objc func controlsEnabled(_ enabled: Bool){
        
        if (!Thread.isMainThread){
            DispatchQueue.main.sync{
                controlsEnabled(enabled)
            }
        }
        else{
            signingControlsEnabled = enabled
            setSigningInputControlsEnabled(enabled)
            if(enabled){
                InputFileText.isEnabled = true
                BrowseButton.isEnabled = true
                ProvisioningProfilesPopup.isEnabled = true
                CodesigningCertsPopup.isEnabled = true
                NewApplicationIDTextField.isEnabled = ReEnableNewApplicationID
                NewApplicationIDTextField.stringValue = PreviousNewApplicationID
                StartButton.isEnabled = true
                appDisplayName.isEnabled = true
                entitlementSourcePopup?.isEnabled = true
                finalAppGroupsField?.isEnabled = true
                finalKeychainGroupsField?.isEnabled = true
                chooseEntitlementsFileButton?.isEnabled = true
                clearEntitlementsFileButton?.isEnabled = entitlementFilePath != nil
            } else {
                // Backup previous values
                PreviousNewApplicationID = NewApplicationIDTextField.stringValue
                ReEnableNewApplicationID = NewApplicationIDTextField.isEnabled
                
                InputFileText.isEnabled = false
                BrowseButton.isEnabled = false
                ProvisioningProfilesPopup.isEnabled = false
                CodesigningCertsPopup.isEnabled = false
                NewApplicationIDTextField.isEnabled = false
                StartButton.isEnabled = false
                appDisplayName.isEnabled = false
                entitlementSourcePopup?.isEnabled = false
                finalAppGroupsField?.isEnabled = false
                finalKeychainGroupsField?.isEnabled = false
                chooseEntitlementsFileButton?.isEnabled = false
                clearEntitlementsFileButton?.isEnabled = false
            }
        }
    }
    
    @objc func recursiveDirectorySearch(_ path: String, extensions: [String], found: ((_ file: String) -> Void)){
        
        if let files = try? fileManager.contentsOfDirectory(atPath: path) {
            var isDirectory: ObjCBool = true
            
            for file in files {
                let currentFile = path.stringByAppendingPathComponent(file)
                fileManager.fileExists(atPath: currentFile, isDirectory: &isDirectory)
                if isDirectory.boolValue {
                    recursiveDirectorySearch(currentFile, extensions: extensions, found: found)
                }
                if extensions.contains(file.pathExtension) {
                    if file.pathExtension != "" || file == "IpaSecurityRestriction" {
                        found(currentFile)
                    } else {
                        //NSLog("couldnt find: %@", file)
                    }
                } else if isDirectory.boolValue == false && checkMachOFile(currentFile) {
                    found(currentFile)
                }
                
            }
        }
    }

    func allowRecursiveSearchAt(_ path: String) -> Bool {
        return shouldCheckPlugins || path.lastPathComponent != "PlugIns"
    }
    
    /// check if Mach-O file
    @objc func checkMachOFile(_ path: String) -> Bool {
        if let file = FileHandle(forReadingAtPath: path) {
            let data = file.readData(ofLength: 4)
            file.closeFile()
            var machOFile = data.elementsEqual([0xCE, 0xFA, 0xED, 0xFE]) || data.elementsEqual([0xCF, 0xFA, 0xED, 0xFE]) || data.elementsEqual([0xCA, 0xFE, 0xBA, 0xBE])
            
            if machOFile == false && signableExtensions.contains(path.lastPathComponent.pathExtension.lowercased()) {
                Log.write("Detected binary by extension: \(path)")
                machOFile = true
            }
            return machOFile
        }
        return false
    }
    
    func unzip(_ inputFile: String, outputPath: String)->AppSignerTaskOutput {
        return Process().execute(unzipPath, workingDirectory: nil, arguments: ["-q",inputFile,"-d",outputPath])
    }
    func zip(_ inputPath: String, outputFile: String)->AppSignerTaskOutput {
        return Process().execute(zipPath, workingDirectory: inputPath, arguments: ["-qry", outputFile, "."])
    }
    
    @objc func cleanup(_ tempFolder: String){
        do {
            Log.write("Deleting: \(tempFolder)")
            try fileManager.removeItem(atPath: tempFolder)
        } catch let error as NSError {
            setStatus("Unable to delete temp folder")
            Log.write(error.localizedDescription)
        }
        controlsEnabled(true)
    }
    @objc func bytesToSmallestSi(_ size: Double) -> String {
        let prefixes = ["","K","M","G","T","P","E","Z","Y"]
        for i in 1...6 {
            let nextUnit = pow(1024.00, Double(i+1))
            let unitMax = pow(1024.00, Double(i))
            if size < nextUnit {
                return "\(round((size / unitMax)*100)/100)\(prefixes[i])B"
            }
            
        }
        return "\(size)B"
    }
    @objc func getPlistKey(_ plist: String, keyName: String)->String? {
        let dictionary = NSDictionary(contentsOfFile: plist);
        return dictionary?[keyName] as? String
    }
    
    func setPlistKey(_ plist: String, keyName: String, value: String)->AppSignerTaskOutput {
        return Process().execute(defaultsPath, workingDirectory: nil, arguments: ["write", plist, keyName, value])
    }
    
    //MARK: NSURL Delegate
    @objc var downloading = false
    @objc var downloadError: NSError?
    @objc var downloadPath: String!
    
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        downloadError = downloadTask.error as NSError?
        if downloadError == nil {
            do {
                try fileManager.moveItem(at: location, to: URL(fileURLWithPath: downloadPath))
            } catch let error as NSError {
                setStatus("Unable to move downloaded file")
                Log.write(error.localizedDescription)
            }
        }
        downloading = false
        downloadProgress.doubleValue = 0.0
        downloadProgress.stopAnimation(nil)
        DispatchQueue.main.async {
            self.downloadProgress.isHidden = true
        }
    }
    
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        
        //StatusLabel.stringValue = "Downloading file: \(bytesToSmallestSi(Double(totalBytesWritten))) / \(bytesToSmallestSi(Double(totalBytesExpectedToWrite)))"
        let percentDownloaded = (Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)) * 100
        downloadProgress.doubleValue = percentDownloaded
    }
    
    //MARK: Codesigning
    @discardableResult
    func codeSign(_ file: String, certificate: String, entitlements: String?,before:((_ file: String, _ certificate: String, _ entitlements: String?)->Void)?, after: ((_ file: String, _ certificate: String, _ entitlements: String?, _ codesignTask: AppSignerTaskOutput)->Void)?)->AppSignerTaskOutput{

        var needEntitlements: Bool = false
        let filePath: String
        switch file.pathExtension.lowercased() {
        case "framework":
            // append executable file in framework
            let fileName = file.lastPathComponent.stringByDeletingPathExtension
            filePath = file.stringByAppendingPathComponent(fileName)
        case "app", "appex":
            // read executable file from Info.plist
            let infoPlist = file.stringByAppendingPathComponent("Info.plist")
            let executableFile = getPlistKey(infoPlist, keyName: "CFBundleExecutable")!
            filePath = file.stringByAppendingPathComponent(executableFile)

            if let entitlementsPath = entitlements, fileManager.fileExists(atPath: entitlementsPath) {
                needEntitlements = true
            }
        default:
            filePath = file
        }

        if let beforeFunc = before {
            beforeFunc(file, certificate, entitlements)
        }

        var arguments = ["-f", "-s", certificate, "--generate-entitlement-der"]
        if needEntitlements {
            arguments += ["--entitlements", entitlements!]
        }
        arguments.append(filePath)

        let codesignTask = Process().execute(codesignPath, workingDirectory: nil, arguments: arguments)
        if codesignTask.status != 0 {
            Log.write("Error codesign: \(codesignTask.output)")
            
            if (codesignTask.output.contains("ambiguous")) {
                let alert = NSAlert()
                alert.messageText = "Codesign failed due to ambiguous certificates"
                alert.informativeText = "\(codesignTask.output)\nOpen Keychain Access and remove the duplicate certificates."
                alert.alertStyle = .warning
                alert.addButton(withTitle: "OK")
                alert.runModal()
            }
        }
        
        if let afterFunc = after {
            afterFunc(file, certificate, entitlements, codesignTask)
        }
        return codesignTask
    }
    func testSigning(_ certificate: String, tempFolder: String )->Bool? {
        let codesignTempFile = tempFolder.stringByAppendingPathComponent("test-sign")
        
        // Copy our binary to the temp folder to use for testing.
        let path = ProcessInfo.processInfo.arguments[0]
        if (try? fileManager.copyItem(atPath: path, toPath: codesignTempFile)) != nil {
            codeSign(codesignTempFile, certificate: certificate, entitlements: nil, before: nil, after: nil)
            
            let verificationTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-v",codesignTempFile])
            try? fileManager.removeItem(atPath: codesignTempFile)
            if verificationTask.status == 0 {
                Log.write("Error testing codesign: \(verificationTask.output)")
                return true
            } else {
                return false
            }
        } else {
            setStatus("Error testing codesign")
        }
        return nil
    }

    func plistDictionary(fromCodesignOutput output: String) -> [String : AnyObject]? {
        guard let plistStart = output.range(of: "<?xml"),
              let plistEnd = output.range(of: "</plist>") else {
            return nil
        }

        let plistString = output[plistStart.lowerBound..<plistEnd.upperBound]
        guard let plistData = String(plistString).data(using: .utf8) else {
            return nil
        }

        return try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String : AnyObject]
    }

    func signedEntitlements(forBundle bundlePath: String) -> [String : AnyObject]? {
        let entitlementsTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-d", "--entitlements", ":-", bundlePath])
        if entitlementsTask.status != 0 {
            Log.write("Unable to read signed entitlements from \(bundlePath): \(entitlementsTask.output)")
            return nil
        }

        return plistDictionary(fromCodesignOutput: entitlementsTask.output)
    }

    func formattedAccessGroups(_ groups: [String]) -> String {
        if groups.isEmpty {
            return "(none)"
        }

        return groups.map { "  \($0)" }.joined(separator: "\n")
    }

    @objc func startSigning() {
        let inputFile = InputFileText.stringValue
        if (inputFile.count < 4) {
            return
        }
        
        if inputFile.pathExtension.lowercased() == "appex" {
            outputFile = inputFile
        } else {
            //MARK: Get output filename
            let saveDialog = NSSavePanel()
            saveDialog.allowedFileTypes = ["ipa"]
            saveDialog.nameFieldStringValue = inputFile.lastPathComponent.stringByDeletingPathExtension
            if saveDialog.runModal().rawValue == NSFileHandlingPanelOKButton {
                outputFile = saveDialog.url!.path
            } else {
                outputFile = nil
            }
        }
        if outputFile != nil {
            controlsEnabled(false)
            Thread.detachNewThreadSelector(#selector(self.signingThread), toTarget: self, with: nil)
        }
    }
    
    @objc func signingThread(){
        
        
        //MARK: Set up variables
        var warnings = 0
        var inputFile : String = ""
        var signingCertificate : String?
        var newApplicationID : String = ""
        var newDisplayName : String = ""
        var newShortVersion : String = ""
        var newVersion : String = ""
        var finalEntitlementSource: FinalEntitlementSource = .provisioningProfile
        var finalAppGroups: [String] = []
        var finalKeychainGroups: [String] = []
        var entitlementsFilePath: String?

        DispatchQueue.main.sync {
            downloadProgress.isHidden = true
            inputFile = self.InputFileText.stringValue
            signingCertificate = self.CodesigningCertsPopup.selectedItem?.title
            newApplicationID = self.NewApplicationIDTextField.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newDisplayName = self.appDisplayName.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newShortVersion = self.appShortVersion.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newVersion = self.appVersion.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            shouldCheckPlugins = ignorePluginsCheckbox.state == .off
            shouldSkipGetTaskAllow = noGetTaskAllowCheckbox.state == .on
            finalEntitlementSource = self.finalEntitlementSource
            finalAppGroups = self.currentFinalAppGroups()
            finalKeychainGroups = self.currentFinalKeychainGroups()
            entitlementsFilePath = self.entitlementFilePath
        }

        var provisioningFile = self.profileFilename
        let inputStartsWithHTTP = inputFile.lowercased().substring(to: inputFile.index(inputFile.startIndex, offsetBy: 4)) == "http"
        var eggCount: Int = 0
        var continueSigning: Bool? = nil
        
        //MARK: Sanity checks
        
        // Check signing certificate selection
        if signingCertificate == nil {
            setStatus("No signing certificate selected")
            return
        }
        
        // Check if input file exists
        var inputIsDirectory: ObjCBool = false
        if !inputStartsWithHTTP && !fileManager.fileExists(atPath: inputFile, isDirectory: &inputIsDirectory){
            DispatchQueue.main.async(execute: {
                let alert = NSAlert()
                alert.messageText = "Input file not found"
                alert.addButton(withTitle: "OK")
                alert.informativeText = "The file \(inputFile) could not be found"
                alert.runModal()
                self.controlsEnabled(true)
            })
            return
        }
        
        //MARK: Create working temp folder
        var tempFolder: String! = nil
        if let tmpFolder = makeTempFolder() {
            tempFolder = tmpFolder
        } else {
            setStatus("Error creating temp folder")
            return
        }
        let workingDirectory = tempFolder.stringByAppendingPathComponent("out")
        let eggDirectory = tempFolder.stringByAppendingPathComponent("eggs")
        let payloadDirectory = workingDirectory.stringByAppendingPathComponent("Payload/")
        let entitlementsPlist = tempFolder.stringByAppendingPathComponent("entitlements.plist")
        
        Log.write("Temp folder: \(tempFolder)")
        Log.write("Working directory: \(workingDirectory)")
        Log.write("Payload directory: \(payloadDirectory)")
        
        //MARK: Codesign Test
        
        DispatchQueue.main.async(execute: {
            if let codesignResult = self.testSigning(signingCertificate!, tempFolder: tempFolder) {
                if codesignResult == false {
                    let alert = NSAlert()
                    alert.messageText = "Codesigning error"
                    alert.addButton(withTitle: "Yes")
                    alert.addButton(withTitle: "No")
                    alert.informativeText = "You appear to have a error with your codesigning certificate, do you want me to try and fix the problem?"
                    let response = alert.runModal()
                    if response == NSApplication.ModalResponse.alertFirstButtonReturn {
                        iASShared.fixSigning(tempFolder)
                        if self.testSigning(signingCertificate!, tempFolder: tempFolder) == false {
                            let errorAlert = NSAlert()
                            errorAlert.messageText = "Unable to Fix"
                            errorAlert.addButton(withTitle: "OK")
                            errorAlert.informativeText = "I was unable to automatically resolve your codesigning issue ☹\n\nIf you have previously trusted your certificate using Keychain, please set the Trust setting back to the system default."
                            errorAlert.runModal()
                            continueSigning = false
                            return
                        }
                    } else {
                        continueSigning = false
                        return
                    }
                }
            }
            continueSigning = true
        })
        
        
        while true {
            if continueSigning != nil {
                if continueSigning! == false {
                    continueSigning = nil
                    cleanup(tempFolder); return
                }
                break
            }
            usleep(100)
        }
        
        //MARK: Create Egg Temp Directory
        do {
            try fileManager.createDirectory(atPath: eggDirectory, withIntermediateDirectories: true, attributes: nil)
        } catch let error as NSError {
            setStatus("Error creating egg temp directory")
            Log.write(error.localizedDescription)
            cleanup(tempFolder); return
        }
        
        //MARK: Download file
        downloading = false
        downloadError = nil
        downloadPath = tempFolder.stringByAppendingPathComponent("download.\(inputFile.pathExtension)")
        
        if inputStartsWithHTTP {
            let defaultConfigObject = URLSessionConfiguration.default
            let defaultSession = Foundation.URLSession(configuration: defaultConfigObject, delegate: self, delegateQueue: OperationQueue.main)
            if let url = URL(string: inputFile) {
                downloading = true
                
                let downloadTask = defaultSession.downloadTask(with: url)
                setStatus("Downloading file")
                DispatchQueue.main.async {
                    self.downloadProgress.isHidden = false
                }
                downloadProgress.startAnimation(nil)
                downloadTask.resume()
                defaultSession.finishTasksAndInvalidate()
            }
            
            while downloading {
                usleep(100000)
            }
            if downloadError != nil {
                setStatus("Error downloading file, \(downloadError!.localizedDescription.lowercased())")
                cleanup(tempFolder); return
            } else {
                inputFile = downloadPath
            }
        }
        
        //MARK: Process input file
        switch(inputFile.pathExtension.lowercased()){
        case "deb":
            //MARK: --Unpack deb
            let debPath = tempFolder.stringByAppendingPathComponent("deb")
            do {
                
                try fileManager.createDirectory(atPath: debPath, withIntermediateDirectories: true, attributes: nil)
                try fileManager.createDirectory(atPath: workingDirectory, withIntermediateDirectories: true, attributes: nil)
                setStatus("Extracting deb file")
                let debTask = Process().execute(arPath, workingDirectory: debPath, arguments: ["-x", inputFile])
                Log.write(debTask.output)
                if debTask.status != 0 {
                    setStatus("Error processing deb file")
                    cleanup(tempFolder); return
                }
                
                var tarUnpacked = false
                for tarFormat in ["tar","tar.gz","tar.bz2","tar.lzma","tar.xz"]{
                    let dataPath = debPath.stringByAppendingPathComponent("data.\(tarFormat)")
                    if fileManager.fileExists(atPath: dataPath){
                        
                        setStatus("Unpacking data.\(tarFormat)")
                        let tarTask = Process().execute(tarPath, workingDirectory: debPath, arguments: ["-xf",dataPath])
                        Log.write(tarTask.output)
                        if tarTask.status == 0 {
                            tarUnpacked = true
                        }
                        break
                    }
                }
                if !tarUnpacked {
                    setStatus("Error unpacking data.tar")
                    cleanup(tempFolder); return
                }
              
              var sourcePath = debPath.stringByAppendingPathComponent("Applications")
              if fileManager.fileExists(atPath: debPath.stringByAppendingPathComponent("var/mobile/Applications")){
                  sourcePath = debPath.stringByAppendingPathComponent("var/mobile/Applications")
              }
              
              try fileManager.moveItem(atPath: sourcePath, toPath: payloadDirectory)
                
            } catch {
                setStatus("Error processing deb file")
                cleanup(tempFolder); return
            }
            
        case "ipa":
            //MARK: --Unzip ipa
            do {
                try fileManager.createDirectory(atPath: workingDirectory, withIntermediateDirectories: true, attributes: nil)
                setStatus("Extracting ipa file")
                
                let unzipTask = self.unzip(inputFile, outputPath: workingDirectory)
                if unzipTask.status != 0 {
                    setStatus("Error extracting ipa file")
                    cleanup(tempFolder); return
                }
            } catch {
                setStatus("Error extracting ipa file")
                cleanup(tempFolder); return
            }
            
        case "app", "appex":
            //MARK: --Copy app bundle
            if !inputIsDirectory.boolValue {
                setStatus("Unsupported input file")
                cleanup(tempFolder); return
            }
            do {
                try fileManager.createDirectory(atPath: payloadDirectory, withIntermediateDirectories: true, attributes: nil)
                setStatus("Copying app to payload directory")
                try fileManager.copyItem(atPath: inputFile, toPath: payloadDirectory.stringByAppendingPathComponent(inputFile.lastPathComponent))
            } catch {
                setStatus("Error copying app to payload directory")
                cleanup(tempFolder); return
            }
            
        case "xcarchive":
            //MARK: --Copy app bundle from xcarchive
            if !inputIsDirectory.boolValue {
                setStatus("Unsupported input file")
                cleanup(tempFolder); return
            }
            do {
                try fileManager.createDirectory(atPath: workingDirectory, withIntermediateDirectories: true, attributes: nil)
                setStatus("Copying app to payload directory")
                try fileManager.copyItem(atPath: inputFile.stringByAppendingPathComponent("Products/Applications/"), toPath: payloadDirectory)
            } catch {
                setStatus("Error copying app to payload directory")
                cleanup(tempFolder); return
            }
            
        default:
            setStatus("Unsupported input file")
            cleanup(tempFolder); return
        }
        
        if !fileManager.fileExists(atPath: payloadDirectory){
            setStatus("Payload directory doesn't exist")
            cleanup(tempFolder); return
        }
        
        // Loop through app bundles in payload directory
        do {
            let files = try fileManager.contentsOfDirectory(atPath: payloadDirectory)
            var isDirectory: ObjCBool = true
            
            for file in files {
                
                fileManager.fileExists(atPath: payloadDirectory.stringByAppendingPathComponent(file), isDirectory: &isDirectory)
                if !isDirectory.boolValue { continue }
                
                //MARK: Bundle variables setup
                let appBundlePath = payloadDirectory.stringByAppendingPathComponent(file)
                let appBundleInfoPlist = appBundlePath.stringByAppendingPathComponent("Info.plist")
                let appBundleProvisioningFilePath = appBundlePath.stringByAppendingPathComponent("embedded.mobileprovision")
                let useAppBundleProfile = (provisioningFile == nil && fileManager.fileExists(atPath: appBundleProvisioningFilePath))
                
                //MARK: Delete CFBundleResourceSpecification from Info.plist
                Log.write(Process().execute(defaultsPath, workingDirectory: nil, arguments: ["delete",appBundleInfoPlist,"CFBundleResourceSpecification"]).output)
                
                //MARK: Copy Provisioning Profile
                if provisioningFile != nil {
                    if fileManager.fileExists(atPath: appBundleProvisioningFilePath) {
                        setStatus("Deleting embedded.mobileprovision")
                        do {
                            try fileManager.removeItem(atPath: appBundleProvisioningFilePath)
                        } catch let error as NSError {
                            setStatus("Error deleting embedded.mobileprovision")
                            Log.write(error.localizedDescription)
                            cleanup(tempFolder); return
                        }
                    }
                    setStatus("Copying provisioning profile to app bundle")
                    do {
                        try fileManager.copyItem(atPath: provisioningFile!, toPath: appBundleProvisioningFilePath)
                    } catch let error as NSError {
                        setStatus("Error copying provisioning profile")
                        Log.write(error.localizedDescription)
                        cleanup(tempFolder); return
                    }
                }
                
                let bundleID = getPlistKey(appBundleInfoPlist, keyName: "CFBundleIdentifier")
                
                //MARK: Generate entitlements.plist
                setStatus("Parsing entitlements")
                var signingProfile: ProvisioningProfile?
                if provisioningFile != nil || useAppBundleProfile {
                    if var profile = ProvisioningProfile(filename: useAppBundleProfile ? appBundleProvisioningFilePath : provisioningFile!) {
                        let hasNewAppID = !newApplicationID.isEmpty
                        if let wildcardIndex = profile.appID.firstIndex(of: "*") {
                            let allowedPrefix = profile.appID.prefix(upTo: wildcardIndex)
                            if hasNewAppID, newApplicationID.starts(with: allowedPrefix) {
                                profile.update(trueAppID: newApplicationID)
                            } else if let existingBundleID = bundleID {
                                profile.update(trueAppID: existingBundleID)
                            }
                        } else if hasNewAppID, newApplicationID != profile.appID {
                            setStatus("Unable to change App ID to \(newApplicationID), provisioning profile won't allow it")
                            cleanup(tempFolder)
                            return
                        }
                        signingProfile = profile
                    } else {
                        setStatus("Unable to parse provisioning profile, it may be corrupt")
                        warnings += 1
                    }
                }

                if let entitlements = entitlementsForSigning(
                    profile: signingProfile,
                    appBundlePath: appBundlePath,
                    bundleID: bundleID,
                    entitlementsFilePath: entitlementsFilePath,
                    finalSource: finalEntitlementSource,
                    appGroups: finalAppGroups,
                    keychainGroups: finalKeychainGroups,
                    newApplicationID: newApplicationID
                ) {
                    if let data = try? PropertyListSerialization.data(
                        fromPropertyList: entitlements,
                        format: .xml,
                        options: 0
                    ) {
                        do {
                            try data.write(to: URL(fileURLWithPath: entitlementsPlist), options: .atomic)
                            Log.write("Using final App Groups:\n\(formattedAccessGroups(finalAppGroups))")
                            Log.write("Using final Keychain Access Groups:\n\(formattedAccessGroups(finalKeychainGroups))")
                            Log.write("–––––––––––––––––––––––\n\(String(data: data, encoding: .utf8) ?? "")")
                            Log.write("–––––––––––––––––––––––")
                            setStatus("Saved entitlements to \(entitlementsPlist)")
                        } catch {
                            setStatus("Error writing entitlements.plist, \(error.localizedDescription)")
                        }
                    }
                } else if provisioningFile != nil || useAppBundleProfile || entitlementsFilePath != nil {
                    setStatus("Unable to build entitlements; signing without an entitlements plist")
                    warnings += 1
                }
                
                //MARK: Make sure that the executable is well... executable.
                if let bundleExecutable = getPlistKey(appBundleInfoPlist, keyName: "CFBundleExecutable"){
                    _ = Process().execute(chmodPath, workingDirectory: nil, arguments: ["755", appBundlePath.stringByAppendingPathComponent(bundleExecutable)])
                }
                
                //MARK: Change Application ID
                if newApplicationID != "" {
                    
                    if let oldAppID = bundleID {
                        func changeAppexID(_ appexFile: String){
                            guard allowRecursiveSearchAt(appexFile.stringByDeletingLastPathComponent) else {
                                return
                            }

                            let appexPlist = appexFile.stringByAppendingPathComponent("Info.plist")
                            if let appexBundleID = getPlistKey(appexPlist, keyName: "CFBundleIdentifier"){
                                let newAppexID = "\(newApplicationID)\(appexBundleID.substring(from: oldAppID.endIndex))"
                                setStatus("Changing \(appexFile) id to \(newAppexID)")
                                _ = setPlistKey(appexPlist, keyName: "CFBundleIdentifier", value: newAppexID)
                            }
                            if Process().execute(defaultsPath, workingDirectory: nil, arguments: ["read", appexPlist,"WKCompanionAppBundleIdentifier"]).status == 0 {
                                _ = setPlistKey(appexPlist, keyName: "WKCompanionAppBundleIdentifier", value: newApplicationID)
                            }
                            // 修复微信改bundleid后安装失败问题
                            let pluginInfoPlist = NSMutableDictionary(contentsOfFile: appexPlist)
                            if let dictionaryArray = pluginInfoPlist?["NSExtension"] as? [String:AnyObject],
                                let attributes : NSMutableDictionary = dictionaryArray["NSExtensionAttributes"] as? NSMutableDictionary,
                                let wkAppBundleIdentifier = attributes["WKAppBundleIdentifier"] as? String{
                                let newAppesID = wkAppBundleIdentifier.replacingOccurrences(of:oldAppID, with:newApplicationID);
                                attributes["WKAppBundleIdentifier"] = newAppesID;
                                pluginInfoPlist!.write(toFile: appexPlist, atomically: true);
                            }
                            recursiveDirectorySearch(appexFile, extensions: ["app"], found: changeAppexID)
                        }
                        recursiveDirectorySearch(appBundlePath, extensions: ["appex"], found: changeAppexID)
                    }
                    
                    setStatus("Changing App ID to \(newApplicationID)")
                    let IDChangeTask = setPlistKey(appBundleInfoPlist, keyName: "CFBundleIdentifier", value: newApplicationID)
                    if IDChangeTask.status != 0 {
                        setStatus("Error changing App ID")
                        Log.write(IDChangeTask.output)
                        cleanup(tempFolder); return
                    }
                }
                
                //MARK: Change Display Name
                if newDisplayName != "" {
                    setStatus("Changing Display Name to \(newDisplayName))")
                    let displayNameChangeTask = Process().execute(defaultsPath, workingDirectory: nil, arguments: ["write",appBundleInfoPlist,"CFBundleDisplayName", newDisplayName])
                    if displayNameChangeTask.status != 0 {
                        setStatus("Error changing display name")
                        Log.write(displayNameChangeTask.output)
                        cleanup(tempFolder); return
                    }
                }
                
                //MARK: Change Version
                if newVersion != "" {
                    setStatus("Changing Version to \(newVersion)")
                    let versionChangeTask = Process().execute(defaultsPath, workingDirectory: nil, arguments: ["write",appBundleInfoPlist,"CFBundleVersion", newVersion])
                    if versionChangeTask.status != 0 {
                        setStatus("Error changing version")
                        Log.write(versionChangeTask.output)
                        cleanup(tempFolder); return
                    }
                }
                
                //MARK: Change Short Version
                if newShortVersion != "" {
                    setStatus("Changing Short Version to \(newShortVersion)")
                    let shortVersionChangeTask = Process().execute(defaultsPath, workingDirectory: nil, arguments: ["write",appBundleInfoPlist,"CFBundleShortVersionString", newShortVersion])
                    if shortVersionChangeTask.status != 0 {
                        setStatus("Error changing short version")
                        Log.write(shortVersionChangeTask.output)
                        cleanup(tempFolder); return
                    }
                }
                
                
                func generateFileSignFunc(_ payloadDirectory:String, entitlementsPath: String, signingCertificate: String)->((_ file:String)->Void){
                    
                    
                    let useEntitlements: Bool = ({
                        if fileManager.fileExists(atPath: entitlementsPath) {
                            return true
                        }
                        return false
                    })()
                    
                    func shortName(_ file: String, payloadDirectory: String)->String{
                        return file.substring(from: payloadDirectory.endIndex)
                    }
                    
                    func beforeFunc(_ file: String, certificate: String, entitlements: String?){
                            setStatus("Codesigning \(shortName(file, payloadDirectory: payloadDirectory))\(useEntitlements ? " with entitlements":"")")
                    }
                    
                    func afterFunc(_ file: String, certificate: String, entitlements: String?, codesignOutput: AppSignerTaskOutput){
                        if codesignOutput.status != 0 {
                            setStatus("Error codesigning \(shortName(file, payloadDirectory: payloadDirectory))")
                            Log.write(codesignOutput.output)
                            warnings += 1
                        }
                    }
                    
                    func output(_ file:String){
                        codeSign(file, certificate: signingCertificate, entitlements: entitlementsPath, before: beforeFunc, after: afterFunc)
                    }
                    return output
                }
                
                //MARK: Codesigning - Eggs
                let eggSigningFunction = generateFileSignFunc(eggDirectory, entitlementsPath: entitlementsPlist, signingCertificate: signingCertificate!)
                func signEgg(_ eggFile: String){
                    eggCount += 1
                    
                    let currentEggPath = eggDirectory.stringByAppendingPathComponent("egg\(eggCount)")
                    let shortName = eggFile.substring(from: payloadDirectory.endIndex)
                    setStatus("Extracting \(shortName)")
                    if self.unzip(eggFile, outputPath: currentEggPath).status != 0 {
                        Log.write("Error extracting \(shortName)")
                        return
                    }
                    recursiveDirectorySearch(currentEggPath, extensions: ["egg"], found: signEgg)
                    recursiveDirectorySearch(currentEggPath, extensions: signableExtensions, found: eggSigningFunction)
                    setStatus("Compressing \(shortName)")
                    _ = self.zip(currentEggPath, outputFile: eggFile)                    
                }
                
                recursiveDirectorySearch(appBundlePath, extensions: ["egg"], found: signEgg)
                
                //MARK: Codesigning - App
                let signingFunction = generateFileSignFunc(payloadDirectory, entitlementsPath: entitlementsPlist, signingCertificate: signingCertificate!)
                
                recursiveDirectorySearch(appBundlePath, extensions: signableExtensions, found: signingFunction)
                signingFunction(appBundlePath)
                
                //MARK: Codesigning - Verification
                let verificationTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-v",appBundlePath])
                if verificationTask.status != 0 {
                    DispatchQueue.main.async(execute: {
                        let alert = NSAlert()
                        alert.addButton(withTitle: "OK")
                        alert.messageText = "Error verifying code signature!"
                        alert.informativeText = verificationTask.output
                        alert.alertStyle = .critical
                        alert.runModal()
                        self.setStatus("Error verifying code signature")
                        Log.write(verificationTask.output)
                        self.cleanup(tempFolder); return
                    })
                }
            }
        } catch let error as NSError {
            setStatus("Error listing files in payload directory")
            Log.write(error.localizedDescription)
            cleanup(tempFolder); return
        }
        
        //MARK: Packaging
        //Check if output already exists and delete if so
        if fileManager.fileExists(atPath: outputFile!) {
            do {
                try fileManager.removeItem(atPath: outputFile!)
            } catch let error as NSError {
                setStatus("Error deleting output file")
                Log.write(error.localizedDescription)
                cleanup(tempFolder)
                return
            }
        }

        switch outputFile?.pathExtension.lowercased() {
        case "ipa":
            setStatus("Packaging IPA")
            let zipTask = self.zip(workingDirectory, outputFile: outputFile!)
            if zipTask.status != 0 {
                setStatus("Error packaging IPA")
            }
        case "appex":
            do {
                try fileManager.copyItem(atPath: payloadDirectory.stringByAppendingPathComponent(inputFile.lastPathComponent), toPath: outputFile!)
            } catch let error as NSError {
                setStatus("Error copying appex bundle to \(outputFile!)")
                Log.write(error.localizedDescription)
            }
        default:
            break
        }

        //MARK: Cleanup
        cleanup(tempFolder)
        setStatus("Done, output at \(outputFile!)")
    }

    //MARK: IBActions
    @IBAction func chooseProvisioningProfile(_ sender: NSPopUpButton) {
        defer { updateProfileDetails() }
        
        switch(sender.indexOfSelectedItem){
        case 0:
            self.profileFilename = nil
            self.selectedProvisioningProfile = nil
            if NewApplicationIDTextField.isEnabled == false {
                NewApplicationIDTextField.isEnabled = true
                NewApplicationIDTextField.stringValue = ""
            }
            scheduleEntitlementInspection()
            
        case 1:
            let openDialog = NSOpenPanel()
            openDialog.canChooseFiles = true
            openDialog.canChooseDirectories = false
            openDialog.allowsMultipleSelection = false
            openDialog.allowsOtherFileTypes = false
            openDialog.allowedFileTypes = ["mobileprovision"]
            openDialog.runModal()
            if let filename = openDialog.urls.first {
                loadProfileFile(filename.path)
            } else {
                sender.selectItem(at: 0)
                chooseProvisioningProfile(sender)
            }
            
        case 2:
            sender.selectItem(at: 0)
            chooseProvisioningProfile(sender)
            
        default:
            let profile = provisioningProfiles[sender.indexOfSelectedItem - 3]
            checkProfileID(profile)
        }
        
    }
    @IBAction func doBrowse(_ sender: AnyObject) {
        let openDialog = NSOpenPanel()
        openDialog.canChooseFiles = true
        openDialog.canChooseDirectories = false
        openDialog.allowsMultipleSelection = false
        openDialog.allowsOtherFileTypes = false
        openDialog.allowedFileTypes = MainView.allowedFileTypes + MainView.allowedFileTypes.map({ $0.uppercased() })
        openDialog.runModal()
        if let filename = openDialog.urls.first {
            InputFileText.stringValue = filename.path
            scheduleEntitlementInspection()
        }
    }
    @IBAction func chooseSigningCertificate(_ sender: NSPopUpButton) {
        Log.write("Set Codesigning Certificate Default to: \(sender.stringValue)")
        defaults.setValue(sender.selectedItem?.title, forKey: "signingCertificate")
        if !isImportingCertificate {
            certificateFilePath = nil
            certificatePathField?.stringValue = ""
            certificatePathField?.toolTip = nil
            certificateHintLabel?.stringValue = "使用钥匙串中的签名身份；导入 P12 / PFX 时需包含私钥。"
            certificateHintLabel?.textColor = .secondaryLabelColor
        }
    }
    
    @IBAction func doSign(_ sender: NSButton) {
        if codesigningCerts.count > 0 {
            NSApplication.shared.windows[0].makeFirstResponder(self)
            startSigning()
        } else {
            showCodesignCertsErrorAlert()
        }
    }
    
    @IBAction func statusLabelClick(_ sender: NSButton) {
        if let outputFile = self.outputFile {
            if fileManager.fileExists(atPath: outputFile) {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: outputFile)])
            }
        }
    }
    
}
