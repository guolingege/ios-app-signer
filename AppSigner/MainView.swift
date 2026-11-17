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
    var sourceName: String
    let appGroups: [String]
    let keychainGroups: [String]
    let applicationIdentifier: String?
    let teamID: String?
    let status: EntitlementSnapshotStatus
    var sourcePath: String? = nil
    var sourceDescription: String? = nil
    var isAuthorizationScope = false

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
    case provisioningProfile = 0
    case originalApp = 1
    case embeddedProfile = 4
    case entitlementsFile = 2
    case custom = 3

    var title: String {
        switch self {
        case .provisioningProfile:
            return "本次签名描述文件"
        case .originalApp:
            return "Mach-O 签名权限"
        case .entitlementsFile:
            return "Entitlements 文件"
        case .custom:
            return "自定义"
        case .embeddedProfile:
            return "App 内嵌描述文件"
        }
    }
}

enum AccessGroupKind: Int, CaseIterable {
    case appGroups
    case keychainGroups

    var title: String { self == .appGroups ? "App Groups" : "钥匙串访问组" }
}

struct FinalGroupSelection {
    var source: FinalEntitlementSource = .provisioningProfile
    var userEdited = false
    var customValue: String?
}

class MainView: NSView, NSTextFieldDelegate {
    
    //MARK: IBOutlets
    @IBOutlet var ProvisioningProfilesPopup: NSPopUpButton!
    @IBOutlet var CodesigningCertsPopup: NSPopUpButton!
    @IBOutlet var StatusLabel: NSTextField!
    @IBOutlet var InputFileText: NSTextField!
    @IBOutlet var BrowseButton: NSButton!
    @IBOutlet var StartButton: NSButton!
    @IBOutlet var NewApplicationIDTextField: NSTextField!
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
    var inspectedEmbeddedEntitlements: EntitlementSnapshot?
    var entitlementFilePath: String?
    var finalAppGroupsSelection = FinalGroupSelection()
    var finalKeychainGroupsSelection = FinalGroupSelection()
    var isLeagsoftApp = true
    var leagsoftAppCheckbox: NSButton?
    var entitlementInspectorConfigured = false
    var entitlementInspectionGeneration = 0
    var inspectedInputPath: String?
    var inspectedApplicationMetadata: ApplicationMetadata?
    var applicationMetadataLabels: [String: NSTextField] = [:]
    var applicationMetadataStatusLabel: NSTextField?

    var profilePathField: SigningPathField?
    var certificatePathField: SigningPathField?
    var certificateFilePath: String?
    var certificateInputSource: SigningInputSource = .existing
    var profileInputSource: SigningInputSource = .existing
    var importedCertificateName: String?
    var importedProvisioningProfile: ProvisioningProfile?
    var certificateSourceControl: NSSegmentedControl?
    var profileSourceControl: NSSegmentedControl?
    var certificateExistingRow: NSView?
    var certificateFileRow: NSView?
    var profileExistingRow: NSView?
    var profileFileRow: NSView?
    var profileBrowseButton: NSButton?
    var certificateBrowseButton: NSButton?
    var profileDetailsLabel: NSTextField?
    var certificateHintLabel: NSTextField?
    var pathEditWorkItem: DispatchWorkItem?
    var signingControlsEnabled = true
    var signingIdentities: [SigningIdentity] = []
    var importedCertificateFingerprint: String?
    var importedCertificateFileDigest: String?
    var certificateMatchLabel: NSTextField?
    var refreshInspectionButton: NSButton?
    var profileReadError: String?
    var unreadableProfilePath: String?
    var isImportingCertificate = false

    var entitlementPanel: NSBox?
    var entitlementContentStack: NSStackView?
    var entitlementWarningLabel: NSTextField?
    var entitlementFilePathLabel: NSTextField?
    var appGroupsSourcePopup: NSPopUpButton?
    var keychainGroupsSourcePopup: NSPopUpButton?
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
    static let allowedFileTypes = ["ipa", "deb", "app", "appex", "xcarchive"]
    static let entitlementsFileTypes = ["entitlements", "plist"]
    static let certificateFileTypes = ["p12", "pfx", "cer", "crt", "pem"]
    static let fileTypes = allowedFileTypes + ["mobileprovision"] + entitlementsFileTypes + certificateFileTypes
    @objc var fileTypeIsOk = false
    
    @objc func fileDropped(_ filename: String){
        guard signingControlsEnabled else { return }
        let filename = SigningFilePath.normalize(filename)
        guard OfflineNetworkPolicy.isLocalPath(filename) else { return }
        switch filename.pathExtension.lowercased() {
        case let ext where MainView.allowedFileTypes.contains(ext):
            InputFileText.stringValue = filename
            scheduleEntitlementInspection()
        case "mobileprovision":
            loadProfileFile(filename)
        case let ext where MainView.certificateFileTypes.contains(ext):
            loadCertificateFile(filename)
        case let ext where MainView.entitlementsFileTypes.contains(ext):
            selectEntitlementsFile(filename)
        default:
            break
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
            if OfflineNetworkPolicy.isLocalPath(path), MainView.fileTypes.contains(path.pathExtension.lowercased()), fileManager.fileExists(atPath: path) {
                fileDropped(path)
                handled = true
            }
        }
        return handled
    }

    @objc func checkExtension(_ drag: NSDraggingInfo) -> Bool {
        guard signingControlsEnabled else { return false }
        return SigningFilePath.paths(from: drag.draggingPasteboard).contains { path in
            OfflineNetworkPolicy.isLocalPath(path) && fileManager.fileExists(atPath: path)
                && MainView.fileTypes.contains(path.pathExtension.lowercased())
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
            updateSigningInputSources()
            setStatus("就绪")
            if checkXcodeCLI() == false {
                let alert = NSAlert()
                alert.messageText = "缺少 Xcode 命令行工具"
                alert.informativeText = "本应用仅离线工作，不会启动在线安装。请自行准备好 Xcode 或命令行工具后重新打开。"
                alert.runModal()
                NSApplication.shared.terminate(self)
            }
        }
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
        stack.addArrangedSubview(sectionHeading("权限对比", subtitle: "橙色表示授权范围不同，或值不同但仍获授权；红色表示未授权。文件被替换后请使用顶部刷新。"))
        stack.addArrangedSubview(makeEntitlementsFilePickerRow())

        let baseline = entitlementComparisonReference()
        let profile = baseline?.snapshot
        let referenceTeam = profile?.teamID ?? inspectedOriginalEntitlements?.teamID ?? inspectedEntitlementsFile?.teamID
        let table = verticalStack(spacing: 0)
        table.addArrangedSubview(makeEntitlementTableRow(
            values: ["权限来源", "App Groups", "Keychain Access Groups", "对比状态"],
            colors: Array(repeating: .secondaryLabelColor, count: 4), bold: true, unavailable: false))
        for source in [FinalEntitlementSource.originalApp, .embeddedProfile, .provisioningProfile, .entitlementsFile] {
            let separator = NSBox()
            separator.boxType = .separator
            table.addArrangedSubview(separator)
            table.addArrangedSubview(makeSnapshotRow(title: source.title, snapshot: snapshot(for: source),
                reference: profile, teamID: referenceTeam, isReference: source == baseline?.source))
        }
        stack.addArrangedSubview(table)
        stack.addArrangedSubview(uiLabel("Mach-O：签名中声明的实际权限；描述文件：授权范围（可能含 *）。优先对照本次签名描述文件，否则对照 App 内嵌描述文件。此处不验证签名有效性。", size: 11, secondary: true))
        for row in table.arrangedSubviews { constrainInspectorRow(row, to: table) }

        let warning = uiLabel("", size: 11, weight: .medium)
        warning.maximumNumberOfLines = 0
        entitlementWarningLabel = warning
        stack.addArrangedSubview(warning)
        let separator = NSBox()
        separator.boxType = .separator
        stack.addArrangedSubview(separator)
        stack.addArrangedSubview(sectionHeading("最终签名值", subtitle: "勾选“联软应用”使用固定规则；取消勾选后，两类组可独立选择来源或自定义。"))
        let checkbox = NSButton(checkboxWithTitle: "联软应用", target: self, action: #selector(leagsoftAppChanged(_:)))
        checkbox.state = isLeagsoftApp ? .on : .off
        checkbox.toolTip = "App Groups 固定读取外部描述文件；钥匙串固定使用该描述文件 Team ID 对应的两个联软组。"
        leagsoftAppCheckbox = checkbox
        stack.addArrangedSubview(checkbox)
        if isLeagsoftApp {
            let detail = uiLabel(leagsoftValidationMessage ?? "App Groups：外部描述文件中的值；钥匙串：${TeamID}.com.apple.networkextensionsharing、${TeamID}.com.leagsoft.emm。Team ID 来自该描述文件，不使用 App 内嵌配置。", size: 11, secondary: true)
            detail.textColor = leagsoftValidationMessage == nil ? .secondaryLabelColor : .systemOrange
            stack.addArrangedSubview(detail)
        }
        stack.addArrangedSubview(makeFinalGroupsRow(kind: .appGroups, previousValue: previousAppGroups))
        stack.addArrangedSubview(makeFinalGroupsRow(kind: .keychainGroups, previousValue: previousKeychainGroups))
        for row in stack.arrangedSubviews { constrainInspectorRow(row, to: stack) }
        updateEntitlementWarning()
        setSigningInputControlsEnabled(signingControlsEnabled)
    }

    func makeSnapshotRow(title: String, snapshot: EntitlementSnapshot?, reference: EntitlementSnapshot?, teamID: String?, isReference: Bool = false) -> NSStackView {
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
            if isReference {
                result = "比较基准"
                color = .controlAccentColor
            } else if let reference, reference.isAvailable {
                let allowedApp = expandedGroups(reference.appGroups, teamID: reference.teamID)
                let allowedKeychain = expandedGroups(reference.keychainGroups, teamID: reference.teamID)
                let appMatches = setsEqual(appGroups, allowedApp)
                let keychainMatches = setsEqual(keychainGroups, allowedKeychain)
                let appAllowed = groupsAreAuthorized(appGroups, by: allowedApp)
                let keychainAllowed = groupsAreAuthorized(keychainGroups, by: allowedKeychain)
                appColor = appMatches ? .labelColor : (snapshot.isAuthorizationScope || appAllowed ? .systemOrange : .systemRed)
                keychainColor = keychainMatches ? .labelColor : (snapshot.isAuthorizationScope || keychainAllowed ? .systemOrange : .systemRed)
                if appMatches && keychainMatches {
                    result = "✓ 一致"
                    color = .systemGreen
                } else if snapshot.isAuthorizationScope {
                    result = "授权范围不同"
                    color = .systemOrange
                } else if appAllowed && keychainAllowed {
                    result = "值不同 · 已授权"
                    color = .systemOrange
                } else {
                    result = "⚠ 存在未授权值"
                    color = .systemRed
                }
            } else {
                result = "等待比较基准"
            }
        }
        let row = makeEntitlementTableRow(
            values: [title, snapshot.isAvailable ? formattedGroups(appGroups) : "—", snapshot.isAvailable ? formattedGroups(keychainGroups) : "—", result],
            colors: [.labelColor, appColor, keychainColor, color], bold: false, unavailable: !snapshot.isAvailable,
            sourceDetail: snapshot.sourceDescription, sourcePath: snapshot.sourcePath)
        row.toolTip = "\(snapshot.sourceName)\n\(snapshot.sourcePath ?? "")\nTeam ID: \(snapshot.teamID ?? "未知")\nApplication ID: \(snapshot.applicationIdentifier ?? "未知")\n\(snapshot.statusText)"
        return row
    }

    func groupsAreAuthorized(_ values: [String], by allowed: [String]) -> Bool {
        values.allSatisfy { group in allowed.contains { entitlementGroup(group, isAllowedBy: $0) } }
    }

    func makeEntitlementTableRow(values: [String], colors: [NSColor], bold: Bool, unavailable: Bool, sourceDetail: String? = nil, sourcePath: String? = nil) -> NSStackView {
        let row = horizontalStack(spacing: 14)
        row.alignment = .top
        row.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10)
        if bold { row.wantsLayer = true; row.layer?.backgroundColor = NSColor.quaternaryLabelColor.withAlphaComponent(0.18).cgColor }
        let proportions: [CGFloat] = [0.17, 0.31, 0.35, 0.17]
        for (index, value) in values.enumerated() {
            let cell: NSView
            if !bold && index == 0, let sourceDetail {
                let column = verticalStack(spacing: 4)
                let title = uiLabel(value, size: 12, weight: .medium)
                title.maximumNumberOfLines = 0
                column.addArrangedSubview(title)
                let detail = uiLabel(sourceDetail, size: 10, secondary: true)
                detail.maximumNumberOfLines = 3
                detail.lineBreakMode = .byTruncatingMiddle
                detail.isSelectable = true
                detail.toolTip = sourcePath
                column.addArrangedSubview(detail)
                for label in column.arrangedSubviews { label.widthAnchor.constraint(equalTo: column.widthAnchor).isActive = true }
                cell = column
            } else if !bold && (index == 1 || index == 2) && value != "—" && value != "未设置" {
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

    func groupSelection(for kind: AccessGroupKind) -> FinalGroupSelection {
        kind == .appGroups ? finalAppGroupsSelection : finalKeychainGroupsSelection
    }

    func setGroupSelection(_ selection: FinalGroupSelection, for kind: AccessGroupKind) {
        if kind == .appGroups { finalAppGroupsSelection = selection }
        else { finalKeychainGroupsSelection = selection }
    }

    func snapshot(for source: FinalEntitlementSource) -> EntitlementSnapshot? {
        switch source {
        case .provisioningProfile: return selectedProfileSnapshot()
        case .embeddedProfile: return embeddedProfileSnapshot()
        case .originalApp: return inspectedOriginalEntitlements
        case .entitlementsFile: return inspectedEntitlementsFile
        case .custom: return nil
        }
    }

    var leagsoftValidationMessage: String? {
        guard isLeagsoftApp else { return nil }
        if let message = profileReadError { return message }
        guard let profile = selectedProvisioningProfile else {
            return "联软应用需要外部描述文件：请选择已安装配置或指定 .mobileprovision 文件；不会回退到 App 内嵌描述文件。"
        }
        guard profile.expires > Date(), fileManager.fileExists(atPath: profile.filename) else {
            return "联软应用的外部描述文件已过期或不存在，请重新选择。"
        }
        guard LeagsoftEntitlementPolicy.values(from: profile) != nil else {
            return "无法从外部描述文件读取有效 Team ID，不能生成联软应用的钥匙串访问组。"
        }
        return nil
    }

    var leagsoftGroupValues: (appGroups: [String], keychainGroups: [String], teamID: String)? {
        guard leagsoftValidationMessage == nil, let profile = selectedProvisioningProfile else { return nil }
        return LeagsoftEntitlementPolicy.values(from: profile)
    }

    func finalGroupSourceTitle(for kind: AccessGroupKind) -> String {
        if isLeagsoftApp { return kind == .appGroups ? "外部描述文件（固定）" : "联软规则（Team ID）" }
        return groupSelection(for: kind).source.title
    }

    @objc func leagsoftAppChanged(_ sender: NSButton) {
        guard signingControlsEnabled else { return }
        // Finish any manual edit before replacing the fields; custom drafts stay in their own selections.
        window?.makeFirstResponder(nil)
        isLeagsoftApp = sender.state == .on
        rebuildEntitlementInspectorContent()
    }

    func makeFinalGroupsRow(kind: AccessGroupKind, previousValue: String?) -> NSStackView {
        if isLeagsoftApp { return makeLeagsoftGroupsRow(kind: kind) }
        var selection = groupSelection(for: kind)
        if selection.source == .custom, !selection.userEdited {
            selection.source = defaultFinalEntitlementSource()
        }
        // A pending inspection must not change this row's selection or erase its values.
        let isLoading: Bool
        if case .loading? = snapshot(for: selection.source)?.status { isLoading = true }
        else { isLoading = false }
        if !isLoading, !selection.userEdited, selection.source != .custom, valuesForFinalSource(selection.source) == nil {
            selection.source = defaultFinalEntitlementSource()
        }
        setGroupSelection(selection, for: kind)

        let popup = NSPopUpButton(frame: .zero, pullsDown: false)
        popup.translatesAutoresizingMaskIntoConstraints = false
        popup.autoenablesItems = false
        popup.tag = kind.rawValue
        popup.target = self
        popup.action = #selector(groupSourceChanged(_:))
        popup.setAccessibilityLabel("\(kind.title) 的最终来源")
        for source in FinalEntitlementSource.allCases {
            popup.addItem(withTitle: source.title)
            popup.lastItem?.tag = source.rawValue
            popup.lastItem?.isEnabled = source == .custom || valuesForFinalSource(source) != nil
            if let snapshot = snapshot(for: source) {
                popup.lastItem?.toolTip = [snapshot.sourceDescription, snapshot.sourcePath].compactMap { $0 }.joined(separator: "\n")
            }
        }
        popup.selectItem(withTag: selection.source.rawValue)
        popup.widthAnchor.constraint(equalToConstant: 180).isActive = true

        let text: String
        if selection.source == .custom { text = selection.customValue ?? previousValue ?? "" }
        else if isLoading { text = previousValue ?? "" }
        else if let values = valuesForFinalSource(selection.source) {
            text = (kind == .appGroups ? values.appGroups : values.keychainGroups).joined(separator: ", ")
        } else { text = "" }
        let field = NSTextField(string: text)
        field.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        field.placeholderString = kind == .appGroups ? "例如 group.com.example.app" : "例如 TEAMID.com.example.shared"
        field.setAccessibilityLabel("\(kind.title) 的最终签名值")
        field.toolTip = "多个组用英文逗号分隔；留空表示不设置该项。手动编辑只更改此项的来源。"
        field.delegate = self
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let label = uiLabel(kind.title, size: 11, secondary: true)
        label.widthAnchor.constraint(equalToConstant: 116).isActive = true
        if kind == .appGroups {
            appGroupsSourcePopup = popup
            finalAppGroupsField = field
        } else {
            keychainGroupsSourcePopup = popup
            finalKeychainGroupsField = field
        }
        return horizontalStack(views: [label, popup, field], spacing: 10)
    }

    func makeLeagsoftGroupsRow(kind: AccessGroupKind) -> NSStackView {
        let popup = NSPopUpButton(frame: .zero, pullsDown: false)
        popup.addItem(withTitle: finalGroupSourceTitle(for: kind))
        popup.widthAnchor.constraint(equalToConstant: 180).isActive = true
        popup.setAccessibilityLabel("\(kind.title) 的最终来源")
        let values = leagsoftGroupValues
        let groups = kind == .appGroups ? values?.appGroups : values?.keychainGroups
        let field = NSTextField(wrappingLabelWithString: groups?.joined(separator: "\n") ?? "")
        field.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        field.maximumNumberOfLines = 0
        field.isEditable = false
        field.isSelectable = true
        if groups?.isEmpty != false {
            field.stringValue = values == nil ? "请先选择外部描述文件" : "未设置 App Groups（签名时不设置此项）"
            field.textColor = .secondaryLabelColor
        }
        field.setAccessibilityLabel("\(kind.title) 的最终签名值")
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let sourcePath = selectedProvisioningProfile?.filename ?? "尚未选择外部描述文件"
        let tooltip = "联软应用固定规则；取消勾选后可自行选择或编辑。\n\(sourcePath)\n\(groups?.joined(separator: "\n") ?? "")"
        popup.toolTip = tooltip
        field.toolTip = tooltip
        let label = uiLabel(kind.title, size: 11, secondary: true)
        label.widthAnchor.constraint(equalToConstant: 116).isActive = true
        for control in [label, popup, field] { control.translatesAutoresizingMaskIntoConstraints = false }
        if kind == .appGroups {
            appGroupsSourcePopup = popup
            finalAppGroupsField = field
        } else {
            keychainGroupsSourcePopup = popup
            finalKeychainGroupsField = field
        }
        let row = horizontalStack(views: [label, popup, field], spacing: 10)
        field.widthAnchor.constraint(equalTo: row.widthAnchor, constant: -316).isActive = true
        return row
    }

    /// Attaching a permission file makes it available to both rows, without replacing explicit choices.
    func selectEntitlementsFile(_ path: String) {
        guard OfflineNetworkPolicy.isLocalPath(path) else { return }
        entitlementFilePath = path
        for kind in AccessGroupKind.allCases {
            var selection = groupSelection(for: kind)
            if !isLeagsoftApp, !selection.userEdited {
                selection.source = .entitlementsFile
                setGroupSelection(selection, for: kind)
            }
        }
        scheduleEntitlementInspection()
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
            selectEntitlementsFile(filename.path)
        }
    }

    @objc func clearEntitlementsFile(_ sender: Any?) {
        entitlementFilePath = nil
        inspectedEntitlementsFile = nil
        for kind in AccessGroupKind.allCases {
            var selection = groupSelection(for: kind)
            if selection.source == .entitlementsFile {
                selection.source = defaultFinalEntitlementSource()
                setGroupSelection(selection, for: kind)
            }
        }
        scheduleEntitlementInspection()
    }

    @objc func groupSourceChanged(_ sender: NSPopUpButton) {
        guard signingControlsEnabled, !isLeagsoftApp,
              let kind = AccessGroupKind(rawValue: sender.tag),
              let source = FinalEntitlementSource(rawValue: sender.selectedTag()) else { return }
        var selection = groupSelection(for: kind)
        if source == .custom, selection.customValue == nil {
            selection.customValue = (kind == .appGroups ? finalAppGroupsField : finalKeychainGroupsField)?.stringValue ?? ""
        }
        selection.source = source
        selection.userEdited = true
        setGroupSelection(selection, for: kind)
        rebuildEntitlementInspectorContent()
    }

    func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        if field === InputFileText {
            if SigningFilePath.normalize(field.stringValue) != inspectedInputPath {
                inspectedApplicationMetadata = nil
                updateApplicationMetadataDisplay(status: "路径已变更，结束输入或点击顶部刷新。")
            }
            updateSigningReadiness()
        } else if field === finalAppGroupsField || field === finalKeychainGroupsField {
            guard signingControlsEnabled, !isLeagsoftApp else { return }
            let kind: AccessGroupKind = field === finalAppGroupsField ? .appGroups : .keychainGroups
            var selection = groupSelection(for: kind)
            selection.source = .custom
            selection.userEdited = true
            selection.customValue = field.stringValue
            setGroupSelection(selection, for: kind)
            let popup = kind == .appGroups ? appGroupsSourcePopup : keychainGroupsSourcePopup
            popup?.selectItem(withTag: FinalEntitlementSource.custom.rawValue)
            updateEntitlementWarning()
        } else if field === profilePathField || field === certificatePathField || field === entitlementFilePathLabel {
            StartButton.isEnabled = false
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
        guard profileReadError == nil else { return nil }
        if let profile = selectedProvisioningProfile {
            return snapshot(from: profile, sourceName: "本次签名描述文件")
        }
        if !isLeagsoftApp, profileInputSource == .existing, selectedProvisioningProfile == nil {
            guard var embedded = embeddedProfileSnapshot() else { return nil }
            embedded.sourceName = "本次签名描述文件"
            embedded.sourceDescription = "使用 App 内嵌描述文件\nEntitlements 授权范围"
            return embedded
        }
        return nil
    }

    func embeddedProfileSnapshot() -> EntitlementSnapshot? {
        if let snapshot = inspectedEmbeddedEntitlements { return snapshot }
        return inspectedEmbeddedProfile.map { snapshot(from: $0, sourceName: "App 内嵌描述文件") }
    }

    func entitlementComparisonReference() -> (source: FinalEntitlementSource, snapshot: EntitlementSnapshot)? {
        if let snapshot = selectedProfileSnapshot(), snapshot.isAvailable { return (.provisioningProfile, snapshot) }
        if let snapshot = embeddedProfileSnapshot(), snapshot.isAvailable { return (.embeddedProfile, snapshot) }
        return nil
    }

    func snapshot(from profile: ProvisioningProfile, sourceName: String) -> EntitlementSnapshot {
        EntitlementSnapshot(
            sourceName: sourceName,
            appGroups: groups(named: "com.apple.security.application-groups", in: profile.entitlements),
            keychainGroups: groups(named: "keychain-access-groups", in: profile.entitlements),
            applicationIdentifier: profile.entitlements["application-identifier"] as? String,
            teamID: profile.teamID,
            status: .available,
            sourcePath: profile.filename,
            sourceDescription: "Entitlements 授权范围\n\(profile.filename.lastPathComponent)",
            isAuthorizationScope: true
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
        if isLeagsoftApp { return leagsoftGroupValues?.appGroups ?? [] }
        return splitGroupList(finalAppGroupsField?.stringValue ?? "")
    }

    func currentFinalKeychainGroups() -> [String] {
        if isLeagsoftApp { return leagsoftGroupValues?.keychainGroups ?? [] }
        return splitGroupList(finalKeychainGroupsField?.stringValue ?? "")
    }

    func valuesForFinalSource(_ source: FinalEntitlementSource) -> (appGroups: [String], keychainGroups: [String])? {
        let teamID = selectedProfileSnapshot()?.teamID ?? inspectedOriginalEntitlements?.teamID ?? inspectedEntitlementsFile?.teamID
        if source == .custom { return (currentFinalAppGroups(), currentFinalKeychainGroups()) }
        let snapshot = snapshot(for: source)

        guard let snapshot, snapshot.isAvailable else { return nil }
        return (
            expandedGroups(snapshot.appGroups, teamID: snapshot.teamID ?? teamID),
            expandedGroups(snapshot.keychainGroups, teamID: snapshot.teamID ?? teamID)
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
        if let message = leagsoftValidationMessage {
            label.stringValue = message
            label.textColor = .systemOrange
            label.toolTip = message
            return
        }
        let profile = selectedProfileSnapshot()
        let snapshots = [inspectedOriginalEntitlements, embeddedProfileSnapshot(), inspectedEntitlementsFile].compactMap { $0 }
        if snapshots.contains(where: { if case .loading = $0.status { return true }; return false }) {
            label.stringValue = "正在读取 Mach-O 签名权限与描述文件，请稍候…"
            label.textColor = .secondaryLabelColor
            return
        }
        var warnings: [String] = []
        var unauthorized = false
        if let profile, profile.isAvailable {
            let allowedApp = expandedGroups(profile.appGroups, teamID: profile.teamID)
            let allowedKeychain = expandedGroups(profile.keychainGroups, teamID: profile.teamID)
            for snapshot in snapshots where snapshot.isAvailable {
                let app = expandedGroups(snapshot.appGroups, teamID: snapshot.teamID ?? profile.teamID)
                let keychain = expandedGroups(snapshot.keychainGroups, teamID: snapshot.teamID ?? profile.teamID)
                var differing: [String] = []
                if !setsEqual(app, allowedApp) { differing.append("App Groups") }
                if !setsEqual(keychain, allowedKeychain) { differing.append("钥匙串访问组") }
                if !differing.isEmpty {
                    let isAllowed = groupsAreAuthorized(app, by: allowedApp) && groupsAreAuthorized(keychain, by: allowedKeychain)
                    let suffix = snapshot.isAuthorizationScope ? "授权范围不同" : (isAllowed ? "值不同，但在授权范围内" : "包含未授权值")
                    warnings.append("\(snapshot.sourceName)的\(differing.joined(separator: "、"))：\(suffix)（对照本次签名描述文件）")
                    unauthorized = unauthorized || (!snapshot.isAuthorizationScope && !isAllowed)
                }
            }
            let finalApp = expandedGroups(currentFinalAppGroups(), teamID: profile.teamID)
            let finalKeychain = expandedGroups(currentFinalKeychainGroups(), teamID: profile.teamID)
            if !groupsAreAuthorized(finalApp, by: allowedApp) {
                warnings.append("最终 App Groups 包含本次签名描述文件未授权的值")
                unauthorized = true
            }
            if !groupsAreAuthorized(finalKeychain, by: allowedKeychain) {
                warnings.append("最终钥匙串访问组包含本次签名描述文件未授权的值")
                unauthorized = true
            }
        }
        if (currentFinalAppGroups() + currentFinalKeychainGroups()).contains(where: { $0.contains("*") }) {
            warnings.append("最终组值含 *；描述文件中的通配授权范围不等于应用的实际组名，请选择 Mach-O 或填写具体组名")
        }
        if !warnings.isEmpty {
            label.stringValue = "⚠ " + warnings.joined(separator: "；") + "。请核对下方最终签名值。"
            label.textColor = unauthorized ? .systemRed : .systemOrange
        } else if profile?.isAvailable != true {
            label.stringValue = "尚无可读取的本次签名描述文件，暂时无法验证最终权限是否获授权。"
            label.textColor = .systemOrange
        } else if let original = inspectedOriginalEntitlements, !original.isAvailable {
            label.stringValue = "Mach-O 签名权限不可读取（\(original.statusText)）；可使用描述文件或权限文件设置最终值。"
            label.textColor = .systemOrange
        } else if snapshots.contains(where: { !$0.isAvailable }) {
            label.stringValue = "部分来源缺失或读取失败；已读取来源与本次签名描述文件一致。"
            label.textColor = .systemOrange
        } else if snapshots.contains(where: { $0.isAvailable }) {
            label.stringValue = "✓ 已读取来源与本次签名描述文件一致，最终组值在授权范围内。"
            label.textColor = .systemGreen
        } else {
            label.stringValue = "已读取本次签名描述文件。选择应用后，将对比 Mach-O 签名中的权限。"
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
        let inputFile = SigningFilePath.normalize(InputFileText.stringValue)
        inspectedInputPath = inputFile
        let entitlementsFile = entitlementFilePath
        let selectedProfile = selectedProvisioningProfile

        inspectedApplicationMetadata = nil
        updateApplicationMetadataDisplay(status: inputFile.isEmpty ? "未选择应用" : "正在读取应用 Info.plist…")

        inspectedEmbeddedProfile = nil
        inspectedEmbeddedEntitlements = EntitlementSnapshot(sourceName: "App 内嵌描述文件", appGroups: [], keychainGroups: [],
            applicationIdentifier: nil, teamID: nil, status: .loading, isAuthorizationScope: true)
        inspectedOriginalEntitlements = EntitlementSnapshot(
            sourceName: "Mach-O 签名权限",
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

        guard !inputFile.isEmpty, OfflineNetworkPolicy.isLocalPath(inputFile) else {
            updateApplicationMetadataDisplay(status: inputFile.isEmpty ? "未选择应用" : "仅支持本地应用文件")
            inspectedOriginalEntitlements = nil
            inspectedEmbeddedProfile = nil
            inspectedEmbeddedEntitlements = nil
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
                guard generation == self.entitlementInspectionGeneration,
                      inputFile == SigningFilePath.normalize(self.InputFileText.stringValue) else { return }
                self.inspectedApplicationMetadata = result.metadata
                self.updateApplicationMetadataDisplay(status: result.metadata == nil ? "无法读取应用 Info.plist，请检查文件后刷新。" : "已读取当前值；输入框留空则保留。")
                self.inspectedOriginalEntitlements = result.original
                self.inspectedEmbeddedProfile = result.embeddedProfile
                self.inspectedEmbeddedEntitlements = result.embeddedEntitlements
                self.inspectedEntitlementsFile = fileResult
                self.rebuildEntitlementInspectorContent()
            }
        }
    }

    /// Read the executable itself, not the provisioning profile or _CodeSignature/CodeResources.
    /// codesign decodes the entitlement blob in LC_CODE_SIGNATURE (including DER representation).
    func inspectOriginalInput(path: String, profileTeamID: String?) -> (original: EntitlementSnapshot?, embeddedProfile: ProvisioningProfile?, embeddedEntitlements: EntitlementSnapshot?, metadata: ApplicationMetadata?) {
        var temporaryRoot: String?
        defer {
            if let temporaryRoot { try? fileManager.removeItem(atPath: temporaryRoot) }
        }
        guard let appBundlePath = locateAppBundle(inputPath: path, temporaryRoot: &temporaryRoot) else {
            return (EntitlementSnapshot(sourceName: "Mach-O 签名权限", appGroups: [], keychainGroups: [],
                applicationIdentifier: nil, teamID: nil, status: .unavailable("无法定位 App Bundle"), sourcePath: path), nil, nil, nil)
        }
        // Keep the original archive/member location: the extracted temporary files are deleted after inspection.
        func originalLocation(_ extractedPath: String) -> String {
            guard let temporaryRoot else { return extractedPath }
            let member = String(extractedPath.dropFirst(temporaryRoot.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            return "\(path)!/\(member)"
        }
        // Reuse this extraction; Info.plist is independent of the Mach-O signature and profile.
        let infoPath = appBundlePath.stringByAppendingPathComponent("Info.plist")
        let metadata = ApplicationMetadata.read(at: infoPath, sourcePath: originalLocation(infoPath))
        let profilePath = appBundlePath.stringByAppendingPathComponent("embedded.mobileprovision")
        let hasProfile = fileManager.fileExists(atPath: profilePath)
        let embeddedProfile = hasProfile ? ProvisioningProfile(filename: profilePath) : nil
        var embedded = embeddedProfile.map { snapshot(from: $0, sourceName: "App 内嵌描述文件") }
            ?? EntitlementSnapshot(sourceName: "App 内嵌描述文件", appGroups: [], keychainGroups: [],
                applicationIdentifier: nil, teamID: nil, status: .unavailable(hasProfile ? "描述文件解析失败" : "未内嵌描述文件"), isAuthorizationScope: true)
        embedded.sourcePath = originalLocation(profilePath)
        embedded.sourceDescription = "embedded.mobileprovision\nEntitlements 授权范围"

        guard let executablePath = mainExecutablePath(in: appBundlePath) else {
            return (EntitlementSnapshot(sourceName: "Mach-O 签名权限", appGroups: [], keychainGroups: [],
                applicationIdentifier: nil, teamID: nil, status: .unavailable("无法定位主 Mach-O"),
                sourcePath: originalLocation(appBundlePath), sourceDescription: "Info.plist → CFBundleExecutable"), embeddedProfile, embedded, metadata)
        }
        let read = readMachOEntitlements(at: executablePath)
        let entitlements = read.values
        let teamID = entitlements?["com.apple.developer.team-identifier"] as? String
            ?? (entitlements?["application-identifier"] as? String).flatMap { $0.split(separator: ".", maxSplits: 1).first.map(String.init) }
        let original = EntitlementSnapshot(sourceName: "Mach-O 签名权限",
            appGroups: entitlements.map { groups(named: "com.apple.security.application-groups", in: $0) } ?? [],
            keychainGroups: entitlements.map { groups(named: "keychain-access-groups", in: $0) } ?? [],
            applicationIdentifier: entitlements?["application-identifier"] as? String, teamID: teamID,
            status: read.status,
            sourcePath: originalLocation(executablePath),
            sourceDescription: "LC_CODE_SIGNATURE\nEntitlements（XML / DER）\n\(executablePath.lastPathComponent)")
        return (original, embeddedProfile, embedded, metadata)
    }

    func mainExecutablePath(in bundlePath: String) -> String? {
        guard let info = NSDictionary(contentsOfFile: bundlePath.stringByAppendingPathComponent("Info.plist")),
              let name = info["CFBundleExecutable"] as? String, !name.isEmpty,
              name == (name as NSString).lastPathComponent, name != ".", name != ".." else { return nil }
        let path = bundlePath.stringByAppendingPathComponent(name)
        return fileManager.fileExists(atPath: path) ? path : nil
    }

    func locateAppBundle(inputPath: String, temporaryRoot: inout String?) -> String? {
        guard OfflineNetworkPolicy.isLocalPath(inputPath) else { return nil }
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
        guard OfflineNetworkPolicy.isLocalPath(path), let data = fileManager.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let entitlements = plist as? [String: AnyObject] else {
            return EntitlementSnapshot(
                sourceName: "Entitlements 文件",
                appGroups: [],
                keychainGroups: [],
                applicationIdentifier: nil,
                teamID: teamID,
                status: .unavailable("无法解析 Plist"),
                sourcePath: path, sourceDescription: "独立 Plist 权限文件\n\(path.lastPathComponent)"
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
            status: .available,
            sourcePath: path, sourceDescription: "独立 Plist 权限文件\n\(path.lastPathComponent)"
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
        guard OfflineNetworkPolicy.isLocalPath(path), let data = fileManager.contents(atPath: path),
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
        appGroups: [String],
        keychainGroups: [String],
        newApplicationID: String,
        useLeagsoftPolicy: Bool = false
    ) -> [String: AnyObject]? {
        let originalEntitlements = signedEntitlements(forBundle: appBundlePath)
        let fileEntitlements = entitlementsFilePath.flatMap { entitlementsDictionary(fromFile: $0) }

        // Group sources only control their own arrays, never the rest of the entitlement dictionary.
        let base = profile?.entitlements ?? fileEntitlements ?? originalEntitlements
        guard base != nil || !appGroups.isEmpty || !keychainGroups.isEmpty else { return nil }
        var entitlements = base ?? [:]

        let applicationIdentifier = entitlements["application-identifier"] as? String
        let teamID = profile?.teamID ?? applicationIdentifier.flatMap { identifier in
            identifier.split(separator: ".", maxSplits: 1).first.map(String.init)
        }
        let signingAppGroups: [String]
        let signingKeychainGroups: [String]
        if useLeagsoftPolicy {
            guard let profile, let values = LeagsoftEntitlementPolicy.values(from: profile) else { return nil }
            signingAppGroups = values.appGroups
            signingKeychainGroups = values.keychainGroups
        } else {
            signingAppGroups = appGroups
            signingKeychainGroups = keychainGroups
        }
        let expandedAppGroups = signingAppGroups.map { expandEntitlementVariables($0, teamID: teamID) }
        let expandedKeychainGroups = signingKeychainGroups.map { expandEntitlementVariables($0, teamID: teamID) }

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
            "使用 App 内嵌描述文件"
        ])
        ProvisioningProfilesPopup.menu?.addItem(.separator())
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
        let securityResult = Process().execute(securityPath, workingDirectory: nil, arguments: ["find-identity","-v","-p","codesigning"])
        signingIdentities = SigningIdentity.parse(securityResult.output, certificates: SigningCertificateFile.keychainCertificates())
        return signingIdentities.map { $0.displayName }
    }
    
    @objc func showCodesignCertsErrorAlert() {
        let alert = NSAlert()
        alert.messageText = "未找到可用签名证书"
        alert.informativeText = "请导入包含私钥的 P12 / PFX，或在钥匙串中准备有效的签名身份。本应用不会下载或在线修复证书。"
        alert.runModal()
    }

    @objc func populateCodesigningCerts() {
        let previousFingerprint = currentSigningIdentity?.fingerprint
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

        if let previousFingerprint {
            if let identity = signingIdentities.first(where: { $0.fingerprint == previousFingerprint }) {
                CodesigningCertsPopup.selectItem(withTitle: identity.displayName)
            } else { CodesigningCertsPopup.selectItem(at: -1) }
        }
        if let fingerprint = importedCertificateFingerprint {
            importedCertificateName = signingIdentities.first(where: { $0.fingerprint == fingerprint })?.displayName
        }
        updateSigningReadiness()

    }

    func checkProfileID(_ profile: ProvisioningProfile?, inspect: Bool = true){
        profileReadError = nil
        unreadableProfilePath = nil
        defer { updateProfileDetails() }
        if let profile = profile {
            self.profileFilename = profile.filename
            self.selectedProvisioningProfile = profile
            setStatus("已选择描述文件：\(profile.name)")
            if profile.expires.timeIntervalSince1970 < Date().timeIntervalSince1970 {
                if profileInputSource == .file {
                    importedProvisioningProfile = nil
                } else {
                    ProvisioningProfilesPopup.selectItem(at: 0)
                }
                checkProfileID(nil)
                setStatus("描述文件已过期")
                return
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
            if inspect { scheduleEntitlementInspection() }
        } else {
            self.profileFilename = nil
            self.selectedProvisioningProfile = nil
            if NewApplicationIDTextField.isEnabled == false {
                NewApplicationIDTextField.isEnabled = true
                NewApplicationIDTextField.stringValue = ""
            }
            if inspect {
                scheduleEntitlementInspection()
                rebuildEntitlementInspectorContent()
            }
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
                NewApplicationIDTextField.isEnabled = ReEnableNewApplicationID
                NewApplicationIDTextField.stringValue = PreviousNewApplicationID
                updateSigningReadiness()
                appDisplayName.isEnabled = true
                appGroupsSourcePopup?.isEnabled = !isLeagsoftApp
                keychainGroupsSourcePopup?.isEnabled = !isLeagsoftApp
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
                appGroupsSourcePopup?.isEnabled = false
                keychainGroupsSourcePopup?.isEnabled = false
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

        var arguments = ["-f", "-s", certificate, "--generate-entitlement-der", "--timestamp=none"]
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
        guard let executablePath = mainExecutablePath(in: bundlePath) else { return nil }
        return readMachOEntitlements(at: executablePath).values
    }

    func readMachOEntitlements(at executablePath: String) -> (values: [String: AnyObject]?, status: EntitlementSnapshotStatus) {
        let task = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-d", "--entitlements", "-", "--xml", executablePath])
        guard task.status == 0 else {
            Log.write("Unable to read Mach-O entitlements from \(executablePath): \(task.output)")
            return (nil, .unavailable("未签名或签名区不可读"))
        }
        if task.output.contains("invalid entitlements blob") {
            return (nil, .unavailable("签名权限数据无效"))
        }
        guard let values = plistDictionary(fromCodesignOutput: task.output) else {
            return (nil, .unavailable("签名存在，无 Entitlements"))
        }
        return (values, .available)
    }

    func formattedAccessGroups(_ groups: [String]) -> String {
        if groups.isEmpty {
            return "(none)"
        }

        return groups.map { "  \($0)" }.joined(separator: "\n")
    }

    @objc func startSigning() {
        guard validateSigningInputs() else { return }
        let inputFile = SigningFilePath.normalize(InputFileText.stringValue)
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
            guard OfflineNetworkPolicy.isLocalPath(outputFile!) else {
                showSigningFileError("仅支持导出到本地", detail: "禁止写入网络路径。请选择本地目录。")
                outputFile = nil
                return
            }
            controlsEnabled(false)
            Thread.detachNewThreadSelector(#selector(self.signingThread), toTarget: self, with: nil)
        }
    }
    
    @objc func signingThread(){
        
        
        //MARK: Set up variables
        var warnings = 0
        var inputFile : String = ""
        var signingCertificate : String?
        var signingCertificateData: Data?
        var certificateFileRequired = false
        var certificateFileSnapshot: (path: String, digest: String)?
        var provisioningFile: String?
        var newApplicationID : String = ""
        var newDisplayName : String = ""
        var newShortVersion : String = ""
        var newVersion : String = ""
        var appGroupsSource = FinalEntitlementSource.provisioningProfile.title
        var keychainGroupsSource = FinalEntitlementSource.provisioningProfile.title
        var useLeagsoftPolicy = false
        var finalAppGroups: [String] = []
        var finalKeychainGroups: [String] = []
        var entitlementsFilePath: String?

        DispatchQueue.main.sync {
            inputFile = SigningFilePath.normalize(self.InputFileText.stringValue)
            signingCertificate = self.currentSigningCertificateFingerprint
            signingCertificateData = self.currentSigningIdentity?.certificateData
            certificateFileRequired = self.certificateInputSource == .file
            if let path = self.certificateFilePath, let digest = self.importedCertificateFileDigest {
                certificateFileSnapshot = (path, digest)
            }
            provisioningFile = self.profileFilename
            newApplicationID = self.NewApplicationIDTextField.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newDisplayName = self.appDisplayName.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newShortVersion = self.appShortVersion.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            newVersion = self.appVersion.stringValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            shouldCheckPlugins = ignorePluginsCheckbox.state == .off
            shouldSkipGetTaskAllow = noGetTaskAllowCheckbox.state == .on
            appGroupsSource = self.finalGroupSourceTitle(for: .appGroups)
            keychainGroupsSource = self.finalGroupSourceTitle(for: .keychainGroups)
            useLeagsoftPolicy = self.isLeagsoftApp
            finalAppGroups = self.currentFinalAppGroups()
            finalKeychainGroups = self.currentFinalKeychainGroups()
            entitlementsFilePath = self.entitlementFilePath
        }

        var eggCount: Int = 0
        var continueSigning: Bool? = nil
        
        //MARK: Sanity checks
        
        // Check signing certificate selection
        if signingCertificate == nil {
            setStatus("No signing certificate selected")
            controlsEnabled(true)
            return
        }

        if certificateFileRequired {
            guard let snapshot = certificateFileSnapshot, OfflineNetworkPolicy.isLocalPath(snapshot.path),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: snapshot.path)),
                  SigningCertificateFile.fileDigest(data) == snapshot.digest else {
                setStatus("签名前复核失败：证书文件已变更，请刷新并重新导入")
                controlsEnabled(true)
                return
            }
        }
        
        // Check if input file exists
        var inputIsDirectory: ObjCBool = false
        if !OfflineNetworkPolicy.isLocalPath(inputFile) || !fileManager.fileExists(atPath: inputFile, isDirectory: &inputIsDirectory){
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
            controlsEnabled(true)
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
                    alert.messageText = "签名证书不可用"
                    alert.informativeText = "本地签名测试失败。请检查证书私钥与本地证书链；本应用不会调用在线修复。"
                    alert.runModal()
                    continueSigning = false
                    return
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
                    if var profile = ProvisioningProfile(filename: appBundleProvisioningFilePath) {
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

                if useLeagsoftPolicy {
                    guard provisioningFile != nil, let signingProfile,
                          LeagsoftEntitlementPolicy.values(from: signingProfile) != nil else {
                        setStatus("联软应用模式无法读取外部描述文件或 Team ID，已停止签名")
                        cleanup(tempFolder); return
                    }
                }
                guard let checkedProfile = signingProfile, let certificateData = signingCertificateData,
                      checkedProfile.expires > Date(), checkedProfile.developerCertificates.contains(certificateData) else {
                    setStatus("签名前复核失败：证书与当前描述文件不匹配或描述文件已失效，已停止签名")
                    cleanup(tempFolder); return
                }
                if let entitlements = entitlementsForSigning(
                    profile: signingProfile,
                    appBundlePath: appBundlePath,
                    bundleID: bundleID,
                    entitlementsFilePath: entitlementsFilePath,
                    appGroups: finalAppGroups,
                    keychainGroups: finalKeychainGroups,
                    newApplicationID: newApplicationID,
                    useLeagsoftPolicy: useLeagsoftPolicy
                ) {
                    if let data = try? PropertyListSerialization.data(
                        fromPropertyList: entitlements,
                        format: .xml,
                        options: 0
                    ) {
                        do {
                            try data.write(to: URL(fileURLWithPath: entitlementsPlist), options: .atomic)
                            Log.write("Using final App Groups (\(appGroupsSource)):\n\(formattedAccessGroups(groups(named: "com.apple.security.application-groups", in: entitlements)))")
                            Log.write("Using final Keychain Access Groups (\(keychainGroupsSource)):\n\(formattedAccessGroups(groups(named: "keychain-access-groups", in: entitlements)))")
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
        guard signingControlsEnabled, profileInputSource == .existing else { return }
        applyProfileInputSelection()
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
        updateSigningInputSources()
    }
    
    @IBAction func doSign(_ sender: NSButton) {
        window?.makeFirstResponder(self)
        startSigning()
    }
    
    @IBAction func statusLabelClick(_ sender: NSButton) {
        if let outputFile = self.outputFile {
            if fileManager.fileExists(atPath: outputFile) {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: outputFile)])
            }
        }
    }
    
}
