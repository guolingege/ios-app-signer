import Cocoa
import Security
import Darwin
@testable import iOS_App_Signer

// Run via run-ui-smoke.sh. Certificate tests use only a temporary, non-default keychain.
setbuf(stdout, nil)
let builtApp = CommandLine.arguments[1]
let fixtures = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
let app = NSApplication.shared
app.appearance = NSAppearance(named: .aqua)
let nib = NSNib(nibNamed: "Application", bundle: Bundle(path: builtApp)!)!
var objects: NSArray?
precondition(nib.instantiate(withOwner: app, topLevelObjects: &objects))
func pump(_ seconds: TimeInterval = 0.5) { RunLoop.current.run(until: Date().addingTimeInterval(seconds)) }
pump()
let view = (app.delegate as! AppDelegate).mainView!
let window = view.window!
window.layoutIfNeeded()
precondition(view.entitlementInspectorConfigured && view.profilePathField != nil && view.certificatePathField != nil)
precondition(window.maxSize.height > 1000 && window.contentMinSize.width == 900)
precondition(view.entitlementWarningLabel?.textColor != NSColor.systemGreen)
func refreshButtons(in root: NSView) -> [NSButton] {
    let own = (root as? NSButton).map { $0.action == #selector(MainView.refreshSigningInputs(_:)) ? [$0] : [] } ?? []
    return own + root.subviews.flatMap { refreshButtons(in: $0) }
}
precondition(refreshButtons(in: view).count == 1)
precondition(refreshButtons(in: view.entitlementPanel!).isEmpty)
precondition(view.applicationMetadataLabels.count == 4 && view.inspectedApplicationMetadata == nil)
print("PASS: nib startup, resizable window, unavailable sources are not marked consistent")
func containsUpdateMenu(_ menu: NSMenu) -> Bool {
    menu.items.contains { item in
        item.action == NSSelectorFromString("checkForUpdates:") || item.title == "Check for Updates"
            || (item.submenu.map(containsUpdateMenu) ?? false)
    }
}
precondition(!containsUpdateMenu(app.mainMenu!))
precondition(!(app.delegate as! AppDelegate).responds(to: NSSelectorFromString("checkForUpdates:")))
precondition(NSClassFromString("iOS_App_Signer.UpdatesController") == nil)
precondition(Bundle(path: builtApp)!.url(forResource: "Updates", withExtension: "nib") == nil)
print("PASS: software update menu, action, controller and bundled update window removed")

func snapshot(_ name: String) throws {
    view.layoutSubtreeIfNeeded()
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { fatalError("No bitmap") }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    try bitmap.representation(using: .png, properties: [:])!.write(to: fixtures.appendingPathComponent(name + ".png"))
}
try snapshot("initial")
precondition(view.isLeagsoftApp && view.leagsoftAppCheckbox!.state == .on)
precondition(!view.appGroupsSourcePopup!.isEnabled && !view.keychainGroupsSourcePopup!.isEnabled)
precondition(!view.finalAppGroupsField!.isEditable && !view.finalKeychainGroupsField!.isEditable)
precondition(view.currentFinalAppGroups().isEmpty && view.currentFinalKeychainGroups().isEmpty)
precondition(view.leagsoftValidationMessage != nil && view.signingInputValidationMessage != nil)
func setLeagsoftApp(_ enabled: Bool) {
    view.leagsoftAppCheckbox!.state = enabled ? .on : .off
    view.leagsoftAppChanged(view.leagsoftAppCheckbox!)
}
setLeagsoftApp(false)
precondition(!view.isLeagsoftApp && view.leagsoftValidationMessage == nil)
print("PASS: Leagsoft mode checked by default, fixed fields read-only, missing external profile blocks signing, opt-out restores manual controls")
func selectCertificateSource(_ source: SigningInputSource) {
    view.certificateSourceControl!.selectedSegment = source.rawValue
    view.certificateSourceChanged(view.certificateSourceControl!)
}
func selectProfileSource(_ source: SigningInputSource) {
    view.profileSourceControl!.selectedSegment = source.rawValue
    view.profileSourceChanged(view.profileSourceControl!)
}
precondition(view.certificateInputSource == .existing && view.profileInputSource == .existing)
precondition(view.certificateFileRow!.isHidden && view.profileFileRow!.isHidden)
precondition(!view.certificatePathField!.isEnabled && !view.profilePathField!.isEnabled)
let existingCertificate = view.currentSigningCertificate
if let existingCertificate {
    precondition(view.certificateHintLabel!.stringValue.contains(existingCertificate))
    precondition(view.certificateHintLabel!.textColor == .secondaryLabelColor)
}
selectCertificateSource(.file)
precondition(view.certificateExistingRow!.isHidden && !view.certificateFileRow!.isHidden)
precondition(!view.CodesigningCertsPopup.isEnabled && view.certificatePathField!.isEnabled)
precondition(view.currentSigningCertificate == nil && view.signingInputValidationMessage != nil)
if let existingCertificate {
    view.finishCertificateImport(path: fixtures.appendingPathComponent("certificate.p12").path, names: [existingCertificate], certificates: [view.signingIdentities.first { $0.displayName == existingCertificate }!.certificateData!])
    precondition(view.currentSigningCertificate == existingCertificate)
    let otherCertificate = view.codesigningCerts.last!
    view.CodesigningCertsPopup.selectItem(withTitle: otherCertificate)
    precondition(view.currentSigningCertificate == existingCertificate) // Hidden list must not affect file mode.
    selectCertificateSource(.existing)
    precondition(view.currentSigningCertificate == otherCertificate)
    selectCertificateSource(.file)
    precondition(view.currentSigningCertificate == existingCertificate)
    view.CodesigningCertsPopup.selectItem(withTitle: existingCertificate)
}
view.finishCertificateImport(path: fixtures.appendingPathComponent("certificate.pem").path, names: ["Signer UI Import Fixture"])
precondition(view.certificateInputSource == .file && view.currentSigningCertificate == nil)
precondition(view.signingInputValidationMessage != nil) // Must not fall back to an unrelated keychain identity.
selectProfileSource(.file)
precondition(view.profileExistingRow!.isHidden && view.profilePathField!.isEnabled)
precondition(view.selectedProvisioningProfile == nil && view.profileFilename == nil)
try snapshot("file-sources-empty")
selectCertificateSource(.existing)
selectProfileSource(.existing)
precondition(view.currentSigningCertificate == existingCertificate)
precondition(!view.certificateExistingRow!.isHidden && !view.profileExistingRow!.isHidden)
print("PASS: mutually exclusive source controls, retained selections, no certificate fallback from file mode")
precondition(SigningFilePath.normalize(" \"/tmp/a b.p12\" \n") == "/tmp/a b.p12")
precondition(SigningFilePath.normalize("file:///tmp/a%20b.mobileprovision") == "/tmp/a b.mobileprovision")
precondition(SigningFilePath.normalize("~/file.p12") == NSHomeDirectory() + "/file.p12")
let board = NSPasteboard.withUniqueName()
board.writeObjects([fixtures.appendingPathComponent("certificate.p12") as NSURL])
precondition(SigningFilePath.paths(from: board).first == fixtures.appendingPathComponent("certificate.p12").path)
board.clearContents()
board.setString("\"/tmp/a b.mobileprovision\"", forType: .string)
precondition(SigningFilePath.paths(from: board) == ["/tmp/a b.mobileprovision"])
board.releaseGlobally()
print("PASS: Finder file URLs, pasted paths, spaces, quotes, tilde")

if let profile = view.provisioningProfiles.first(where: { $0.appID == "com.leagsoft.emm.standard" }) ?? view.provisioningProfiles.first {
    view.ProvisioningProfilesPopup.selectItem(at: 2 + view.provisioningProfiles.firstIndex(where: { $0.filename == profile.filename })!)
    view.chooseProvisioningProfile(view.ProvisioningProfilesPopup)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename)
    precondition(view.profilePathField!.stringValue.isEmpty) // List selection is not a file selection.
    selectProfileSource(.file)
    precondition(view.selectedProvisioningProfile == nil && view.selectedProfileSnapshot() == nil)
    if existingCertificate != nil { precondition(view.signingInputValidationMessage != nil) }
    let field = view.profilePathField!
    field.stringValue = "\"" + profile.filename + "\""
    view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: field))
    pump(0.7)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename)
    precondition(field.stringValue == profile.filename)
    precondition(view.finalAppGroupsSelection.source == .provisioningProfile && view.finalKeychainGroupsSelection.source == .provisioningProfile)
    precondition(view.currentFinalKeychainGroups() == view.valuesForFinalSource(.provisioningProfile)!.keychainGroups)
    precondition(view.profileInputSource == .file && !view.ProvisioningProfilesPopup.isEnabled)
    selectProfileSource(.existing)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename && !field.isEnabled)
    view.ProvisioningProfilesPopup.selectItem(at: 0)
    view.chooseProvisioningProfile(view.ProvisioningProfilesPopup)
    precondition(view.selectedProvisioningProfile == nil && view.profileFilename == nil)
    selectProfileSource(.file)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename && field.isEnabled)
    selectProfileSource(.existing)
    view.fileDropped(profile.filename)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename && view.profileInputSource == .file)
    try snapshot("file-profile")
    print("PASS: profile source isolation, preserved file/list selection, paste/drop auto-selection and default groups")
} else { print("SKIP: no installed profiles available for profile-paste integration check") }

let entitlementURL = fixtures.appendingPathComponent("custom.entitlements")
let plist: [String: Any] = [
    "application-identifier": "OTHERTEAM.com.example.app",
    "aps-environment": "development",
    "com.apple.security.application-groups": ["group.com.example.shared.with.a.long.identifier.to.test.wrapping", "group.com.example.second"],
    "keychain-access-groups": ["OTHERTEAM.com.example.shared"]
]
try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: entitlementURL)
view.fileDropped(entitlementURL.path)
pump()
precondition(view.finalAppGroupsSelection.source == .entitlementsFile && view.finalKeychainGroupsSelection.source == .entitlementsFile)
precondition(view.currentFinalKeychainGroups() == ["OTHERTEAM.com.example.shared"])
for popup in [view.appGroupsSourcePopup!, view.keychainGroupsSourcePopup!] {
    precondition(popup.itemArray.first(where: { $0.tag == FinalEntitlementSource.originalApp.rawValue })!.isEnabled == false)
}
if view.selectedProvisioningProfile != nil { precondition(view.entitlementWarningLabel?.textColor == NSColor.systemRed) }
try snapshot("differences")
let editingField = view.finalKeychainGroupsField!
editingField.stringValue = "CUSTOMTEAM.com.example.manual"
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: editingField))
precondition(view.finalKeychainGroupsSelection.source == .custom && view.finalKeychainGroupsField === editingField)
precondition(view.finalAppGroupsSelection.source == .entitlementsFile)
view.rebuildEntitlementInspectorContent()
precondition(view.currentFinalKeychainGroups() == ["CUSTOMTEAM.com.example.manual"])
print("PASS: entitlement file, differences, unavailable source disabled, live custom editing and value preservation")

func selectGroupSource(_ kind: AccessGroupKind, _ source: FinalEntitlementSource) {
    let popup = kind == .appGroups ? view.appGroupsSourcePopup! : view.keychainGroupsSourcePopup!
    popup.selectItem(withTag: source.rawValue)
    view.groupSourceChanged(popup)
}
let originalAppGroups = ["group.com.example.original"]
let originalKeychainGroups = ["ORIGINALTEAM.com.example.original"]
view.inspectedOriginalEntitlements = EntitlementSnapshot(sourceName: "原 App Mach-O 签名", appGroups: originalAppGroups,
    keychainGroups: originalKeychainGroups, applicationIdentifier: "ORIGINALTEAM.com.example.app", teamID: "ORIGINALTEAM", status: .available)
view.rebuildEntitlementInspectorContent()
selectGroupSource(.appGroups, .originalApp)
precondition(view.currentFinalAppGroups() == originalAppGroups)
precondition(view.finalKeychainGroupsSelection.source == .custom)
precondition(view.currentFinalKeychainGroups() == ["CUSTOMTEAM.com.example.manual"])
selectGroupSource(.keychainGroups, .entitlementsFile)
precondition(view.currentFinalAppGroups() == originalAppGroups)
precondition(view.currentFinalKeychainGroups() == ["OTHERTEAM.com.example.shared"])
view.layoutSubtreeIfNeeded()
_ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
try snapshot("mixed-sources")

// The dictionary handed to codesign must contain both independent choices, not both arrays from one source.
view.shouldSkipGetTaskAllow = true
func signingEntitlements(profile: ProvisioningProfile? = nil, file: String? = entitlementURL.path) -> [String: AnyObject]? {
    view.entitlementsForSigning(profile: profile, appBundlePath: fixtures.appendingPathComponent("Unsigned.app").path,
        bundleID: "com.example.app", entitlementsFilePath: file, appGroups: view.currentFinalAppGroups(),
        keychainGroups: view.currentFinalKeychainGroups(), newApplicationID: "")
}
let mixed = signingEntitlements()!
precondition(mixed["com.apple.security.application-groups"] as? [String] == originalAppGroups)
precondition(mixed["keychain-access-groups"] as? [String] == ["OTHERTEAM.com.example.shared"])
precondition(mixed["aps-environment"] as? String == "development")
if let profile = view.selectedProvisioningProfile {
    let withProfile = signingEntitlements(profile: profile)!
    precondition(withProfile["com.apple.security.application-groups"] as? [String] == originalAppGroups)
    precondition(withProfile["keychain-access-groups"] as? [String] == ["OTHERTEAM.com.example.shared"])
    precondition(withProfile["application-identifier"] as? String == profile.entitlements["application-identifier"] as? String)
}
selectGroupSource(.appGroups, .entitlementsFile)
selectGroupSource(.keychainGroups, .originalApp)
precondition(view.currentFinalAppGroups() == plist["com.apple.security.application-groups"] as? [String])
precondition(view.currentFinalKeychainGroups() == originalKeychainGroups)
let reversed = signingEntitlements()!
precondition(reversed["com.apple.security.application-groups"] as? [String] == view.currentFinalAppGroups())
precondition(reversed["keychain-access-groups"] as? [String] == originalKeychainGroups)
let emptyAppField = view.finalAppGroupsField!
emptyAppField.stringValue = ""
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: emptyAppField))
let withoutAppGroup = signingEntitlements()!
precondition(withoutAppGroup["com.apple.security.application-groups"] == nil)
precondition(withoutAppGroup["keychain-access-groups"] as? [String] == originalKeychainGroups)

// Custom drafts, including intentional empty values, belong to their own row.
let appField = view.finalAppGroupsField!
appField.stringValue = "group.com.example.manual"
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: appField))
precondition(view.finalAppGroupsSelection.source == .custom && view.finalKeychainGroupsSelection.source == .originalApp)
selectGroupSource(.appGroups, .entitlementsFile)
selectGroupSource(.appGroups, .custom)
precondition(view.currentFinalAppGroups() == ["group.com.example.manual"])
precondition(view.currentFinalKeychainGroups() == originalKeychainGroups)
let keychainField = view.finalKeychainGroupsField!
keychainField.stringValue = ""
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: keychainField))
view.rebuildEntitlementInspectorContent()
let customOnly = signingEntitlements(file: nil)!
precondition(customOnly["com.apple.security.application-groups"] as? [String] == ["group.com.example.manual"])
precondition(customOnly["keychain-access-groups"] == nil)
selectGroupSource(.keychainGroups, .originalApp)
selectGroupSource(.keychainGroups, .custom)
precondition(view.currentFinalKeychainGroups().isEmpty)

selectGroupSource(.appGroups, .entitlementsFile)
let previousAppValue = view.currentFinalAppGroups()
let availableFile = view.inspectedEntitlementsFile!
view.inspectedEntitlementsFile = EntitlementSnapshot(sourceName: "Entitlements 文件", appGroups: [], keychainGroups: [],
    applicationIdentifier: nil, teamID: nil, status: .loading)
view.rebuildEntitlementInspectorContent()
precondition(view.finalAppGroupsSelection.source == .entitlementsFile && view.currentFinalAppGroups() == previousAppValue)
precondition(view.finalKeychainGroupsSelection.source == .custom && view.currentFinalKeychainGroups().isEmpty)
view.inspectedEntitlementsFile = availableFile
view.rebuildEntitlementInspectorContent()
view.clearEntitlementsFile(nil)
precondition(view.finalAppGroupsSelection.source != .entitlementsFile)
precondition(view.finalKeychainGroupsSelection.source == .custom && view.currentFinalKeychainGroups().isEmpty)
let appSourceBeforeAttach = view.finalAppGroupsSelection.source
view.fileDropped(entitlementURL.path)
pump()
precondition(view.finalAppGroupsSelection.source == appSourceBeforeAttach) // Adding a file must not override an explicit source.
precondition(view.finalKeychainGroupsSelection.source == .custom && view.currentFinalKeychainGroups().isEmpty)
print("PASS: independent group sources, mixed signing dictionary, per-row custom drafts/empty values, loading and file removal")

let doc = view.subviews.compactMap { $0 as? NSScrollView }.first!
window.setContentSize(NSSize(width: 900, height: 600))
view.layoutSubtreeIfNeeded()
precondition(doc.documentView!.frame.height > doc.contentView.frame.height)
precondition(view.finalKeychainGroupsField!.frame.width > 300)
precondition(view.entitlementPanel!.frame.width <= 900)
_ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
try snapshot("small-window")
view.signingControlsEnabled = false
view.setSigningInputControlsEnabled(false)
precondition(!view.profilePathField!.isEnabled && !view.certificatePathField!.isEnabled && !view.finalAppGroupsField!.isEnabled)
precondition(!view.appGroupsSourcePopup!.isEnabled && !view.keychainGroupsSourcePopup!.isEnabled)
precondition(!view.certificateSourceControl!.isEnabled && !view.profileSourceControl!.isEnabled)
precondition(!view.ProvisioningProfilesPopup.isEnabled && !view.CodesigningCertsPopup.isEnabled)
view.signingControlsEnabled = true
view.setSigningInputControlsEnabled(true)
precondition(view.profilePathField!.isEnabled == (view.profileInputSource == .file))
precondition(view.CodesigningCertsPopup.isEnabled == (view.certificateInputSource == .existing))
view.controlsEnabled(false)
precondition(!view.profileSourceControl!.isEnabled && !view.CodesigningCertsPopup.isEnabled)
view.controlsEnabled(true)
precondition(view.profileSourceControl!.isEnabled)
precondition(view.appGroupsSourcePopup!.isEnabled && view.keychainGroupsSourcePopup!.isEnabled)
precondition(view.ProvisioningProfilesPopup.isEnabled == (view.profileInputSource == .existing))
precondition(view.certificatePathField!.isEnabled == (view.certificateInputSource == .file))
print("PASS: minimum window width, scroll overflow, signing-time controls disabled")

// Exercise encrypted P12 import, wrong passwords and duplicates without touching the user's default keychain.
var testKeychain: SecKeychain?
let keychainPath = fixtures.appendingPathComponent("import-test.keychain-db").path
precondition(SecKeychainCreate(keychainPath, 12, "test-keypass", false, nil, &testKeychain) == errSecSuccess)
let keychain = testKeychain!
do {
    defer { SecKeychainDelete(keychain) }
    let data = try Data(contentsOf: fixtures.appendingPathComponent("certificate.p12"))
    let wrong = SigningCertificateFile.importData(data, filename: "certificate.p12", password: "wrong", keychain: keychain)
    precondition(wrong.status != errSecSuccess)
    let imported = SigningCertificateFile.importData(data, filename: "certificate.p12", password: "ui-test-pass", keychain: keychain)
    precondition(imported.status == errSecSuccess)
    precondition(imported.names.contains("Signer UI Import Fixture"))
    let duplicate = SigningCertificateFile.importData(data, filename: "certificate.p12", password: "ui-test-pass", keychain: keychain)
    precondition(duplicate.status == errSecSuccess || duplicate.status == errSecDuplicateItem)
    precondition(duplicate.names.contains("Signer UI Import Fixture"))
}
print("PASS: encrypted certificate import, wrong password and duplicate import in isolated keychain")

// Verify direct Mach-O extraction independently of the profile's authorization entitlements.
let signedFixture = view.inspectOriginalInput(path: fixtures.appendingPathComponent("Signed.app").path, profileTeamID: "WRONGTEAM")
let fixtureGroups = ["group.com.example.fixture"]
let fixtureKeychains = ["FIXTURETEAM.com.example.fixture", "FIXTURETEAM.com.example.shared"]
for name in ["Signed", "DEROnly", "XMLOnly"] {
    let bundle = fixtures.appendingPathComponent(name + ".app").path
    let result = view.inspectOriginalInput(path: bundle, profileTeamID: "WRONGTEAM")
    precondition(result.original!.isAvailable && result.original!.appGroups == fixtureGroups)
    precondition(result.original!.keychainGroups == fixtureKeychains && result.original!.teamID == "FIXTURETEAM")
    precondition(result.original!.sourcePath == bundle + "/Fixture")
    precondition(result.original!.sourceDescription!.contains("LC_CODE_SIGNATURE"))
    precondition(result.embeddedEntitlements!.keychainGroups == ["FIXTURETEAM.*"])
    precondition(result.embeddedEntitlements!.sourcePath == bundle + "/embedded.mobileprovision")
    precondition(result.embeddedEntitlements!.isAuthorizationScope && !result.original!.isAuthorizationScope)
    precondition(view.signedEntitlements(forBundle: bundle)!["keychain-access-groups"] as? [String] == fixtureKeychains)
}
let archiveFixture = view.inspectOriginalInput(path: fixtures.appendingPathComponent("Fixture.ipa").path, profileTeamID: nil)
let expectedMetadata = ["CFBundleIdentifier": "com.example.fixture", "CFBundleDisplayName": "原应用名称",
    "CFBundleShortVersionString": "5.15", "CFBundleVersion": "2026111701"]
precondition(signedFixture.metadata!.values == expectedMetadata)
precondition(archiveFixture.metadata!.values == expectedMetadata)
precondition(archiveFixture.metadata!.sourcePath.hasSuffix("Fixture.ipa!/Payload/Signed.app/Info.plist"))
let xcarchiveApplications = fixtures.appendingPathComponent("Metadata.xcarchive/Products/Applications")
try FileManager.default.createDirectory(at: xcarchiveApplications, withIntermediateDirectories: true)
try FileManager.default.copyItem(at: fixtures.appendingPathComponent("Signed.app"), to: xcarchiveApplications.appendingPathComponent("Fixture.app"))
precondition(view.inspectOriginalInput(path: fixtures.appendingPathComponent("Metadata.xcarchive").path, profileTeamID: nil).metadata!.values == expectedMetadata)
let fallbackInfo = fixtures.appendingPathComponent("fallback-info.plist")
try PropertyListSerialization.data(fromPropertyList: ["CFBundleName": "备用名称", "CFBundleVersion": 17], format: .binary, options: 0).write(to: fallbackInfo)
let fallbackMetadata = ApplicationMetadata.read(at: fallbackInfo.path, sourcePath: fallbackInfo.path)!
precondition(fallbackMetadata.values["CFBundleDisplayName"] == "备用名称" && fallbackMetadata.values["CFBundleVersion"] == "17")
precondition(archiveFixture.original!.keychainGroups == fixtureKeychains)
precondition(archiveFixture.original!.sourcePath == fixtures.appendingPathComponent("Fixture.ipa").path + "!/Payload/Signed.app/Fixture")
precondition(archiveFixture.embeddedEntitlements!.sourcePath == fixtures.appendingPathComponent("Fixture.ipa").path + "!/Payload/Signed.app/embedded.mobileprovision")
let noEntitlements = view.inspectOriginalInput(path: fixtures.appendingPathComponent("NoEntitlements.app").path, profileTeamID: nil)
precondition(!noEntitlements.original!.isAvailable && noEntitlements.original!.statusText == "签名存在，无 Entitlements")
precondition(noEntitlements.embeddedEntitlements!.isAvailable)
let invalidEntitlements = view.inspectOriginalInput(path: fixtures.appendingPathComponent("InvalidEntitlements.app").path, profileTeamID: nil)
precondition(!invalidEntitlements.original!.isAvailable && invalidEntitlements.original!.statusText == "签名权限数据无效")
precondition(view.signedEntitlements(forBundle: fixtures.appendingPathComponent("InvalidEntitlements.app").path) == nil)
let unsignedFixture = view.inspectOriginalInput(path: fixtures.appendingPathComponent("Unsigned.app").path, profileTeamID: nil)
precondition(!unsignedFixture.original!.isAvailable && unsignedFixture.original!.teamID == nil)
precondition(unsignedFixture.embeddedEntitlements!.isAvailable) // Profile data must never impersonate Mach-O data.
precondition(unsignedFixture.metadata!.values == expectedMetadata)
print("PASS: original metadata read from App/IPA/xcarchive Info.plist independently of signatures; display-name fallback and numeric build supported")
let noProfile = view.inspectOriginalInput(path: fixtures.appendingPathComponent("NoProfile.app").path, profileTeamID: nil)
precondition(noProfile.original!.isAvailable && noProfile.embeddedEntitlements!.statusText == "未内嵌描述文件")
let badProfile = view.inspectOriginalInput(path: fixtures.appendingPathComponent("BadProfile.app").path, profileTeamID: nil)
precondition(badProfile.original!.isAvailable && badProfile.embeddedEntitlements!.statusText == "描述文件解析失败")
print("PASS: actual Mach-O XML/DER entitlement slots, signed-without-entitlements, unsigned, missing/corrupt embedded profiles")

func labels(in view: NSView) -> [NSTextField] {
    (view as? NSTextField).map { [$0] } ?? view.subviews.flatMap { labels(in: $0) }
}
view.clearEntitlementsFile(nil)
view.loadProfileFile(fixtures.appendingPathComponent("selected.mobileprovision").path)
view.inspectedOriginalEntitlements = signedFixture.original
view.inspectedEmbeddedProfile = signedFixture.embeddedProfile
view.inspectedEmbeddedEntitlements = signedFixture.embeddedEntitlements
view.finalAppGroupsSelection = FinalGroupSelection()
view.finalKeychainGroupsSelection = FinalGroupSelection()
view.rebuildEntitlementInspectorContent()
precondition(view.selectedProfileSnapshot()!.sourcePath == fixtures.appendingPathComponent("selected.mobileprovision").path)
precondition(view.embeddedProfileSnapshot()!.sourcePath!.hasSuffix("Signed.app/embedded.mobileprovision"))
precondition(view.snapshot(for: .originalApp)!.keychainGroups == fixtureKeychains)
precondition(view.snapshot(for: .embeddedProfile)!.keychainGroups == ["FIXTURETEAM.*"])
precondition(view.snapshot(for: .provisioningProfile)!.keychainGroups == ["SELECTEDTEAM.*"])
precondition(view.entitlementComparisonReference()!.source == .provisioningProfile)
let externalProfile = view.selectedProvisioningProfile
view.selectedProvisioningProfile = nil
precondition(view.selectedProfileSnapshot() == nil && view.entitlementComparisonReference()!.source == .embeddedProfile)
view.rebuildEntitlementInspectorContent()
precondition(labels(in: view.entitlementPanel!).contains { $0.stringValue == "值不同 · 已授权" })
view.selectedProvisioningProfile = externalProfile
view.rebuildEntitlementInspectorContent()
let displayed = labels(in: view.entitlementPanel!).map { $0.stringValue }
for title in ["Mach-O 签名权限", "App 内嵌描述文件", "本次签名描述文件", "Entitlements 文件"] {
    precondition(displayed.contains(title))
}
precondition(!displayed.contains("原 App 签名"))
precondition(displayed.contains(where: { $0.contains("LC_CODE_SIGNATURE") }))
precondition(displayed.contains(where: { $0.contains("embedded.mobileprovision") }))
selectGroupSource(.appGroups, .embeddedProfile)
selectGroupSource(.keychainGroups, .originalApp)
precondition(view.currentFinalAppGroups() == fixtureGroups && view.currentFinalKeychainGroups() == fixtureKeychains)
precondition(view.entitlementWarningLabel!.textColor == .systemRed)
let authorizedRow = view.makeSnapshotRow(title: "Mach-O 签名权限", snapshot: signedFixture.original,
    reference: signedFixture.embeddedEntitlements, teamID: "FIXTURETEAM")
precondition(labels(in: authorizedRow).last!.stringValue == "值不同 · 已授权")
precondition(labels(in: authorizedRow).last!.textColor == .systemOrange)
let unauthorizedRow = view.makeSnapshotRow(title: "Mach-O 签名权限", snapshot: signedFixture.original,
    reference: view.selectedProfileSnapshot(), teamID: "SELECTEDTEAM")
precondition(labels(in: unauthorizedRow).last!.stringValue == "⚠ 存在未授权值")
precondition(labels(in: unauthorizedRow).last!.textColor == .systemRed)
let embeddedComparison = view.makeSnapshotRow(title: "App 内嵌描述文件", snapshot: signedFixture.embeddedEntitlements,
    reference: view.selectedProfileSnapshot(), teamID: "SELECTEDTEAM")
precondition(labels(in: embeddedComparison).last!.stringValue == "授权范围不同")
view.layoutSubtreeIfNeeded()
_ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
try snapshot("explicit-sources")
print("PASS: four explicit source rows with file provenance, embedded/selected profiles stay distinct, independent final choices, wildcard authorization vs literal differences")

// The product identity and offline restrictions must be present in the actual built nib/bundle.
let productBundle = Bundle(path: builtApp)!
precondition(productBundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String == "联软EMM签名")
precondition(productBundle.object(forInfoDictionaryKey: "CFBundleName") as? String == "联软EMM签名")
precondition(window.title == "联软EMM签名")
precondition(app.mainMenu!.items.first!.title == "联软EMM签名")
precondition(productBundle.object(forInfoDictionaryKey: "NSAppTransportSecurity") == nil)
precondition(productBundle.url(forResource: "fix-wwdr", withExtension: "sh") == nil)
precondition(NSClassFromString("iOS_App_Signer.NSMenuLink") == nil)
precondition(!view.responds(to: NSSelectorFromString("urlDropped:")))
precondition(OfflineNetworkPolicy.isActive)
func networkConnectIsDenied() -> Bool {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { return errno == EPERM }
    defer { close(fd) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(9).bigEndian
    address.sin_addr.s_addr = UInt32(INADDR_LOOPBACK).bigEndian
    return withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            let result = connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            return result == -1 && errno == EPERM
        }
    }
}
precondition(networkConnectIsDenied())
let networkChild = Process().execute(fixtures.appendingPathComponent("network-probe").path, workingDirectory: nil, arguments: [])
precondition(networkChild.status == 0, networkChild.output)
precondition(OfflineNetworkPolicy.isLocalPath(fixtures.path))
for remote in ["https://example.invalid/app.ipa", "http://127.0.0.1/a.ipa", "file://server/share/a.mobileprovision", "//server/share/app.ipa", "smb://server/share/app.ipa"] {
    precondition(!OfflineNetworkPolicy.isLocalPath(remote))
}
let previousInput = view.InputFileText.stringValue
view.fileDropped("https://example.invalid/a.ipa")
precondition(view.InputFileText.stringValue == previousInput)
precondition(ProvisioningProfile(filename: "file://server/share/a.mobileprovision") == nil)
print("PASS: product/window/menu rename, removed web resources/actions, app and child TCP connections denied by offline policy, remote inputs rejected")

func waitForInspection() {
    let deadline = Date().addingTimeInterval(45)
    while Date() < deadline {
        pump(0.05)
        if case .loading? = view.inspectedOriginalEntitlements?.status { continue }
        return
    }
    fatalError("Inspection timed out")
}
let selectedProfileURL = fixtures.appendingPathComponent("selected.mobileprovision")
view.loadProfileFile(selectedProfileURL.path)
view.fileDropped(fixtures.appendingPathComponent("Signed.app").path)
waitForInspection()
view.finalAppGroupsSelection = FinalGroupSelection(source: .custom, userEdited: true, customValue: "group.manual.preserved")
view.finalKeychainGroupsSelection = FinalGroupSelection(source: .custom, userEdited: true, customValue: "MANUALTEAM.preserved")
view.rebuildEntitlementInspectorContent()
setLeagsoftApp(true)
precondition(view.currentFinalAppGroups() == ["group.com.example.selected"])
precondition(view.currentFinalKeychainGroups() == ["SELECTEDTEAM.com.apple.networkextensionsharing", "SELECTEDTEAM.com.leagsoft.emm"])
precondition(!view.appGroupsSourcePopup!.isEnabled && !view.keychainGroupsSourcePopup!.isEnabled)
precondition(!view.finalAppGroupsField!.isEditable && view.finalAppGroupsField!.isSelectable)
let presetEntitlements = view.entitlementsForSigning(profile: view.selectedProvisioningProfile,
    appBundlePath: fixtures.appendingPathComponent("Unsigned.app").path, bundleID: "com.example.fixture",
    entitlementsFilePath: entitlementURL.path, appGroups: ["group.WRONG"], keychainGroups: ["WRONG.*", "com.apple.token"],
    newApplicationID: "", useLeagsoftPolicy: true)!
precondition(presetEntitlements["com.apple.security.application-groups"] as? [String] == view.currentFinalAppGroups())
precondition(presetEntitlements["keychain-access-groups"] as? [String] == view.currentFinalKeychainGroups())
let presetURL = fixtures.appendingPathComponent("leagsoft-final.entitlements")
try PropertyListSerialization.data(fromPropertyList: presetEntitlements, format: .xml, options: 0).write(to: presetURL)
let presetApp = fixtures.appendingPathComponent("PresetResult.app")
try FileManager.default.copyItem(at: fixtures.appendingPathComponent("Unsigned.app"), to: presetApp)
let adhoc = view.codeSign(presetApp.path, certificate: "-", entitlements: presetURL.path, before: nil, after: nil)
precondition(adhoc.status == 0, adhoc.output)
precondition(view.signedEntitlements(forBundle: presetApp.path)!["keychain-access-groups"] as? [String] == view.currentFinalKeychainGroups())
precondition(view.signedEntitlements(forBundle: presetApp.path)!["com.apple.security.application-groups"] as? [String] == view.currentFinalAppGroups())
view.loadProfileFile(fixtures.appendingPathComponent("empty-groups.mobileprovision").path)
waitForInspection()
precondition(view.currentFinalAppGroups().isEmpty) // No fallback to Mach-O, embedded profile or standalone entitlements.
let emptyPolicy = view.entitlementsForSigning(profile: view.selectedProvisioningProfile,
    appBundlePath: fixtures.appendingPathComponent("Signed.app").path, bundleID: "com.example.fixture",
    entitlementsFilePath: entitlementURL.path, appGroups: ["group.WRONG"], keychainGroups: ["WRONG"],
    newApplicationID: "", useLeagsoftPolicy: true)!
precondition(emptyPolicy["com.apple.security.application-groups"] == nil)
view.loadProfileFile(fixtures.appendingPathComponent("migrated-prefix.mobileprovision").path)
waitForInspection()
precondition(view.selectedProvisioningProfile!.teamID == "OLDPREFIX")
precondition(view.currentFinalKeychainGroups() == ["SELECTEDTEAM.com.apple.networkextensionsharing", "SELECTEDTEAM.com.leagsoft.emm"])
view.loadProfileFile(fixtures.appendingPathComponent("top-level-team.mobileprovision").path)
waitForInspection()
precondition(view.currentFinalKeychainGroups() == ["REALTEAM.com.apple.networkextensionsharing", "REALTEAM.com.leagsoft.emm"])
view.loadProfileFile(fixtures.appendingPathComponent("other-team.mobileprovision").path)
waitForInspection()
precondition(view.currentFinalKeychainGroups() == ["OTHERTEAM.com.apple.networkextensionsharing", "OTHERTEAM.com.leagsoft.emm"])
precondition(view.currentFinalAppGroups() == ["group.com.example.refreshed"])
view.controlsEnabled(false)
precondition(!view.leagsoftAppCheckbox!.isEnabled && !view.refreshInspectionButton!.isEnabled && !view.StartButton.isEnabled)
view.controlsEnabled(true)
precondition(view.leagsoftAppCheckbox!.isEnabled && view.refreshInspectionButton!.isEnabled)
precondition(!view.appGroupsSourcePopup!.isEnabled && !view.keychainGroupsSourcePopup!.isEnabled)
setLeagsoftApp(false)
precondition(view.currentFinalAppGroups() == ["group.manual.preserved"])
precondition(view.currentFinalKeychainGroups() == ["MANUALTEAM.preserved"])
setLeagsoftApp(true)
view.ProvisioningProfilesPopup.selectItem(at: 0)
selectProfileSource(.existing)
waitForInspection()
precondition(view.inspectedEmbeddedProfile != nil && view.leagsoftValidationMessage != nil && !view.StartButton.isEnabled)
precondition(view.selectedProfileSnapshot() == nil)
precondition(view.profileDetailsLabel!.stringValue.contains("不会使用 App 内嵌"))
precondition(view.currentFinalAppGroups().isEmpty && view.currentFinalKeychainGroups().isEmpty)
view.loadProfileFile(selectedProfileURL.path)
waitForInspection()
print("PASS: default Leagsoft preset, exactly two keychain groups, external-only App Groups (including absent groups), Team ID vs App ID prefix, manual drafts preserved, actual signed Mach-O matches preset")

// Certificate equality is DER equality; neither a common name nor team alone is sufficient.
let productionIdentities = view.signingIdentities
precondition(productionIdentities.allSatisfy { $0.certificateData != nil }, "Keychain DER query must cover every valid signing identity")
let fixtureDER = try Data(contentsOf: fixtures.appendingPathComponent("certificate.der"))
let otherDER = try Data(contentsOf: fixtures.appendingPathComponent("other-certificate.der"))
let hash = SigningCertificateFile.fingerprint(fixtureDER)
let otherHash = SigningCertificateFile.fingerprint(otherDER)
let parsed = SigningIdentity.parse("  1) \(hash) \"Same certificate name\"\n  2) \(otherHash) \"Same certificate name\"\n  3) \(hash) \"Same certificate name\"\n     2 valid identities found", certificates: [fixtureDER, otherDER])
precondition(parsed.count == 2 && parsed[0].displayName != parsed[1].displayName)
precondition(Set(parsed.compactMap { $0.certificateData }) == Set([fixtureDER, otherDER]))
func setTestIdentities(_ identities: [SigningIdentity], selected: String?) {
    view.signingIdentities = identities
    view.codesigningCerts = identities.map { $0.displayName }
    view.CodesigningCertsPopup.removeAllItems()
    view.CodesigningCertsPopup.addItems(withTitles: view.codesigningCerts)
    if let selected, let identity = identities.first(where: { $0.fingerprint == selected }) {
        view.CodesigningCertsPopup.selectItem(withTitle: identity.displayName)
    } else { view.CodesigningCertsPopup.selectItem(at: -1) }
    view.certificateInputSource = .existing
    view.updateSigningInputSources()
}
setTestIdentities(parsed, selected: hash)
precondition(view.certificateProfileValidationMessage == nil && view.StartButton.isEnabled)
setTestIdentities(parsed, selected: otherHash)
precondition(view.certificateProfileValidationMessage!.contains("不匹配") && !view.StartButton.isEnabled)
view.controlsEnabled(false)
view.controlsEnabled(true)
precondition(!view.StartButton.isEnabled) // Re-enabling controls must not bypass validation.
setTestIdentities(parsed, selected: nil)
precondition(!view.StartButton.isEnabled)
setTestIdentities(parsed, selected: hash)
for profileName in ["mismatch", "missing-certificates"] {
    view.loadProfileFile(fixtures.appendingPathComponent(profileName + ".mobileprovision").path)
    waitForInspection()
    precondition(view.certificateProfileValidationMessage != nil && !view.StartButton.isEnabled)
}
view.checkProfileID(ProvisioningProfile(filename: fixtures.appendingPathComponent("expired.mobileprovision").path))
waitForInspection()
precondition(!view.StartButton.isEnabled)
view.loadProfileFile(selectedProfileURL.path)
precondition(!view.StartButton.isEnabled) // Waiting for asynchronous inspection is not ready.
waitForInspection()
precondition(view.StartButton.isEnabled)
view.InputFileText.stringValue = fixtures.appendingPathComponent("Unsigned.app").path
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: view.InputFileText))
precondition(!view.StartButton.isEnabled)
view.scheduleEntitlementInspection()
waitForInspection()
precondition(view.StartButton.isEnabled) // Missing original Mach-O entitlements is not an error with a matching external profile.
print("PASS: certificate/profile DER equality, duplicate names distinguished, mismatch/missing/expired/unchecked states disable signing; matching unsigned app enables signing")

// Refresh re-reads all input bytes at unchanged paths and never falls back after a failure.
func writeTestProfile(to url: URL, source: String = "selected", certificate: Data) throws {
    let data = try Data(contentsOf: fixtures.appendingPathComponent(source + ".plist"))
    var profile = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
    profile["DeveloperCertificates"] = [certificate]
    let unsigned = fixtures.appendingPathComponent("refresh-profile.plist")
    try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0).write(to: unsigned)
    let result = Process().execute("/usr/bin/openssl", workingDirectory: nil, arguments: ["cms", "-sign", "-binary", "-nodetach", "-in", unsigned.path,
        "-signer", fixtures.appendingPathComponent("certificate.pem").path, "-inkey", fixtures.appendingPathComponent("key.pem").path,
        "-outform", "DER", "-out", url.path])
    precondition(result.status == 0, result.output)
}
// Use an already-available local identity when possible, so refresh also exercises the real keychain query.
let refreshIdentity = productionIdentities.first(where: { $0.certificateData != nil }) ?? parsed.first(where: { $0.fingerprint == hash })!
let refreshDER = refreshIdentity.certificateData!
let refreshURL = fixtures.appendingPathComponent("refresh.mobileprovision")
try writeTestProfile(to: refreshURL, certificate: refreshDER)
setTestIdentities(productionIdentities.isEmpty ? parsed : productionIdentities, selected: refreshIdentity.fingerprint)
view.loadProfileFile(refreshURL.path)
let refreshedApp = fixtures.appendingPathComponent("Refresh.app")
try FileManager.default.copyItem(at: fixtures.appendingPathComponent("Signed.app"), to: refreshedApp)
view.fileDropped(refreshedApp.path)
view.fileDropped(entitlementURL.path)
waitForInspection()
precondition(view.StartButton.isEnabled)
precondition(view.inspectedApplicationMetadata!.values == expectedMetadata)
for (key, value) in expectedMetadata {
    precondition(view.applicationMetadataLabels[key]!.stringValue == "当前：\(value)")
    precondition(view.applicationMetadataLabels[key]!.isSelectable)
}
// Original Bundle ID is shown separately even when the profile dictates the signing value.
let displayedProfile = view.selectedProvisioningProfile
var forcedProfile = ProvisioningProfile(filename: selectedProfileURL.path)!
forcedProfile.appID = "com.example.profile.forced"
view.checkProfileID(forcedProfile, inspect: false)
precondition(view.NewApplicationIDTextField.stringValue == "com.example.profile.forced" && !view.NewApplicationIDTextField.isEnabled)
precondition(view.applicationMetadataLabels["CFBundleIdentifier"]!.stringValue == "当前：com.example.fixture")
view.checkProfileID(displayedProfile, inspect: false)
view.appDisplayName.stringValue = "手动签名名称"
view.appShortVersion.stringValue = "9.9"
view.appVersion.stringValue = "999"
func refreshAndWait() {
    precondition(refreshButtons(in: view).count == 1)
    precondition(view.refreshInspectionButton!.title == "刷新")
    view.refreshInspectionButton!.performClick(nil)
    precondition(!view.StartButton.isEnabled)
    waitForInspection()
    if productionIdentities.isEmpty && view.certificateInputSource == .existing { setTestIdentities(parsed, selected: refreshIdentity.fingerprint) }
}
try writeTestProfile(to: refreshURL, source: "other-team", certificate: refreshDER)
let refreshedInfoURL = refreshedApp.appendingPathComponent("Info.plist")
var refreshedInfo = try PropertyListSerialization.propertyList(from: Data(contentsOf: refreshedInfoURL), options: [], format: nil) as! [String: Any]
refreshedInfo["CFBundleIdentifier"] = "com.example.refreshed"
refreshedInfo["CFBundleDisplayName"] = "已替换的当前名称"
refreshedInfo["CFBundleShortVersionString"] = "6.0"
refreshedInfo["CFBundleVersion"] = "2026111702"
try PropertyListSerialization.data(fromPropertyList: refreshedInfo, format: .binary, options: 0).write(to: refreshedInfoURL)
let replacement = fixtures.appendingPathComponent("refresh-macho.entitlements")
let replacementGroups: [String: Any] = ["application-identifier": "NEWMACHO.com.example.fixture",
    "com.apple.developer.team-identifier": "NEWMACHO", "com.apple.security.application-groups": ["group.refreshed.macho"],
    "keychain-access-groups": ["NEWMACHO.refreshed"]]
try PropertyListSerialization.data(fromPropertyList: replacementGroups, format: .xml, options: 0).write(to: replacement)
precondition(view.codeSign(refreshedApp.path, certificate: "-", entitlements: replacement.path, before: nil, after: nil).status == 0)
try FileManager.default.removeItem(at: refreshedApp.appendingPathComponent("embedded.mobileprovision"))
try FileManager.default.copyItem(at: fixtures.appendingPathComponent("other-team.mobileprovision"), to: refreshedApp.appendingPathComponent("embedded.mobileprovision"))
try PropertyListSerialization.data(fromPropertyList: ["keychain-access-groups": ["REFRESHEDFILE.group"]], format: .xml, options: 0).write(to: entitlementURL)
refreshAndWait()
precondition(view.applicationMetadataLabels["CFBundleIdentifier"]!.stringValue == "当前：com.example.refreshed")
precondition(view.applicationMetadataLabels["CFBundleDisplayName"]!.stringValue == "当前：已替换的当前名称")
precondition(view.applicationMetadataLabels["CFBundleShortVersionString"]!.stringValue == "当前：6.0")
precondition(view.applicationMetadataLabels["CFBundleVersion"]!.stringValue == "当前：2026111702")
precondition(view.appDisplayName.stringValue == "手动签名名称" && view.appShortVersion.stringValue == "9.9" && view.appVersion.stringValue == "999")
precondition(view.currentFinalAppGroups() == ["group.com.example.refreshed"])
precondition(view.currentFinalKeychainGroups() == ["OTHERTEAM.com.apple.networkextensionsharing", "OTHERTEAM.com.leagsoft.emm"])
precondition(view.inspectedOriginalEntitlements!.keychainGroups == ["NEWMACHO.refreshed"])
precondition(view.inspectedEmbeddedEntitlements!.keychainGroups == ["OTHERTEAM.*"])
precondition(view.inspectedEntitlementsFile!.keychainGroups == ["REFRESHEDFILE.group"])
precondition(view.StartButton.isEnabled)
// Replacing a whole IPA at the same pathname must also refresh both embedded sources.
let refreshIPA = fixtures.appendingPathComponent("Fixture.ipa")
view.fileDropped(refreshIPA.path)
waitForInspection()
precondition(view.inspectedOriginalEntitlements!.keychainGroups == fixtureKeychains)
precondition(view.inspectedApplicationMetadata!.values == expectedMetadata)
let zipRoot = fixtures.appendingPathComponent("RefreshArchive")
let zipPayload = zipRoot.appendingPathComponent("Payload")
try FileManager.default.createDirectory(at: zipPayload, withIntermediateDirectories: true)
try FileManager.default.copyItem(at: refreshedApp, to: zipPayload.appendingPathComponent("Signed.app"))
try FileManager.default.removeItem(at: refreshIPA)
let zipResult = Process().execute("/usr/bin/zip", workingDirectory: zipRoot.path, arguments: ["-qry", refreshIPA.path, "Payload"])
precondition(zipResult.status == 0, zipResult.output)
refreshAndWait()
precondition(view.inspectedOriginalEntitlements!.keychainGroups == ["NEWMACHO.refreshed"])
precondition(view.inspectedEmbeddedEntitlements!.keychainGroups == ["OTHERTEAM.*"])
precondition(view.inspectedOriginalEntitlements!.sourcePath!.contains("Fixture.ipa!/Payload/Signed.app/Fixture"))
precondition(view.applicationMetadataLabels["CFBundleDisplayName"]!.stringValue == "当前：已替换的当前名称")
precondition(view.inspectedApplicationMetadata!.sourcePath.hasSuffix("Fixture.ipa!/Payload/Signed.app/Info.plist"))
view.fileDropped(refreshedApp.path)
waitForInspection()
// Invalid/deleted inputs must clear old values; restore the same path and refresh to recover.
let savedInfo = try Data(contentsOf: refreshedInfoURL)
try Data("invalid plist".utf8).write(to: refreshedInfoURL)
refreshAndWait()
precondition(view.inspectedApplicationMetadata == nil)
precondition(view.applicationMetadataLabels.values.allSatisfy { $0.stringValue == "当前：—" })
precondition(view.applicationMetadataStatusLabel!.stringValue.contains("无法读取"))
try FileManager.default.removeItem(at: refreshedInfoURL)
refreshAndWait()
precondition(view.inspectedApplicationMetadata == nil)
try savedInfo.write(to: refreshedInfoURL)
refreshAndWait()
precondition(view.inspectedApplicationMetadata!.values["CFBundleVersion"] == "2026111702")
view.fileDropped(fixtures.appendingPathComponent("Missing.ipa").path)
precondition(view.inspectedApplicationMetadata == nil)
waitForInspection()
precondition(view.inspectedApplicationMetadata == nil && !view.StartButton.isEnabled)
view.fileDropped(refreshedApp.path)
waitForInspection()
view.InputFileText.stringValue = ""
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: view.InputFileText))
precondition(view.inspectedApplicationMetadata == nil)
view.refreshSigningInputs(nil)
precondition(view.applicationMetadataStatusLabel!.stringValue == "未选择应用")
view.fileDropped(refreshedApp.path)
waitForInspection()
precondition(view.appDisplayName.stringValue == "手动签名名称" && view.appShortVersion.stringValue == "9.9" && view.appVersion.stringValue == "999")
try snapshot("metadata-unified-refresh")
print("PASS: single global refresh updates original metadata and signing checks together, preserves signing overrides, distinguishes profile Bundle ID, clears stale values and recovers same-path replaced/corrupt/missing files")
try writeTestProfile(to: refreshURL, certificate: otherDER)
refreshAndWait()
precondition(!view.StartButton.isEnabled && view.certificateProfileValidationMessage != nil)
try Data("not a profile".utf8).write(to: refreshURL)
refreshAndWait()
precondition(view.selectedProvisioningProfile == nil && view.profileReadError != nil && view.profileFilename == nil)
precondition(view.profilePathField!.stringValue == refreshURL.path && !view.StartButton.isEnabled)
setLeagsoftApp(false)
precondition(view.activeSigningProfile == nil) // Corrupt external file is NOT an instruction to use embedded profile.
setLeagsoftApp(true)
try writeTestProfile(to: refreshURL, certificate: refreshDER)
refreshAndWait()
precondition(view.profileReadError == nil && view.StartButton.isEnabled)
try FileManager.default.removeItem(at: refreshURL)
refreshAndWait()
precondition(!view.StartButton.isEnabled && view.unreadableProfilePath == refreshURL.path)
try writeTestProfile(to: refreshURL, source: "expired", certificate: refreshDER)
refreshAndWait()
precondition(!view.StartButton.isEnabled && view.profileReadError != nil)
try writeTestProfile(to: refreshURL, certificate: refreshDER)
refreshAndWait()
precondition(view.StartButton.isEnabled)
try FileManager.default.removeItem(at: entitlementURL)
refreshAndWait()
precondition(!view.inspectedEntitlementsFile!.isAvailable) // No stale standalone groups after deletion.
precondition(view.currentFinalKeychainGroups() == ["SELECTEDTEAM.com.apple.networkextensionsharing", "SELECTEDTEAM.com.leagsoft.emm"])

// Missing certificate file invalidates a previously imported identity, even if it remains in keychain.
let removedCertificate = fixtures.appendingPathComponent("removed-certificate.cer")
try refreshDER.write(to: removedCertificate)
view.certificateFilePath = removedCertificate.path
view.importedCertificateName = refreshIdentity.displayName
view.importedCertificateFingerprint = refreshIdentity.fingerprint
view.importedCertificateFileDigest = SigningCertificateFile.fileDigest(refreshDER)
view.certificatePathField!.stringValue = removedCertificate.path
view.certificateInputSource = .file
view.updateSigningInputSources()
precondition(view.StartButton.isEnabled)
try FileManager.default.removeItem(at: removedCertificate)
refreshAndWait()
precondition(view.importedCertificateFingerprint == nil && view.currentSigningCertificate == nil && !view.StartButton.isEnabled)
// A changed encrypted P12 requires re-import. Cancelling the password prompt cannot
// silently retain the old identity, and this test never imports into the default keychain.
selectCertificateSource(.existing)
let replacedP12 = fixtures.appendingPathComponent("replaced-certificate.p12")
let originalP12 = try Data(contentsOf: fixtures.appendingPathComponent("certificate.p12"))
try originalP12.write(to: replacedP12)
view.certificateFilePath = replacedP12.path
view.importedCertificateName = refreshIdentity.displayName
view.importedCertificateFingerprint = refreshIdentity.fingerprint
view.importedCertificateFileDigest = SigningCertificateFile.fileDigest(originalP12)
view.certificateInputSource = .file
view.certificatePathField!.stringValue = replacedP12.path
view.updateSigningInputSources()
try Data("replacement encrypted file".utf8).write(to: replacedP12)
view.updateSigningReadiness()
precondition(!view.StartButton.isEnabled && view.certificateFileValidationMessage != nil)
let cancelImport = Timer(timeInterval: 0.05, repeats: true) { _ in
    if let modal = app.modalWindow {
        app.stopModal(withCode: .alertSecondButtonReturn)
        modal.orderOut(nil)
    }
}
RunLoop.main.add(cancelImport, forMode: .modalPanel)
view.refreshSigningInputs(nil)
cancelImport.invalidate()
waitForInspection()
precondition(view.certificateInputSource == .file && view.importedCertificateFingerprint == nil)
precondition(view.currentSigningCertificate == nil && !view.StartButton.isEnabled)
selectCertificateSource(.existing)
setLeagsoftApp(false)
view.finalAppGroupsSelection = FinalGroupSelection(source: .entitlementsFile, userEdited: true)
view.rebuildEntitlementInspectorContent()
precondition(view.finalAppGroupsSelection.source == .entitlementsFile && !view.StartButton.isEnabled)
view.clearEntitlementsFile(nil)
setLeagsoftApp(false)
view.finalAppGroupsSelection = FinalGroupSelection()
view.finalKeychainGroupsSelection = FinalGroupSelection()
print("PASS: refresh button re-reads same-path Mach-O, embedded/external profiles and standalone entitlements; changed certificate membership/corrupt/missing/expired files invalidate signing; restored files recover; missing/replaced certificate cannot reuse old imported identity (including password cancellation); same-path IPA re-read; explicit failed final source stays selected and blocks signing")

// Exercise the customer's real external profile without ever changing it.
let customerProfile = "/Users/mike/Downloads/17/招商永隆/BYOD_UAT_InHouse.mobileprovision"
if FileManager.default.fileExists(atPath: customerProfile) {
    view.loadProfileFile(customerProfile)
    waitForInspection()
    setLeagsoftApp(true)
    precondition(view.currentFinalAppGroups() == ["group.com.cmbwinglungbank.byod.uat"])
    precondition(view.currentFinalKeychainGroups() == ["AK7SXEV839.com.apple.networkextensionsharing", "AK7SXEV839.com.leagsoft.emm"])
    window.setContentSize(NSSize(width: 1100, height: 900))
    app.appearance = NSAppearance(named: .aqua)
    view.layoutSubtreeIfNeeded()
    _ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
    try snapshot("leagsoft-customer-profile")
    app.appearance = NSAppearance(named: .darkAqua)
    pump(0.2)
    try snapshot("leagsoft-customer-profile-dark")
    window.setContentSize(NSSize(width: 900, height: 600))
    view.layoutSubtreeIfNeeded()
    _ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
    try snapshot("leagsoft-small-window")
    setLeagsoftApp(false)
    print("PASS: real external profile gives exact AK7SXEV839 Leagsoft groups, light/dark/small-window screenshots")
}

for (ipaIndex, ipaPath) in CommandLine.arguments.dropFirst(3).enumerated() {
    app.appearance = NSAppearance(named: .aqua)
    view.loadProfileFile(fixtures.appendingPathComponent("selected.mobileprovision").path)
    window.setContentSize(NSSize(width: 1100, height: 900))
    view.clearEntitlementsFile(nil)
    view.finalAppGroupsSelection = FinalGroupSelection()
    view.finalKeychainGroupsSelection = FinalGroupSelection()
    view.fileDropped(ipaPath)
    let deadline = Date().addingTimeInterval(45)
    while Date() < deadline {
        pump(0.1)
        if let snapshot = view.inspectedOriginalEntitlements {
            if case .loading = snapshot.status { continue }
            break
        }
    }
    precondition(view.inspectedOriginalEntitlements != nil)
    if case .loading? = view.inspectedOriginalEntitlements?.status { fatalError("Inspection timed out") }
    precondition(view.finalAppGroupsSelection.source == .provisioningProfile || view.selectedProvisioningProfile == nil)
    precondition(view.finalKeychainGroupsSelection.source == .provisioningProfile || view.selectedProvisioningProfile == nil)
    if ["EMMClient_iPhone.ipa", "EMMClient_iPhone1.ipa"].contains(URL(fileURLWithPath: ipaPath).lastPathComponent) {
        precondition(view.inspectedOriginalEntitlements!.isAvailable)
        precondition(view.inspectedOriginalEntitlements!.appGroups.isEmpty)
        precondition(view.inspectedOriginalEntitlements!.keychainGroups == [
            "AGSJVKAG6H.com.apple.networkextensionsharing", "AGSJVKAG6H.com.leagsoft.emm", "AGSJVKAG6H.com.cmbwinglungbank.byod.uat"])
        precondition(view.embeddedProfileSnapshot()!.keychainGroups == ["AGSJVKAG6H.*", "com.apple.token"])
        precondition(view.inspectedOriginalEntitlements!.sourcePath == ipaPath + "!/Payload/EMMClient_iPhone.app/EMMClient_iPhone")
        precondition(view.embeddedProfileSnapshot()!.sourcePath == ipaPath + "!/Payload/EMMClient_iPhone.app/embedded.mobileprovision")
        // A selected external profile must not hide or replace either original source.
        precondition(view.selectedProfileSnapshot()!.sourcePath == fixtures.appendingPathComponent("selected.mobileprovision").path)
        selectGroupSource(.appGroups, .originalApp)
        selectGroupSource(.keychainGroups, .originalApp)
        precondition(view.currentFinalAppGroups().isEmpty && view.currentFinalKeychainGroups().count == 3)
    }
    print("PASS: real IPA inspection: \(ipaPath) — \(view.inspectedOriginalEntitlements!.statusText)")
    view.layoutSubtreeIfNeeded()
    _ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
    try snapshot("real-ipa-\(ipaIndex)")
    app.appearance = NSAppearance(named: .darkAqua)
    pump(0.2)
    try snapshot("dark-mode-\(ipaIndex)")
    if ["EMMClient_iPhone.ipa", "EMMClient_iPhone1.ipa"].contains(URL(fileURLWithPath: ipaPath).lastPathComponent) {
        view.ProvisioningProfilesPopup.selectItem(at: 0)
        selectProfileSource(.existing)
        let embeddedDeadline = Date().addingTimeInterval(45)
        while Date() < embeddedDeadline {
            pump(0.1)
            if case .loading? = view.inspectedOriginalEntitlements?.status { continue }
            break
        }
        precondition(view.selectedProvisioningProfile == nil && view.selectedProfileSnapshot()!.isAvailable)
        precondition(view.selectedProfileSnapshot()!.sourceDescription!.contains("使用 App 内嵌描述文件"))
        precondition(view.selectedProfileSnapshot()!.sourcePath == view.embeddedProfileSnapshot()!.sourcePath)
        precondition(view.currentFinalKeychainGroups().count == 3 && view.finalKeychainGroupsSelection.source == .originalApp)
        precondition(view.entitlementWarningLabel!.textColor == .systemOrange)
        precondition(!view.entitlementWarningLabel!.stringValue.contains("未授权值"))
        app.appearance = NSAppearance(named: .aqua)
        view.layoutSubtreeIfNeeded()
        _ = view.finalKeychainGroupsField!.scrollToVisible(view.finalKeychainGroupsField!.bounds)
        try snapshot("real-ipa-embedded-profile")
        print("PASS: real IPA embedded profile fallback, three concrete Mach-O keychain groups authorized by wildcard (not misreported as unauthorized)")
    }
}
print("ALL CHECKS PASSED; snapshots: \(fixtures.path)")
