import Cocoa
import Security
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
    view.finishCertificateImport(path: fixtures.appendingPathComponent("certificate.p12").path, names: [existingCertificate])
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
    if ipaPath.hasSuffix("EMMClient_iPhone.ipa") {
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
    if ipaPath.hasSuffix("EMMClient_iPhone.ipa") {
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
