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

func snapshot(_ name: String) throws {
    view.layoutSubtreeIfNeeded()
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { fatalError("No bitmap") }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    try bitmap.representation(using: .png, properties: [:])!.write(to: fixtures.appendingPathComponent(name + ".png"))
}
try snapshot("initial")
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
    let field = view.profilePathField!
    field.stringValue = "\"" + profile.filename + "\""
    view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: field))
    pump(0.7)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename)
    precondition(field.stringValue == profile.filename)
    precondition(view.finalEntitlementSource == .provisioningProfile)
    precondition(view.currentFinalKeychainGroups() == view.valuesForFinalSource(.provisioningProfile)!.keychainGroups)
    view.selectedProvisioningProfile = nil
    view.fileDropped(profile.filename)
    precondition(view.selectedProvisioningProfile?.filename == profile.filename)
    print("PASS: provisioning profile pasted path and drop routing, default groups")
} else { print("SKIP: no installed profiles available for profile-paste integration check") }

let entitlementURL = fixtures.appendingPathComponent("custom.entitlements")
let plist: [String: Any] = [
    "application-identifier": "OTHERTEAM.com.example.app",
    "com.apple.security.application-groups": ["group.com.example.shared.with.a.long.identifier.to.test.wrapping", "group.com.example.second"],
    "keychain-access-groups": ["OTHERTEAM.com.example.shared"]
]
try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: entitlementURL)
view.fileDropped(entitlementURL.path)
pump()
precondition(view.finalEntitlementSource == .entitlementsFile)
precondition(view.currentFinalKeychainGroups() == ["OTHERTEAM.com.example.shared"])
precondition(view.entitlementSourcePopup!.itemArray.first(where: { $0.tag == FinalEntitlementSource.originalApp.rawValue })!.isEnabled == false)
if view.selectedProvisioningProfile != nil { precondition(view.entitlementWarningLabel?.textColor == NSColor.systemRed) }
try snapshot("differences")
let editingField = view.finalKeychainGroupsField!
editingField.stringValue = "CUSTOMTEAM.com.example.manual"
view.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: editingField))
precondition(view.finalEntitlementSource == .custom && view.finalKeychainGroupsField === editingField)
view.rebuildEntitlementInspectorContent()
precondition(view.currentFinalKeychainGroups() == ["CUSTOMTEAM.com.example.manual"])
print("PASS: entitlement file, differences, unavailable source disabled, live custom editing and value preservation")

let doc = view.subviews.compactMap { $0 as? NSScrollView }.first!
window.setContentSize(NSSize(width: 900, height: 600))
view.layoutSubtreeIfNeeded()
precondition(doc.documentView!.frame.height > doc.contentView.frame.height)
precondition(view.finalKeychainGroupsField!.frame.width > 500)
precondition(view.entitlementPanel!.frame.width <= 900)
try snapshot("small-window")
view.signingControlsEnabled = false
view.setSigningInputControlsEnabled(false)
precondition(!view.profilePathField!.isEnabled && !view.certificatePathField!.isEnabled && !view.finalAppGroupsField!.isEnabled)
view.signingControlsEnabled = true
view.setSigningInputControlsEnabled(true)
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

if CommandLine.arguments.count > 3 {
    window.setContentSize(NSSize(width: 1100, height: 900))
    view.clearEntitlementsFile(nil)
    view.finalEntitlementsUserEdited = false
    view.finalEntitlementSource = .provisioningProfile
    view.fileDropped(CommandLine.arguments[3])
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
    precondition(view.finalEntitlementSource == .provisioningProfile || view.selectedProvisioningProfile == nil)
    print("PASS: real IPA inspection: \(view.inspectedOriginalEntitlements!.statusText)")
    try snapshot("real-ipa")
    app.appearance = NSAppearance(named: .darkAqua)
    pump(0.2)
    try snapshot("dark-mode")
}
print("ALL CHECKS PASSED; snapshots: \(fixtures.path)")
