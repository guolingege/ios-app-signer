import Foundation

/// Restrict this process and all helpers without restricting local signing files or keychain access.
/// macOS's legacy Seatbelt API is deprecated; if unavailable, do not run without the restriction.
enum OfflineNetworkPolicy {
    private(set) static var isActive = false

    static func activate() -> Bool {
        if isActive { return true }
        let result = SignerActivateOfflinePolicy()
        isActive = result == 0
        return isActive
    }

    static func isLocalPath(_ value: String) -> Bool {
        let path = SigningFilePath.normalize(value)
        guard path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("://") else { return false }
        // Network mounts are not local files, even when presented as filesystem paths.
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        return (try? url.resourceValues(forKeys: [.volumeIsLocalKey]).volumeIsLocal) != false
    }
}
