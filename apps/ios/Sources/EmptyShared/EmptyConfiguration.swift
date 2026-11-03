import Foundation

public enum EmptyConfiguration {
    /// Default for the production bundle; each target's Info.plist `EmptyAppGroup` is authoritative.
    public static let appGroup = "group.com.empty.shared"
    public static let keychainAccessGroupSuffix = "com.empty.shared"
    public static let cacheFileName = "vault-cache-v1.bin"
    public static let keychainService = "com.empty.local-cache-key.v1"
    public static let keychainAccount = "device-unlock-key"
    public static let vaultIdentityService = "com.empty.vault-identity.v1"
    public static let vaultIdentityAccount = "active-vault"
    public static let deviceSessionService = "com.empty.device-session.v1"
    public static let deviceSessionAccount = "sync-device"

    /// Reads the entitled group from Info.plist so a development-only bundle can use its own IDs.
    /// The OS returns nil for any group the binary is not entitled to, so this fails closed.
    public static func configuredAppGroup(bundle: Bundle = .main) throws -> String {
        guard let group = bundle.object(forInfoDictionaryKey: "EmptyAppGroup") as? String,
              group.hasPrefix("group."), !group.contains("$(") else {
            throw EmptyConfigurationError.appGroupUnavailable
        }
        return group
    }

    public static func sharedContainerURL(
        fileManager: FileManager = .default,
        bundle: Bundle = .main
    ) throws -> URL {
        guard let url = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: try configuredAppGroup(bundle: bundle)
        ) else {
            throw EmptyConfigurationError.appGroupUnavailable
        }
        return url
    }
}

public enum EmptyConfigurationError: Error, Equatable {
    case appGroupUnavailable
    case keychainAccessGroupUnavailable
}
