import Foundation

public enum SpaceConfiguration {
    public static let appGroup = "group.com.space.shared"
    public static let keychainAccessGroupSuffix = "com.space.shared"
    public static let cacheFileName = "vault-cache-v1.bin"
    public static let keychainService = "com.space.local-cache-key.v1"
    public static let keychainAccount = "device-unlock-key"
    public static let vaultIdentityService = "com.space.vault-identity.v1"
    public static let vaultIdentityAccount = "active-vault"

    public static func sharedContainerURL(
        fileManager: FileManager = .default
    ) throws -> URL {
        guard let url = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup
        ) else {
            throw SpaceConfigurationError.appGroupUnavailable
        }
        return url
    }
}

public enum SpaceConfigurationError: Error, Equatable {
    case appGroupUnavailable
    case keychainAccessGroupUnavailable
}
