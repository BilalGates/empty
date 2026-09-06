import Foundation

public enum SpaceEnvironment {
    public static func makeStore(
        bootstrapVaultIdentityIfMissing: Bool = false
    ) throws -> EncryptedVaultStore {
        let container = try SpaceConfiguration.sharedContainerURL()
        guard let accessGroup = Bundle.main.object(
            forInfoDictionaryKey: "SpaceKeychainAccessGroup"
        ) as? String else {
            throw SpaceConfigurationError.keychainAccessGroupUnavailable
        }
        guard !accessGroup.isEmpty, !accessGroup.contains("$(") else {
            throw SpaceConfigurationError.keychainAccessGroupUnavailable
        }

        let identityStore = KeychainVaultIdentityStore(accessGroup: accessGroup)
        if bootstrapVaultIdentityIfMissing {
            try identityStore.createIfNeeded()
        }
        let vaultID = try identityStore.load()
        let keyStore = KeychainUnlockKeyStore(accessGroup: accessGroup)
        return EncryptedVaultStore(
            fileURL: container.appendingPathComponent(SpaceConfiguration.cacheFileName),
            vaultID: vaultID,
            keyStore: keyStore
        )
    }
}
