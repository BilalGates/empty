import Foundation

public enum EmptyEnvironment {
    public static func vaultIdentity() throws -> UUID {
        try KeychainVaultIdentityStore(accessGroup: try keychainAccessGroup()).load()
    }

    public static func makeDeviceSessionStore() throws -> KeychainDeviceSessionStore {
        KeychainDeviceSessionStore(accessGroup: try keychainAccessGroup())
    }

    public static func makeStore(
        bootstrapVaultIdentityIfMissing: Bool = false
    ) throws -> EncryptedVaultStore {
        let container = try EmptyConfiguration.sharedContainerURL()
        let accessGroup = try keychainAccessGroup()

        let identityStore = KeychainVaultIdentityStore(accessGroup: accessGroup)
        if bootstrapVaultIdentityIfMissing {
            try identityStore.createIfNeeded()
        }
        let vaultID = try identityStore.load()
        let keyStore = KeychainUnlockKeyStore(accessGroup: accessGroup)
        return EncryptedVaultStore(
            fileURL: container.appendingPathComponent(EmptyConfiguration.cacheFileName),
            vaultID: vaultID,
            keyStore: keyStore
        )
    }

    private static func keychainAccessGroup() throws -> String {
        guard let accessGroup = Bundle.main.object(
            forInfoDictionaryKey: "EmptyKeychainAccessGroup"
        ) as? String else {
            throw EmptyConfigurationError.keychainAccessGroupUnavailable
        }
        guard !accessGroup.isEmpty, !accessGroup.contains("$(") else {
            throw EmptyConfigurationError.keychainAccessGroupUnavailable
        }

        return accessGroup
    }
}
