import Foundation
import Security

/// Stores the active local vault namespace as OS-authenticated, device-only metadata.
/// The extension can read it but never creates or replaces it.
public final class KeychainVaultIdentityStore: @unchecked Sendable {
    private let accessGroup: String

    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    public func createIfNeeded() throws {
        switch copyData() {
        case .success:
            return
        case .failure(.unavailable):
            break
        case .failure(let error):
            throw error
        }

        var bytes = Data(count: 16)
        let randomStatus = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw VaultIdentityStoreError.unexpectedStatus(randomStatus)
        }
        defer { bytes.resetBytes(in: bytes.indices) }

        var query = baseQuery
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = bytes
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw VaultIdentityStoreError.unexpectedStatus(status)
        }
    }

    public func load() throws -> UUID {
        let data = try copyData().get()
        guard data.count == 16 else { throw VaultIdentityStoreError.invalidIdentity }
        return data.withUnsafeBytes { rawBuffer in
            let value = rawBuffer.bindMemory(to: UInt8.self)
            return UUID(uuid: (
                value[0], value[1], value[2], value[3],
                value[4], value[5], value[6], value[7],
                value[8], value[9], value[10], value[11],
                value[12], value[13], value[14], value[15]
            ))
        }
    }

    private func copyData() -> Result<Data, VaultIdentityStoreError> {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return .failure(.unavailable) }
            return .failure(.unexpectedStatus(status))
        }
        guard let data = item as? Data else { return .failure(.invalidIdentity) }
        return .success(data)
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SpaceConfiguration.vaultIdentityService,
            kSecAttrAccount as String: SpaceConfiguration.vaultIdentityAccount,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false
        ]
    }
}

public enum VaultIdentityStoreError: Error, Equatable {
    case unavailable
    case invalidIdentity
    case unexpectedStatus(OSStatus)
}
