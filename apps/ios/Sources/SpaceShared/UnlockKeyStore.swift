import CryptoKit
import Foundation
import LocalAuthentication
import Security

public protocol UnlockKeyProviding: Sendable {
    func createIfNeeded() throws
    func load(interaction: UnlockInteraction) throws -> SymmetricKey
    func delete() throws
}

public enum UnlockInteraction: Sendable {
    case allowed(reason: String)
    case forbidden
}

public enum UnlockKeyStoreError: Error, Equatable {
    case unavailable
    case interactionRequired
    case cancelled
    case invalidated
    case unexpectedStatus(OSStatus)
}

public final class KeychainUnlockKeyStore: UnlockKeyProviding, @unchecked Sendable {
    private let accessGroup: String

    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    public func createIfNeeded() throws {
        var existenceQuery = baseQuery
        existenceQuery[kSecReturnData as String] = false
        existenceQuery[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        let existing = SecItemCopyMatching(existenceQuery as CFDictionary, nil)
        if existing == errSecSuccess || existing == errSecInteractionNotAllowed { return }
        guard existing == errSecItemNotFound else { throw map(existing) }

        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryCurrentSet],
            &accessError
        ) else {
            throw UnlockKeyStoreError.unavailable
        }

        var keyBytes = Data(count: 32)
        let status = keyBytes.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw map(status) }
        defer { keyBytes.resetBytes(in: keyBytes.indices) }

        var query = baseQuery
        query[kSecAttrAccessControl as String] = accessControl
        query[kSecValueData as String] = keyBytes
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw map(addStatus)
        }
    }

    public func load(interaction: UnlockInteraction) throws -> SymmetricKey {
        let context = LAContext()
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        switch interaction {
        case .allowed(let reason):
            query[kSecUseAuthenticationContext as String] = context
            query[kSecUseOperationPrompt as String] = reason
        case .forbidden:
            context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, data.count == 32 else {
            throw map(status)
        }
        return SymmetricKey(data: data)
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw map(status) }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SpaceConfiguration.keychainService,
            kSecAttrAccount as String: SpaceConfiguration.keychainAccount,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false
        ]
    }

    private func map(_ status: OSStatus) -> UnlockKeyStoreError {
        switch status {
        case errSecInteractionNotAllowed: return .interactionRequired
        case errSecUserCanceled: return .cancelled
        case errSecAuthFailed: return .invalidated
        case errSecItemNotFound: return .unavailable
        default: return .unexpectedStatus(status)
        }
    }
}
