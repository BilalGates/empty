import Foundation
import Security

public protocol DeviceSessionStoring: Sendable {
    func save(_ session: SpaceDeviceSession) throws
    func load() throws -> SpaceDeviceSession
    func delete() throws
}

public enum DeviceSessionStoreError: Error, Equatable {
    case unavailable
    case invalidRecord
    case unexpectedStatus(OSStatus)
}

public final class KeychainDeviceSessionStore: DeviceSessionStoring, @unchecked Sendable {
    private let accessGroup: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    public func save(_ session: SpaceDeviceSession) throws {
        let data = try encoder.encode(session)
        var query = baseQuery
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw map(update) }
        attributes.forEach { query[$0.key] = $0.value }
        let add = SecItemAdd(query as CFDictionary, nil)
        guard add == errSecSuccess else { throw map(add) }
    }

    public func load() throws -> SpaceDeviceSession {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { throw map(status) }
        guard let data = item as? Data,
              data.count <= 4_096,
              let decoded = try? decoder.decode(SpaceDeviceSession.self, from: data),
              let result = try? SpaceDeviceSession(
                baseURL: decoded.baseURL,
                deviceToken: decoded.deviceToken
              ) else {
            throw DeviceSessionStoreError.invalidRecord
        }
        return result
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw map(status) }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SpaceConfiguration.deviceSessionService,
            kSecAttrAccount as String: SpaceConfiguration.deviceSessionAccount,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false
        ]
    }

    private func map(_ status: OSStatus) -> DeviceSessionStoreError {
        if status == errSecItemNotFound { return .unavailable }
        return .unexpectedStatus(status)
    }
}
