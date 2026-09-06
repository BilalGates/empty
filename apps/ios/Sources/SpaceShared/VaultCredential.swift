import Foundation

public struct VaultCredential: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public var title: String
    public var serviceIdentifier: String
    public var username: String
    public var password: String

    public init(
        id: UUID = UUID(),
        title: String,
        serviceIdentifier: String,
        username: String,
        password: String
    ) {
        self.id = id
        self.title = title
        self.serviceIdentifier = serviceIdentifier
        self.username = username
        self.password = password
    }

    public func matches(serviceIdentifiers: [String]) -> Bool {
        guard !serviceIdentifiers.isEmpty else { return true }
        return serviceIdentifiers.contains { requested in
            Self.normalizedHost(requested) == Self.normalizedHost(serviceIdentifier)
        }
    }

    public static func canonicalServiceIdentifier(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let components = URLComponents(string: candidate),
              let host = components.host?.lowercased(),
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              ["https", "http"].contains(components.scheme?.lowercased()) else { return nil }
        if components.scheme?.lowercased() == "http"
            && !["localhost", "127.0.0.1", "::1"].contains(host) { return nil }
        var origin = URLComponents()
        origin.scheme = components.scheme?.lowercased()
        origin.host = host
        origin.port = components.port
        return origin.url?.absoluteString
    }

    private static func normalizedHost(_ value: String) -> String? {
        let candidate = value.contains("://") ? value : "https://\(value)"
        return URLComponents(string: candidate)?.host?
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
    }
}

public struct VaultSnapshot: Codable, Equatable, Sendable {
    public static let schemaVersion = 1
    public var credentials: [VaultCredential]

    public init(credentials: [VaultCredential]) {
        self.credentials = credentials
    }
}
