import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct SpaceDeviceSession: Codable, Equatable, Sendable {
    public let baseURL: URL
    public let deviceToken: String

    public init(baseURL: URL, deviceToken: String) throws {
        guard Self.isAllowed(baseURL) else { throw SpaceSyncError.insecureEndpoint }
        guard deviceToken.hasPrefix("space_dt_"), (32...256).contains(deviceToken.utf8.count) else {
            throw SpaceSyncError.invalidDeviceToken
        }
        self.baseURL = baseURL
        self.deviceToken = deviceToken
    }

    private static func isAllowed(_ url: URL) -> Bool {
        guard url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            return false
        }
        if url.scheme?.lowercased() == "https" { return true }
#if DEBUG
        return url.scheme?.lowercased() == "http" && ["localhost", "127.0.0.1", "::1"].contains(url.host?.lowercased())
#else
        return false
#endif
    }
}

public struct RemoteSessionIdentity: Codable, Equatable, Sendable {
    public let deviceId: UUID
    public let vaultId: UUID
}

public struct OpaqueSyncMutation: Codable, Equatable, Sendable {
    public let mutationId: UUID
    public let itemId: UUID
    public let baseItemVersion: Int
    public let ciphertext: String?
    public let nonce: String?
    public let wrappedKey: String?
    public let aad: String?

    public init(
        mutationId: UUID,
        itemId: UUID,
        baseItemVersion: Int,
        ciphertext: String?,
        nonce: String?,
        wrappedKey: String?,
        aad: String?
    ) throws {
        guard baseItemVersion >= 0 else { throw SpaceSyncError.invalidEnvelope }
        let tombstone = ciphertext == nil
        guard tombstone == (nonce == nil && wrappedKey == nil && aad == nil) else {
            throw SpaceSyncError.invalidEnvelope
        }
        guard ciphertext?.utf8.count ?? 0 <= 1_048_576,
              nonce?.utf8.count ?? 0 <= 256,
              wrappedKey?.utf8.count ?? 0 <= 8_192,
              aad?.utf8.count ?? 0 <= 8_192 else {
            throw SpaceSyncError.responseTooLarge
        }
        if !tombstone {
            guard !(ciphertext?.isEmpty ?? true),
                  !(nonce?.isEmpty ?? true),
                  !(wrappedKey?.isEmpty ?? true) else {
                throw SpaceSyncError.invalidEnvelope
            }
        }
        self.mutationId = mutationId
        self.itemId = itemId
        self.baseItemVersion = baseItemVersion
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.wrappedKey = wrappedKey
        self.aad = aad
    }
}

public struct AcceptedMutation: Codable, Equatable, Sendable {
    public let mutationId: UUID
    public let itemId: UUID
    public let itemVersion: Int
    public let revision: Int
}

public struct PushResult: Codable, Equatable, Sendable {
    public let accepted: [AcceptedMutation]
    public let cursor: Int
}

public struct RemoteSyncChange: Codable, Equatable, Sendable {
    public let itemId: UUID
    public let itemVersion: Int
    public let revision: Int
    public let mutationId: UUID
    public let ciphertext: String?
    public let nonce: String?
    public let wrappedKey: String?
    public let aad: String?
}

public struct PullResult: Codable, Equatable, Sendable {
    public let changes: [RemoteSyncChange]
    public let cursor: Int
    public let hasMore: Bool
}

public enum SpaceSyncError: Error, Equatable {
    case insecureEndpoint
    case invalidDeviceToken
    case invalidEnvelope
    case invalidRequest
    case unauthorized
    case conflict
    case serverFailure
    case unexpectedResponse
    case responseTooLarge
    case vaultMismatch
}

public actor SpaceSyncClient {
    public static let maximumResponseSize = 2 * 1_024 * 1_024
    private let configuration: SpaceDeviceSession
    private let session: URLSession
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(configuration: SpaceDeviceSession, session: URLSession? = nil) {
        self.configuration = configuration
        if let session {
            self.session = session
        } else {
            let urlConfiguration = URLSessionConfiguration.ephemeral
            urlConfiguration.requestCachePolicy = .reloadIgnoringLocalCacheData
            urlConfiguration.urlCache = nil
            urlConfiguration.httpShouldSetCookies = false
            urlConfiguration.timeoutIntervalForRequest = 30
            urlConfiguration.timeoutIntervalForResource = 60
            self.session = URLSession(configuration: urlConfiguration)
        }
    }

    public func identity() async throws -> RemoteSessionIdentity {
        try await send(path: "v1/session", method: "GET", body: nil)
    }

    public func verifyIdentity(expectedVaultID: UUID) async throws -> RemoteSessionIdentity {
        let remote = try await identity()
        guard remote.vaultId == expectedVaultID else { throw SpaceSyncError.vaultMismatch }
        return remote
    }

    public func push(_ mutations: [OpaqueSyncMutation]) async throws -> PushResult {
        guard (1...100).contains(mutations.count),
              Set(mutations.map(\.mutationId)).count == mutations.count,
              Set(mutations.map(\.itemId)).count == mutations.count else {
            throw SpaceSyncError.invalidRequest
        }
        let result: PushResult = try await send(
            path: "v1/sync/push",
            method: "POST",
            body: encoder.encode(PushRequest(mutations: mutations))
        )
        let requested = Dictionary(uniqueKeysWithValues: mutations.map { ($0.mutationId, $0) })
        guard result.accepted.count == mutations.count,
              result.cursor >= 1,
              result.accepted.allSatisfy({ accepted in
                guard let mutation = requested[accepted.mutationId] else { return false }
                return accepted.itemId == mutation.itemId
                    && accepted.itemVersion == mutation.baseItemVersion + 1
                    && accepted.revision >= 1
                    && accepted.revision <= result.cursor
              }),
              Set(result.accepted.map(\.mutationId)).count == result.accepted.count,
              result.accepted.map(\.revision) == result.accepted.map(\.revision).sorted(),
              result.accepted.last?.revision == result.cursor else {
            throw SpaceSyncError.unexpectedResponse
        }
        return result
    }

    public func pull(after cursor: Int, limit: Int = 200) async throws -> PullResult {
        guard cursor >= 0, (1...500).contains(limit) else { throw SpaceSyncError.invalidRequest }
        let result: PullResult = try await send(
            path: "v1/sync/pull",
            method: "GET",
            query: [
                URLQueryItem(name: "cursor", value: String(cursor)),
                URLQueryItem(name: "limit", value: String(limit))
            ],
            body: nil
        )
        guard result.cursor >= cursor,
              result.changes.count <= limit,
              result.changes.map(\.revision) == result.changes.map(\.revision).sorted(),
              Set(result.changes.map(\.revision)).count == result.changes.count,
              result.changes.allSatisfy({ change in
                guard change.itemVersion >= 1,
                      change.revision > cursor,
                      change.revision <= result.cursor else { return false }
                return (try? OpaqueSyncMutation(
                    mutationId: change.mutationId,
                    itemId: change.itemId,
                    baseItemVersion: change.itemVersion - 1,
                    ciphertext: change.ciphertext,
                    nonce: change.nonce,
                    wrappedKey: change.wrappedKey,
                    aad: change.aad
                )) != nil
              }),
              result.changes.last?.revision == result.cursor || result.changes.isEmpty else {
            throw SpaceSyncError.unexpectedResponse
        }
        return result
    }

    private func send<Response: Decodable>(
        path: String,
        method: String,
        query: [URLQueryItem] = [],
        body: Data?
    ) async throws -> Response {
        guard var components = URLComponents(
            url: configuration.baseURL.appendingPathComponent(path),
            resolvingAgainstBaseURL: false
        ) else { throw SpaceSyncError.unexpectedResponse }
        components.queryItems = query.isEmpty ? nil : query
        guard let url = components.url else { throw SpaceSyncError.unexpectedResponse }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("Bearer \(configuration.deviceToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }

#if canImport(FoundationNetworking)
        let (data, response) = try await session.data(for: request)
        guard data.count <= Self.maximumResponseSize else { throw SpaceSyncError.responseTooLarge }
#else
        let (bytes, response) = try await session.bytes(for: request)
        var data = Data()
        data.reserveCapacity(min(Self.maximumResponseSize, 64 * 1_024))
        for try await byte in bytes {
            guard data.count < Self.maximumResponseSize else {
                session.invalidateAndCancel()
                throw SpaceSyncError.responseTooLarge
            }
            data.append(byte)
        }
#endif
        guard let http = response as? HTTPURLResponse else { throw SpaceSyncError.unexpectedResponse }
        switch http.statusCode {
        case 200: break
        case 400: throw SpaceSyncError.invalidRequest
        case 401, 403: throw SpaceSyncError.unauthorized
        case 409: throw SpaceSyncError.conflict
        case 500...599: throw SpaceSyncError.serverFailure
        default: throw SpaceSyncError.unexpectedResponse
        }
        do { return try decoder.decode(Response.self, from: data) }
        catch { throw SpaceSyncError.unexpectedResponse }
    }
}

private struct PushRequest: Codable, Sendable {
    let mutations: [OpaqueSyncMutation]
}
