import Foundation

/// Checks a complete URL origin before any preview credential is offered or released.
/// Domain and app identifiers do not carry enough information to bind scheme and port.
public enum SpaceAutofillOriginPolicy {
    public enum ServiceKind: Sendable { case url, domain, app }

    public struct Service: Sendable {
        public let identifier: String
        public let kind: ServiceKind

        public init(identifier: String, kind: ServiceKind) {
            self.identifier = identifier
            self.kind = kind
        }
    }

    public static func requestedOrigin(_ service: Service) -> String? {
        guard service.kind == .url,
              let schemeEnd = service.identifier.range(of: "://") else { return nil }
        let authorityStart = schemeEnd.upperBound
        let rest = service.identifier[authorityStart...]
        let authorityEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? service.identifier.endIndex
        let origin = String(service.identifier[..<authorityEnd])
        guard SpacePasswordOrigin.isCanonical(origin),
              let components = URLComponents(string: service.identifier),
              components.string == service.identifier,
              components.user == nil, components.password == nil,
              components.host != nil else { return nil }
        return origin
    }

    public static func matches(_ credential: VaultCredential, service: Service) -> Bool {
        guard let requested = requestedOrigin(service),
              let saved = VaultCredential.canonicalServiceIdentifier(credential.serviceIdentifier),
              SpacePasswordOrigin.isCanonical(saved) else { return false }
        return saved == requested
    }

    public static func matching(_ credentials: [VaultCredential], services: [Service]) -> [VaultCredential] {
        guard !services.isEmpty else { return [] }
        return credentials.filter { credential in services.contains { matches(credential, service: $0) } }
    }

    public static func selectedCredential(
        id: UUID, in credentials: [VaultCredential], service: Service
    ) -> VaultCredential? {
        credentials.first { $0.id == id && matches($0, service: service) }
    }
}
