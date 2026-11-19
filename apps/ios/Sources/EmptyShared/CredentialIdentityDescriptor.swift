import Foundation

public struct CredentialIdentityDescriptor: Equatable, Sendable {
    public let recordIdentifier: String
    public let serviceIdentifier: String
    public let username: String

    public init(credential: VaultCredential) {
        recordIdentifier = credential.id.uuidString
        serviceIdentifier = credential.serviceIdentifier
        username = credential.username
    }
}
