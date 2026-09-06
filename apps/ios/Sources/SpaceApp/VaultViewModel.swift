import AuthenticationServices
import Foundation
import Observation
import SpaceShared

@MainActor
@Observable
final class VaultViewModel {
    enum State: Equatable { case locked, unlocking, unlocked, failed(String) }

    private(set) var state: State = .locked
    private(set) var credentials: [VaultCredential] = []
    private var store: EncryptedVaultStore?

    func unlock() async {
        state = .unlocking
        do {
            let store = try store ?? SpaceEnvironment.makeStore()
            let snapshot = try await store.load(
                interaction: .allowed(reason: "Unlock your credentials")
            )
            self.store = store
            credentials = snapshot.credentials
            state = .unlocked
            try await refreshIdentityStore()
        } catch UnlockKeyStoreError.unavailable {
            state = .failed("Create the local vault before unlocking.")
        } catch UnlockKeyStoreError.cancelled {
            state = .locked
        } catch {
            state = .failed("The vault could not be unlocked.")
        }
    }

    func createLocalVault() async {
        do {
            let store = try store ?? SpaceEnvironment.makeStore(
                bootstrapVaultIdentityIfMissing: true
            )
            try await store.save(
                VaultSnapshot(credentials: []),
                interaction: .allowed(reason: "Protect your local vault")
            )
            self.store = store
            credentials = []
            state = .unlocked
            try await refreshIdentityStore()
        } catch UnlockKeyStoreError.cancelled {
            state = .locked
        } catch {
            state = .failed("The local vault could not be created.")
        }
    }

    func lock() {
        credentials.removeAll(keepingCapacity: false)
        state = .locked
    }

    private func refreshIdentityStore() async throws {
        let identities = credentials.map { credential in
            ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(
                    identifier: credential.serviceIdentifier,
                    type: .URL
                ),
                user: credential.username,
                recordIdentifier: credential.id.uuidString
            )
        }
        // AutoFill identity metadata never contains the credential password.
        try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
    }
}
