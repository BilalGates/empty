import AuthenticationServices
import Foundation
import Observation
import SpaceShared

@MainActor
@Observable
final class VaultViewModel {
    enum State: Equatable { case locked, unlocking, unlocked, failed(String) }
    enum SyncState: Equatable { case notConfigured, checking, connected, failed }

    private(set) var state: State = .locked
    private(set) var credentials: [VaultCredential] = []
    private(set) var syncState: SyncState = .notConfigured
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

    func refreshSyncState() async {
        do {
            let saved = try SpaceEnvironment.makeDeviceSessionStore().load()
            syncState = .checking
            let client = SpaceSyncClient(configuration: saved)
            _ = try await client.verifyIdentity(
                expectedVaultID: SpaceEnvironment.vaultIdentity()
            )
            syncState = .connected
        } catch DeviceSessionStoreError.unavailable {
            syncState = .notConfigured
        } catch {
            syncState = .failed
        }
    }

    func connectSync(endpoint: String, deviceToken: String) async -> Bool {
        syncState = .checking
        do {
            guard let url = URL(string: endpoint.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                throw SpaceSyncError.insecureEndpoint
            }
            let configuration = try SpaceDeviceSession(
                baseURL: url,
                deviceToken: deviceToken.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            let client = SpaceSyncClient(configuration: configuration)
            _ = try await client.verifyIdentity(
                expectedVaultID: SpaceEnvironment.vaultIdentity()
            )
            try SpaceEnvironment.makeDeviceSessionStore().save(configuration)
            syncState = .connected
            return true
        } catch {
            syncState = .failed
            return false
        }
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
