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
    private(set) var isSaving = false
    private(set) var mutationError: String?
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

    func addCredential(
        title: String,
        serviceIdentifier: String,
        username: String,
        password: String
    ) async -> Bool {
        guard let normalizedService = VaultCredential.canonicalServiceIdentifier(serviceIdentifier),
              !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !password.isEmpty else {
            mutationError = "Enter a valid website, name, and password."
            return false
        }
        let credential = VaultCredential(
            title: title.trimmingCharacters(in: .whitespacesAndNewlines),
            serviceIdentifier: normalizedService,
            username: username,
            password: password
        )
        return await persist(
            credentials + [credential],
            reason: "Save this login to your vault"
        )
    }

    func deleteCredential(id: UUID) async -> Bool {
        await persist(
            credentials.filter { $0.id != id },
            reason: "Delete this login from your vault"
        )
    }

    private func persist(_ replacement: [VaultCredential], reason: String) async -> Bool {
        guard let store else {
            mutationError = "Unlock the vault before changing it."
            return false
        }
        isSaving = true
        mutationError = nil
        defer { isSaving = false }
        do {
            try await store.save(
                VaultSnapshot(credentials: replacement),
                interaction: .allowed(reason: reason)
            )
            credentials = replacement
            try await refreshIdentityStore()
            return true
        } catch UnlockKeyStoreError.cancelled {
            mutationError = "Authentication was cancelled."
        } catch {
            mutationError = "The local vault could not be updated."
        }
        return false
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
