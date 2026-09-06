import AuthenticationServices
import SpaceShared
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var credentials: [VaultCredential] = []
    private var store: EncryptedVaultStore?

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        Task { @MainActor in
            do {
                let store = try store ?? SpaceEnvironment.makeStore()
                let snapshot = try await store.load(
                    interaction: .allowed(reason: "Unlock credentials for AutoFill")
                )
                self.store = store
                credentials = Self.matches(snapshot.credentials, services: serviceIdentifiers)
                showCredentialList()
            } catch UnlockKeyStoreError.cancelled {
                cancel(code: .userCanceled)
            } catch {
                cancel(code: .failed)
            }
        }
    }

    override func provideCredentialWithoutUserInteraction(
        for credentialRequest: any ASCredentialRequest
    ) {
        guard let recordID = Self.recordID(from: credentialRequest) else {
            cancel(code: .credentialIdentityNotFound)
            return
        }
        Task { @MainActor in
            do {
                let store = try store ?? SpaceEnvironment.makeStore()
                let snapshot = try await store.load(interaction: .forbidden)
                guard let credential = snapshot.credentials.first(where: { $0.id == recordID }) else {
                    cancel(code: .credentialIdentityNotFound)
                    return
                }
                complete(credential)
            } catch UnlockKeyStoreError.interactionRequired {
                cancel(code: .userInteractionRequired)
            } catch {
                cancel(code: .failed)
            }
        }
    }

    override func prepareInterfaceToProvideCredential(
        for credentialRequest: any ASCredentialRequest
    ) {
        guard let recordID = Self.recordID(from: credentialRequest) else {
            cancel(code: .credentialIdentityNotFound)
            return
        }
        Task { @MainActor in
            do {
                let store = try store ?? SpaceEnvironment.makeStore()
                let snapshot = try await store.load(
                    interaction: .allowed(reason: "Unlock the selected credential")
                )
                guard let credential = snapshot.credentials.first(where: { $0.id == recordID }) else {
                    cancel(code: .credentialIdentityNotFound)
                    return
                }
                complete(credential)
            } catch UnlockKeyStoreError.cancelled {
                cancel(code: .userCanceled)
            } catch {
                cancel(code: .failed)
            }
        }
    }

    private func showCredentialList() {
        setViewControllers([
            CredentialListViewController(credentials: credentials) { [weak self] in
                self?.complete($0)
            }
        ], animated: false)
    }

    private func complete(_ credential: VaultCredential) {
        extensionContext.completeRequest(
            withSelectedCredential: ASPasswordCredential(
                user: credential.username,
                password: credential.password
            ),
            completionHandler: nil
        )
        credentials.removeAll(keepingCapacity: false)
    }

    private func cancel(code: ASExtensionError.Code) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        )
        credentials.removeAll(keepingCapacity: false)
    }

    static func recordID(from request: any ASCredentialRequest) -> UUID? {
        guard let request = request as? ASPasswordCredentialRequest,
              let identifier = request.credentialIdentity.recordIdentifier
        else { return nil }
        return UUID(uuidString: identifier)
    }

    static func matches(
        _ credentials: [VaultCredential],
        services: [ASCredentialServiceIdentifier]
    ) -> [VaultCredential] {
        credentials.filter { $0.matches(serviceIdentifiers: services.map(\.identifier)) }
    }

    override func didReceiveMemoryWarning() {
        credentials.removeAll(keepingCapacity: false)
        super.didReceiveMemoryWarning()
    }
}

private final class CredentialListViewController: UITableViewController {
    private var credentials: [VaultCredential]
    private let selection: (VaultCredential) -> Void

    init(credentials: [VaultCredential], selection: @escaping (VaultCredential) -> Void) {
        self.credentials = credentials
        self.selection = selection
        super.init(style: .insetGrouped)
        title = "Space"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        credentials.count
    }

    override func tableView(
        _ tableView: UITableView,
        cellForRowAt indexPath: IndexPath
    ) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        let credential = credentials[indexPath.row]
        cell.textLabel?.text = credential.title
        cell.detailTextLabel?.text = credential.username
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let credential = credentials[indexPath.row]
        credentials.removeAll(keepingCapacity: false)
        selection(credential)
    }

    deinit { credentials.removeAll(keepingCapacity: false) }
}

