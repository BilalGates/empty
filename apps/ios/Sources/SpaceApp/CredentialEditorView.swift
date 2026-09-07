import SwiftUI
import SpaceShared

struct CredentialEditorView: View {
    let model: VaultViewModel
    let credential: VaultCredential?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var title: String
    @State private var website: String
    @State private var username: String
    @State private var password: String
    @State private var attempted = false

    init(model: VaultViewModel, credential: VaultCredential? = nil) {
        self.model = model
        self.credential = credential
        _title = State(initialValue: credential?.title ?? "")
        _website = State(initialValue: credential?.serviceIdentifier ?? "")
        _username = State(initialValue: credential?.username ?? "")
        _password = State(initialValue: credential?.password ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Login") {
                    TextField("Name", text: $title)
                        .textContentType(.name)
                    TextField("Website", text: $website)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Username", text: $username)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                }
                if attempted && model.mutationError != nil {
                    Section {
                        Text(model.mutationError ?? "The login could not be saved.")
                            .foregroundStyle(.red)
                            .accessibilityLabel("Save failed")
                    }
                }
            }
            .navigationTitle(credential == nil ? "New login" : "Edit login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.isSaving ? "Saving…" : "Save") {
                        attempted = true
                        Task {
                            let saved = if let credential {
                                await model.updateCredential(
                                    id: credential.id,
                                    title: title,
                                    serviceIdentifier: website,
                                    username: username,
                                    password: password
                                )
                            } else {
                                await model.addCredential(
                                    title: title,
                                    serviceIdentifier: website,
                                    username: username,
                                    password: password
                                )
                            }
                            if saved {
                                password.removeAll(keepingCapacity: false)
                                dismiss()
                            }
                        }
                    }
                    .disabled(
                        title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || website.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || password.isEmpty
                        || model.isSaving
                    )
                }
            }
        }
        .interactiveDismissDisabled(model.isSaving)
        .onChange(of: scenePhase) { _, phase in
            if phase != .active {
                password.removeAll(keepingCapacity: false)
                dismiss()
            }
        }
    }
}
