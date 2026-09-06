import SwiftUI
import SpaceShared

struct CredentialEditorView: View {
    let model: VaultViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var title = ""
    @State private var website = ""
    @State private var username = ""
    @State private var password = ""
    @State private var attempted = false

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
            .navigationTitle("New login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.isSaving ? "Saving…" : "Save") {
                        attempted = true
                        Task {
                            if await model.addCredential(
                                title: title,
                                serviceIdentifier: website,
                                username: username,
                                password: password
                            ) {
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
