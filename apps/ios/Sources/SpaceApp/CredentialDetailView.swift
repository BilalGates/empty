import SwiftUI
import SpaceShared
import UniformTypeIdentifiers
import UIKit

struct CredentialDetailView: View {
    let credential: VaultCredential
    let model: VaultViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var revealingPassword = false
    @State private var copiedField: String?
    @State private var confirmingDelete = false
    @State private var showingEditor = false

    private var currentCredential: VaultCredential {
        model.credentials.first(where: { $0.id == credential.id }) ?? credential
    }

    var body: some View {
        List {
            Section("Website") {
                Text(currentCredential.serviceIdentifier)
                    .textSelection(.enabled)
            }
            Section("Username") {
                SecretRow(
                    value: currentCredential.username,
                    concealed: false,
                    actionName: "Copy username"
                ) { copy(currentCredential.username, field: "Username") }
            }
            Section("Password") {
                SecretRow(
                    value: revealingPassword ? currentCredential.password : String(repeating: "•", count: 12),
                    concealed: !revealingPassword,
                    actionName: "Copy password"
                ) { copy(currentCredential.password, field: "Password") }
                Button(revealingPassword ? "Hide password" : "Show password") {
                    revealingPassword.toggle()
                    if revealingPassword {
                        Task {
                            try? await Task.sleep(for: .seconds(10))
                            revealingPassword = false
                        }
                    }
                }
            }
            if let copiedField {
                Section {
                    Text("\(copiedField) copied for 60 seconds.")
                        .foregroundStyle(.secondary)
                        .accessibilityAddTraits(.isStaticText)
                }
            }
            Section {
                Button("Delete login", role: .destructive) { confirmingDelete = true }
            }
        }
        .navigationTitle(currentCredential.title)
        .navigationBarTitleDisplayMode(.inline)
        .privacySensitive()
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Edit") { showingEditor = true }
            }
        }
        .sheet(isPresented: $showingEditor) {
            CredentialEditorView(model: model, credential: currentCredential)
        }
        .confirmationDialog(
            "Delete this login?",
            isPresented: $confirmingDelete,
            titleVisibility: .visible
        ) {
            Button("Delete login", role: .destructive) {
                Task {
                    if await model.deleteCredential(id: credential.id) { dismiss() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes it from the local iPhone vault and AutoFill.")
        }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { revealingPassword = false }
        }
    }

    private func copy(_ value: String, field: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(60)
            ]
        )
        let copiedChangeCount = UIPasteboard.general.changeCount
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(60))
            guard UIPasteboard.general.changeCount == copiedChangeCount else { return }
            UIPasteboard.general.items = []
        }
        copiedField = field
    }
}

private struct SecretRow: View {
    let value: String
    let concealed: Bool
    let actionName: String
    let copy: () -> Void

    var body: some View {
        HStack {
            Text(value)
                .lineLimit(1)
                .truncationMode(.middle)
                .accessibilityLabel(concealed ? "Concealed password" : value)
            Spacer()
            Button(actionName, systemImage: "doc.on.doc", action: copy)
                .labelStyle(.iconOnly)
                .accessibilityLabel(actionName)
        }
    }
}
