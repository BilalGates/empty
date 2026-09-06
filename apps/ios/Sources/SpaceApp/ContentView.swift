import SwiftUI

struct ContentView: View {
    let model: VaultViewModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingSyncSetup = false
    @State private var showingCredentialEditor = false

    var body: some View {
        NavigationStack {
            Group {
                switch model.state {
                case .locked:
                    ContentUnavailableView(
                        "Vault locked",
                        systemImage: "lock.fill",
                        description: Text("Unlock locally to manage credentials.")
                    )
                case .unlocking:
                    ProgressView("Unlocking…")
                case .unlocked:
                    if model.credentials.isEmpty {
                        ContentUnavailableView {
                            Label("No logins", systemImage: "key")
                        } description: {
                            Text("Add your first login to use it with AutoFill.")
                        } actions: {
                            Button("Add login") { showingCredentialEditor = true }
                                .buttonStyle(.borderedProminent)
                        }
                    } else {
                        List(model.credentials) { credential in
                            NavigationLink {
                                CredentialDetailView(credential: credential, model: model)
                            } label: {
                                VStack(alignment: .leading) {
                                    Text(credential.title)
                                    Text(credential.username)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                case .failed(let message):
                    ContentUnavailableView(
                        "Space unavailable",
                        systemImage: "exclamationmark.shield",
                        description: Text(message)
                    )
                }
            }
            .navigationTitle("Space")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Sync settings", systemImage: syncSymbol) {
                        showingSyncSetup = true
                    }
                    .accessibilityHint(syncAccessibilityHint)
                }
                ToolbarItem(placement: .primaryAction) {
                    switch model.state {
                    case .unlocked:
                        Menu("Vault actions", systemImage: "ellipsis.circle") {
                            Button("Add login", systemImage: "plus") {
                                showingCredentialEditor = true
                            }
                            Button("Lock", systemImage: "lock") { model.lock() }
                        }
                    case .unlocking:
                        EmptyView()
                    default:
                        Button("Unlock", systemImage: "lock.open") {
                            Task { await model.unlock() }
                        }
                    }
                }
                ToolbarItem(placement: .bottomBar) {
                    if case .failed = model.state {
                        Button("Create local vault") {
                            Task { await model.createLocalVault() }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $showingSyncSetup) {
            SyncSetupView(model: model)
        }
        .sheet(isPresented: $showingCredentialEditor) {
            CredentialEditorView(model: model)
        }
        .task { await model.refreshSyncState() }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active {
                showingCredentialEditor = false
                showingSyncSetup = false
                model.lock()
            }
        }
        .overlay {
            if scenePhase != .active {
                Rectangle()
                    .fill(.background)
                    .ignoresSafeArea()
                    .overlay { Image(systemName: "lock.fill").accessibilityLabel("Space locked") }
            }
        }
    }

    private var syncSymbol: String {
        switch model.syncState {
        case .notConfigured: "arrow.triangle.2.circlepath"
        case .checking: "arrow.triangle.2.circlepath.circle"
        case .connected: "checkmark.icloud"
        case .failed: "exclamationmark.icloud"
        }
    }

    private var syncAccessibilityHint: String {
        switch model.syncState {
        case .notConfigured: "Synchronization is not configured."
        case .checking: "Checking the synchronization server."
        case .connected: "The synchronization server is connected."
        case .failed: "The synchronization server could not be reached."
        }
    }
}

private struct SyncSetupView: View {
    let model: VaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var endpoint = ""
    @State private var deviceToken = ""
    @State private var attempted = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://sync.example.com", text: $endpoint)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Device token", text: $deviceToken)
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } header: {
                    Text("Server")
                } footer: {
                    Text("The token authorizes encrypted synchronization but cannot unlock your vault.")
                }
                if attempted && model.syncState == .failed {
                    Section {
                        Text("Space could not verify this server, token, and vault combination.")
                            .foregroundStyle(.red)
                            .accessibilityLabel("Sync connection failed")
                    }
                }
            }
            .navigationTitle("Synchronization")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.syncState == .checking ? "Checking…" : "Connect") {
                        attempted = true
                        Task {
                            if await model.connectSync(endpoint: endpoint, deviceToken: deviceToken) {
                                deviceToken.removeAll(keepingCapacity: false)
                                dismiss()
                            }
                        }
                    }
                    .disabled(endpoint.isEmpty || deviceToken.isEmpty || model.syncState == .checking)
                }
            }
        }
        .interactiveDismissDisabled(model.syncState == .checking)
    }
}
