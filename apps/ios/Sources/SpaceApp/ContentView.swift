import SwiftUI

struct ContentView: View {
    let model: VaultViewModel
    @Environment(\.scenePhase) private var scenePhase

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
                    List(model.credentials) { credential in
                        VStack(alignment: .leading) {
                            Text(credential.title)
                            Text(credential.username)
                                .font(.caption)
                                .foregroundStyle(.secondary)
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
                ToolbarItem(placement: .primaryAction) {
                    switch model.state {
                    case .unlocked:
                        Button("Lock", systemImage: "lock") { model.lock() }
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
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { model.lock() }
        }
    }
}

