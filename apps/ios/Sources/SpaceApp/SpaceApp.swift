import SwiftUI

@main
struct SpaceApp: App {
    @State private var model = VaultViewModel()

    var body: some Scene {
        WindowGroup { ContentView(model: model) }
    }
}

