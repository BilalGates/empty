import SwiftUI

@main
struct EmptyApp: App {
    @State private var model = VaultViewModel()

    var body: some Scene {
        WindowGroup { ContentView(model: model) }
    }
}

