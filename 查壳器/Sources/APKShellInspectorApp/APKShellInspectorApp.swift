import SwiftUI

@main
struct APKShellInspectorMacApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 760, height: 460)
    }
}
