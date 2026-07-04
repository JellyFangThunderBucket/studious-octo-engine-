import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "curlybraces.square")
                .font(.system(size: 56, weight: .semibold))
                .foregroundStyle(.blue)
            Text("Code Snippet Messages")
                .font(.title2.bold())
            Text("Open Messages, select this app from the iMessage app drawer, and send highlighted, copyable code cards.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
        }
        .padding()
    }
}
