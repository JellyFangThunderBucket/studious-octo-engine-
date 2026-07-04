import SwiftUI

struct ExtensionRootView: View {
    let activeSnippet: CodeSnippet?
    var onSend: (CodeSnippet) -> Void
    var body: some View {
        if let activeSnippet { ScrollView { SnippetCardView(snippet: activeSnippet).padding() }.background(Color(.systemGroupedBackground)) } else { SnippetComposerView(onSend: onSend) }
    }
}
