import SwiftUI

struct SnippetComposerView: View {
    var onSend: (CodeSnippet) -> Void
    @State private var title = ""
    @State private var details = ""
    @State private var code = sampleCode
    @State private var selectedLanguage: SnippetLanguage = .auto
    @State private var errorMessage: String?
    private var effectiveLanguage: SnippetLanguage { selectedLanguage == .auto ? SyntaxHighlighter.detectLanguage(for: code) : selectedLanguage }
    var body: some View {
        NavigationView {
            Form {
                Section("Metadata") { TextField("Optional title", text: $title); TextField("Optional description", text: $details); Picker("Language", selection: $selectedLanguage) { ForEach(SnippetLanguage.allCases) { Text($0.rawValue).tag($0) } }.accessibilityLabel("Snippet language picker"); Text("Detected: \(effectiveLanguage.rawValue)").font(.caption).foregroundStyle(.secondary) }
                Section("Code") { TextEditor(text: $code).font(.system(.body, design: .monospaced)).frame(minHeight: 170).accessibilityLabel("Code input editor") }
                if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red).font(.caption) } }
                Section("Preview") { SnippetCardView(snippet: makeSnippet(), compact: true).listRowInsets(EdgeInsets()).padding(.vertical, 8) }
            }
            .navigationTitle("Code Snippet")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Send Snippet") { send() }.disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) } }
        }
    }
    private func makeSnippet() -> CodeSnippet { CodeSnippet(title: title, details: details, code: code, language: effectiveLanguage, createdAt: Date()) }
    private func send() { let snippet = makeSnippet(); do { _ = try SnippetCodec.makeURL(for: snippet); onSend(snippet) } catch { errorMessage = error.localizedDescription } }
}
private let sampleCode = """
{
  "message": "Paste any JSON, Swift, JavaScript, Python, Markdown, or text here",
  "copyable": true
}
"""
