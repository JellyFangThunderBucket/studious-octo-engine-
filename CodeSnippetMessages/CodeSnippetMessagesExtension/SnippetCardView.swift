import SwiftUI
import UIKit

struct SnippetCardView: View {
    let snippet: CodeSnippet
    var compact: Bool = false
    @State private var expanded = false
    @State private var copied = false
    @Environment(\.colorScheme) private var scheme
    private var lines: [String] { snippet.code.components(separatedBy: .newlines) }
    private var shouldCollapse: Bool { lines.count > 24 || snippet.code.count > 2_500 }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if !snippet.details.isEmpty { Text(snippet.details).font(.caption).foregroundStyle(.secondary) }
            ScrollView([.horizontal, .vertical]) {
                HStack(alignment: .top, spacing: 10) {
                    lineNumbers
                    Text(SyntaxHighlighter.highlighted(snippet.code, language: snippet.language, scheme: scheme))
                        .textSelection(.enabled)
                        .accessibilityLabel("Highlighted code snippet")
                }.padding(12)
            }
            .frame(maxHeight: compact || (shouldCollapse && !expanded) ? 260 : 520)
            .background(codeBackground)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            if shouldCollapse { Button(expanded ? "Collapse" : "Expand full snippet") { withAnimation(.spring()) { expanded.toggle() } }.font(.caption.bold()) }
        }
        .padding(14)
        .background(cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        .shadow(color: .black.opacity(scheme == .dark ? 0.35 : 0.12), radius: 14, y: 6)
        .accessibilityElement(children: .contain)
    }
    private var header: some View { HStack(spacing: 10) { Image(systemName: "curlybraces.square.fill").foregroundStyle(.blue); VStack(alignment: .leading) { Text(snippet.displayTitle).font(.headline); Text("\(snippet.language.templateSubtitle) • \(snippet.createdAt.formatted(date: .abbreviated, time: .shortened))").font(.caption2).foregroundStyle(.secondary) }; Spacer(); Button { UIPasteboard.general.string = snippet.code; copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { copied = false } } label: { Label(copied ? "Copied" : "Copy All", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc") }.buttonStyle(.borderedProminent).controlSize(.small).accessibilityLabel("Copy all raw code") } }
    private var lineNumbers: some View { VStack(alignment: .trailing, spacing: 0) { ForEach(lines.indices, id: \.self) { Text("\($0 + 1)").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).frame(height: 16) } }.accessibilityHidden(true) }
    private var cardBackground: AnyShapeStyle { AnyShapeStyle(scheme == .dark ? Color(white: 0.10).gradient : Color.white.gradient) }
    private var codeBackground: AnyShapeStyle { AnyShapeStyle(scheme == .dark ? Color.black.opacity(0.55).gradient : Color(white: 0.96).gradient) }
}
