import SwiftUI
import UIKit

struct SyntaxHighlighter {
    struct Theme { let keyword: Color; let string: Color; let number: Color; let comment: Color; let punctuation: Color; let plain: Color
        static func current(_ scheme: ColorScheme) -> Theme { scheme == .dark ? Theme(keyword: .cyan, string: .green, number: .orange, comment: .gray, punctuation: .purple, plain: .white) : Theme(keyword: .blue, string: .green, number: .orange, comment: .gray, punctuation: .purple, plain: .primary) }
    }
    static func detectLanguage(for code: String) -> SnippetLanguage {
        let t = code.trimmingCharacters(in: .whitespacesAndNewlines)
        if (t.hasPrefix("{") && t.hasSuffix("}")) || (t.hasPrefix("[") && t.hasSuffix("]")) { return .json }
        if t.contains("```") || t.hasPrefix("# ") || t.contains("\n## ") { return .markdown }
        if t.contains("import SwiftUI") || t.contains("func ") && t.contains("let ") { return .swift }
        if t.contains("def ") || t.contains("import ") && t.contains(":") { return .python }
        if t.contains("function ") || t.contains("const ") || t.contains("=>") { return .javascript }
        if t.contains("<html") || t.contains("</") { return .html }
        if t.contains("SELECT ") || t.contains(" FROM ") { return .sql }
        return .plaintext
    }
    static func highlighted(_ code: String, language: SnippetLanguage, scheme: ColorScheme) -> AttributedString {
        let effective = language == .auto ? detectLanguage(for: code) : language
        var output = AttributedString(code)
        output.font = .system(.caption, design: .monospaced)
        output.foregroundColor = Theme.current(scheme).plain
        guard code.count < 60_000 else { return output }
        apply(pattern: #"("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#, color: Theme.current(scheme).string, to: &output, in: code)
        apply(pattern: #"\b\d+(?:\.\d+)?\b"#, color: Theme.current(scheme).number, to: &output, in: code)
        apply(pattern: #"(//.*|#.*|/\*[\s\S]*?\*/)"#, color: Theme.current(scheme).comment, to: &output, in: code)
        let keywords = effective.grammarKeywords
        if !keywords.isEmpty { apply(pattern: "\\b(" + keywords.map(NSRegularExpression.escapedPattern).joined(separator: "|") + ")\\b", color: Theme.current(scheme).keyword, to: &output, in: code, options: effective == .sql ? [.caseInsensitive] : []) }
        apply(pattern: #"[{}\[\]();,.<>]"#, color: Theme.current(scheme).punctuation, to: &output, in: code)
        return output
    }
    private static func apply(pattern: String, color: Color, to attributed: inout AttributedString, in source: String, options: NSRegularExpression.Options = []) {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else { return }
        let nsRange = NSRange(source.startIndex..<source.endIndex, in: source)
        for match in regex.matches(in: source, range: nsRange) {
            guard let range = Range(match.range, in: source), let attrRange = Range(range, in: attributed) else { continue }
            attributed[attrRange].foregroundColor = color
        }
    }
}
