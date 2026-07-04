import Foundation
import SwiftUI

enum SnippetLanguage: String, CaseIterable, Codable, Identifiable {
    case auto = "Auto Detect", javascript = "JavaScript", json = "JSON", markdown = "Markdown", plaintext = "Plain Text", python = "Python", swift = "Swift", typescript = "TypeScript", html = "HTML", css = "CSS", shell = "Shell", yaml = "YAML", xml = "XML", ruby = "Ruby", go = "Go", rust = "Rust", java = "Java", kotlin = "Kotlin", cpp = "C++", csharp = "C#", sql = "SQL"
    var id: String { rawValue }
    var templateSubtitle: String { self == .auto ? "Code Snippet" : "\(rawValue) Snippet" }
    var grammarKeywords: Set<String> {
        switch self {
        case .javascript, .typescript: return ["async","await","break","case","catch","class","const","continue","default","delete","do","else","export","extends","finally","for","from","function","if","import","in","instanceof","let","new","of","return","static","switch","this","throw","try","typeof","var","void","while","yield"]
        case .python: return ["and","as","assert","async","await","break","class","continue","def","del","elif","else","except","False","finally","for","from","global","if","import","in","is","lambda","None","nonlocal","not","or","pass","raise","return","True","try","while","with","yield"]
        case .swift: return ["actor","as","associatedtype","async","await","break","case","catch","class","continue","defer","do","else","enum","extension","false","for","func","guard","if","import","in","init","let","nil","private","protocol","public","return","self","static","struct","switch","throw","throws","true","try","var","while"]
        case .java, .kotlin: return ["abstract","break","case","catch","class","const","continue","data","do","else","enum","extends","false","final","finally","for","fun","if","implements","import","in","interface","new","null","object","override","package","private","protected","public","return","static","super","switch","this","throw","throws","true","try","val","var","void","while"]
        case .go: return ["break","case","chan","const","continue","default","defer","else","fallthrough","for","func","go","goto","if","import","interface","map","package","range","return","select","struct","switch","type","var"]
        case .rust: return ["as","async","await","break","const","continue","crate","else","enum","extern","false","fn","for","if","impl","in","let","loop","match","mod","move","mut","pub","ref","return","self","Self","static","struct","super","trait","true","type","unsafe","use","where","while"]
        case .cpp, .csharp: return ["auto","bool","break","case","catch","class","const","continue","default","do","double","else","enum","false","float","for","if","int","namespace","new","null","private","protected","public","return","static","string","struct","switch","this","throw","true","try","using","var","virtual","void","while"]
        case .ruby: return ["BEGIN","END","alias","and","begin","break","case","class","def","defined?","do","else","elsif","end","ensure","false","for","if","in","module","next","nil","not","or","redo","rescue","retry","return","self","super","then","true","undef","unless","until","when","while","yield"]
        case .sql: return ["SELECT","FROM","WHERE","INSERT","UPDATE","DELETE","CREATE","ALTER","DROP","JOIN","LEFT","RIGHT","INNER","OUTER","GROUP","ORDER","BY","HAVING","LIMIT","OFFSET","VALUES","INTO","TABLE","INDEX","VIEW","AND","OR","NOT","NULL","IS","AS"]
        default: return []
        }
    }
}

struct CodeSnippet: Codable, Equatable {
    var id = UUID()
    var title: String
    var details: String
    var code: String
    var language: SnippetLanguage
    var createdAt: Date
    var isExpanded: Bool = false
    var displayTitle: String { title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? language.templateSubtitle : title }
}
