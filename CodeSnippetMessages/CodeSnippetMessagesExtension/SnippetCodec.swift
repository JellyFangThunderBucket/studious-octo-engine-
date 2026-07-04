import Foundation

enum SnippetCodecError: LocalizedError { case invalidURL, missingPayload, invalidPayload, oversizedPayload
    var errorDescription: String? { switch self { case .invalidURL: return "The message URL is invalid."; case .missingPayload: return "No snippet payload was found."; case .invalidPayload: return "The snippet payload could not be decoded."; case .oversizedPayload: return "The snippet is too large to send reliably. Keep it under 24 KB." } }
}

enum SnippetCodec {
    static let scheme = "codesnippetmsg"
    static let maxEncodedCharacters = 32_000
    static func makeURL(for snippet: CodeSnippet) throws -> URL {
        let data = try JSONEncoder.iso8601Snippet.encode(snippet)
        let encoded = data.base64URLEncodedString()
        guard encoded.count <= maxEncodedCharacters else { throw SnippetCodecError.oversizedPayload }
        var components = URLComponents(); components.scheme = scheme; components.host = "snippet"; components.queryItems = [URLQueryItem(name: "payload", value: encoded)]
        guard let url = components.url else { throw SnippetCodecError.invalidURL }
        return url
    }
    static func decode(from url: URL?) throws -> CodeSnippet {
        guard let url, let components = URLComponents(url: url, resolvingAgainstBaseURL: false), components.scheme == scheme else { throw SnippetCodecError.invalidURL }
        guard let payload = components.queryItems?.first(where: { $0.name == "payload" })?.value else { throw SnippetCodecError.missingPayload }
        guard let data = Data(base64URLEncoded: payload), let snippet = try? JSONDecoder.iso8601Snippet.decode(CodeSnippet.self, from: data) else { throw SnippetCodecError.invalidPayload }
        return snippet
    }
}

extension JSONEncoder { static var iso8601Snippet: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e } }
extension JSONDecoder { static var iso8601Snippet: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d } }
extension Data {
    func base64URLEncodedString() -> String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URLEncoded string: String) { var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"); s += String(repeating: "=", count: (4 - s.count % 4) % 4); self.init(base64Encoded: s) }
}
