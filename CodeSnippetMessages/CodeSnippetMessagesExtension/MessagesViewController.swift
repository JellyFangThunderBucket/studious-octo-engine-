import UIKit
import SwiftUI
import Messages

final class MessagesViewController: MSMessagesAppViewController {
    private var hostingController: UIHostingController<ExtensionRootView>?
    private var activeSnippet: CodeSnippet?
    override func viewDidLoad() { super.viewDidLoad(); render() }
    override func willBecomeActive(with conversation: MSConversation) { super.willBecomeActive(with: conversation); activeSnippet = try? SnippetCodec.decode(from: conversation.selectedMessage?.url); render() }
    override func didSelect(_ message: MSMessage, conversation: MSConversation) { activeSnippet = try? SnippetCodec.decode(from: message.url); requestPresentationStyle(.expanded); render() }
    private func render() {
        let root = ExtensionRootView(activeSnippet: activeSnippet) { [weak self] snippet in self?.send(snippet) }
        if let hostingController { hostingController.rootView = root; return }
        let host = UIHostingController(rootView: root); hostingController = host; addChild(host); view.addSubview(host.view); host.view.translatesAutoresizingMaskIntoConstraints = false; NSLayoutConstraint.activate([host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor), host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor), host.view.topAnchor.constraint(equalTo: view.topAnchor), host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)]); host.didMove(toParent: self)
    }
    private func send(_ snippet: CodeSnippet) {
        guard let conversation = activeConversation else { return }
        do { conversation.insert(try makeMessage(for: snippet)) { [weak self] error in if error == nil { self?.dismiss() } } } catch { presentError(error) }
    }
    private func makeMessage(for snippet: CodeSnippet) throws -> MSMessage {
        let layout = MSMessageTemplateLayout(); layout.caption = snippet.displayTitle; layout.subcaption = "\(snippet.language.templateSubtitle) • \(snippet.createdAt.formatted(date: .abbreviated, time: .shortened))"; layout.trailingCaption = "Copyable"; layout.image = TranscriptImageRenderer.image(for: snippet)
        let message = MSMessage(); message.url = try SnippetCodec.makeURL(for: snippet); message.layout = layout; message.summaryText = "\(snippet.language.templateSubtitle): \(snippet.displayTitle)"; return message
    }
    private func presentError(_ error: Error) { let alert = UIAlertController(title: "Could Not Send Snippet", message: error.localizedDescription, preferredStyle: .alert); alert.addAction(UIAlertAction(title: "OK", style: .default)); present(alert, animated: true) }
}

enum TranscriptImageRenderer {
    static func image(for snippet: CodeSnippet) -> UIImage {
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: 600, height: 360)); return renderer.image { context in
            UIColor { $0.userInterfaceStyle == .dark ? UIColor(white: 0.10, alpha: 1) : .white }.setFill(); UIBezierPath(roundedRect: CGRect(x: 0, y: 0, width: 600, height: 360), cornerRadius: 34).fill()
            UIColor.systemBlue.setFill(); UIBezierPath(roundedRect: CGRect(x: 28, y: 26, width: 12, height: 52), cornerRadius: 6).fill()
            let titleAttrs: [NSAttributedString.Key: Any] = [.font: UIFont.preferredFont(forTextStyle: .headline), .foregroundColor: UIColor.label]
            (snippet.displayTitle as NSString).draw(in: CGRect(x: 56, y: 24, width: 500, height: 28), withAttributes: titleAttrs)
            let metaAttrs: [NSAttributedString.Key: Any] = [.font: UIFont.preferredFont(forTextStyle: .caption1), .foregroundColor: UIColor.secondaryLabel]
            (snippet.language.templateSubtitle as NSString).draw(in: CGRect(x: 56, y: 54, width: 500, height: 24), withAttributes: metaAttrs)
            UIColor { $0.userInterfaceStyle == .dark ? UIColor.black.withAlphaComponent(0.55) : UIColor(white: 0.95, alpha: 1) }.setFill(); UIBezierPath(roundedRect: CGRect(x: 28, y: 98, width: 544, height: 224), cornerRadius: 18).fill()
            let preview = snippet.code.components(separatedBy: .newlines).prefix(9).joined(separator: "\n")
            let codeAttrs: [NSAttributedString.Key: Any] = [.font: UIFont.monospacedSystemFont(ofSize: 18, weight: .regular), .foregroundColor: UIColor.label]
            (preview as NSString).draw(in: CGRect(x: 48, y: 118, width: 504, height: 184), withAttributes: codeAttrs)
        }
    }
}
