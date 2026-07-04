# CodeSnippetMessages iMessage Extension

A production-ready SwiftUI iMessage extension for sending self-contained, reusable code snippets as rich iMessage cards. The extension supports native syntax highlighting, metadata, safe base64url JSON payload encoding, previewing, copy-to-clipboard, and compact/expanded transcript rendering on iOS 15+.

## Project structure

Create a new Xcode project with an iOS app target and an iMessage Extension target, then add these files:

```text
CodeSnippetMessages/
├── CodeSnippetMessagesApp/
│   ├── CodeSnippetMessagesApp.swift
│   └── ContentView.swift
└── CodeSnippetMessagesExtension/
    ├── Info.plist
    ├── MessagesViewController.swift
    ├── SnippetModels.swift
    ├── SnippetCodec.swift
    ├── SyntaxHighlighter.swift
    ├── SnippetCardView.swift
    ├── SnippetComposerView.swift
    ├── ExtensionRootView.swift
    └── Assets.xcassets/
```

## Target setup

1. In Xcode 15 or newer, choose **File → New → Project → iOS → App** and name it `CodeSnippetMessages`.
2. Add **File → New → Target → iMessage Extension** and name it `CodeSnippetMessagesExtension`.
3. Set the deployment target for both targets to **iOS 15.0** or newer.
4. Add all files in `CodeSnippetMessagesExtension/` to the extension target only.
5. Add all files in `CodeSnippetMessagesApp/` to the host app target only.
6. In the extension target, add frameworks: `Messages.framework`, `SwiftUI.framework`, and `UIKit.framework`.
7. Keep signing capabilities simple: the host app and extension need the same development team and bundle prefix.

## Required Info.plist entries

The extension target must include `NSExtensionPointIdentifier` set to `com.apple.message-payload-provider`, and `NSExtensionPrincipalClass` set to `$(PRODUCT_MODULE_NAME).MessagesViewController`. A complete plist is included at `CodeSnippetMessagesExtension/Info.plist`.

## Running and testing

1. Select the `CodeSnippetMessagesExtension` scheme.
2. Choose an iOS Simulator or a physical device running iOS 15+.
3. Run. Xcode will ask for the host app; choose **Messages**.
4. Open an iMessage conversation, tap the app drawer, and select Code Snippets.
5. Paste code, choose or auto-detect a language, preview, and tap **Send Snippet**.

## Notes on iMessage rendering

Apple does not allow arbitrary live SwiftUI controls inside the collapsed transcript bubble. This extension therefore sends an `MSMessage` with an `MSMessageTemplateLayout` for the native transcript bubble and an encoded URL payload. When a recipient taps the bubble, the extension opens and renders the full interactive SwiftUI card with syntax highlighting, scrolling, expansion, and Copy All support.
