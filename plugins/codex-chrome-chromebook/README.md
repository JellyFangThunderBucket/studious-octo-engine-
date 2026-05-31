# Codex Chrome Chromebook Plugin

This repo-local Codex plugin packages Chromebook-oriented Chrome automation guidance for agents.
It is designed for Codex running inside the Chromebook Linux development environment (Crostini) or a comparable Linux shell.

## What it provides

- A Codex skill for deciding whether to use the Linux Chrome/Chromium browser or a manually exposed ChromeOS browser debugging endpoint.
- Diagnostic scripts for checking available Chrome executables and Chrome DevTools Protocol connectivity.
- A launch helper that starts a dedicated Chrome/Chromium profile with remote debugging enabled.

## Quick start

```bash
./plugins/codex-chrome-chromebook/scripts/check-chrome-debug.sh
./plugins/codex-chrome-chromebook/scripts/start-chrome-debug.sh --port 9222
```

Then ask Codex to use the `chromebook-chrome` skill for browser debugging or web-app verification.
