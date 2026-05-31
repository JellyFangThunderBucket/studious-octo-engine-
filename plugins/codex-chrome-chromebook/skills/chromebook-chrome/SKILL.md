---
name: chromebook-chrome
description: Use when Codex needs to work with Chrome from a Chromebook, especially from the Linux development environment, by diagnosing Chrome availability, starting a dedicated Chrome/Chromium instance with remote debugging, or connecting to an existing Chrome DevTools Protocol endpoint.
---

# Chromebook Chrome Workflow

Use this skill when a user asks Codex to work with Chrome on a Chromebook, verify a local web app in Chrome, or troubleshoot browser automation from the Chromebook Linux environment.

## Operating assumptions

- Codex normally runs inside the Chromebook Linux development environment (Crostini), which is separate from the ChromeOS system browser.
- The most reliable automation path is to install or use Linux `google-chrome`, `google-chrome-stable`, `chromium`, or `chromium-browser` inside the Linux container.
- A ChromeOS system-browser tab is only automatable if the user has intentionally exposed a Chrome DevTools Protocol endpoint and provided the host and port.
- Prefer a dedicated temporary profile for automation so Codex does not touch the user's daily browser profile.

## Standard workflow

1. Run the diagnostic helper from the repository root:

   ```bash
   ./plugins/codex-chrome-chromebook/scripts/check-chrome-debug.sh
   ```

2. If no reachable DevTools endpoint is reported, start a dedicated Linux Chrome/Chromium instance:

   ```bash
   ./plugins/codex-chrome-chromebook/scripts/start-chrome-debug.sh --port 9222
   ```

3. Confirm the endpoint is reachable:

   ```bash
   curl -fsS http://127.0.0.1:9222/json/version
   ```

4. Use the Chrome DevTools Protocol endpoint for browser inspection, page capture, or web-app verification.

## Chromebook-specific guidance

- If the user expects the ChromeOS system browser to be controlled, explain that the Linux container cannot automatically control it unless a debugging bridge or endpoint has been set up.
- If the user wants a normal visible browser window, launch Chrome from the Linux terminal rather than using headless mode.
- If the Chromebook blocks sandboxing inside the container, try the helper's `--no-sandbox` option only for a dedicated automation profile.
- Never reuse the user's normal Chrome profile unless they explicitly ask for it.

## Safety rules

- Do not collect cookies, saved passwords, browser history, or profile data.
- Do not open private user pages unless the user specifically requests the URL or task.
- Prefer localhost DevTools endpoints (`127.0.0.1`) and warn before connecting to a remote debugging endpoint on another host.
