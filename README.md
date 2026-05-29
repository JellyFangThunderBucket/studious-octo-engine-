# studious-octo-engine-

This repository contains two small utilities:

- `Vault.py` — a Pythonista 3 encrypted vault for photos, videos, and other files.
- `advanced-ethical-data-tool.user.js` — a modern Tampermonkey userscript for consent-based research, visible-page data extraction, and media/stream intelligence.

## Pythonista vault

The vault stores staged files in an encrypted archive using AES-CTR plus HMAC verification. In a StaSh terminal, install the dependency and then run the script in Pythonista 3:

```sh
pip install pyaes
```

Then create or open `Vault.py` in Pythonista and run it.

## Ethical Research Assistant userscript

Install `advanced-ethical-data-tool.user.js` in Tampermonkey or another compatible userscript manager. The sidebar can scan visible page content, inventory media, extract metadata and structured data, optionally OCR visible images, redact common sensitive patterns, and export snapshots as JSON, CSV, or Markdown.

### New life / “secret powers”

- **Stream Radar** detects HLS (`.m3u8`), DASH (`.mpd`), and direct video URLs from visible DOM nodes, media elements, attributes, browser performance entries, `fetch`, XHR, and response text.
- **Manifest intelligence** summarizes detected HLS manifests when the browser can read them, including variant count, segment count, duration, and whether an encryption tag is advertised.
- **One-click stream export** copies detected stream URLs or includes them in JSON, CSV, and Markdown exports.
- **Page brief** adds word count, estimated reading time, and top linked hosts to each snapshot for quicker triage.
- **Safer defaults** keep redaction enabled and keep the tool focused on visible or browser-advertised resources rather than bypassing access controls.

This userscript is intentionally consent-first: it does not bypass paywalls, authentication, DRM, or hidden form protections. Use it only on pages you are allowed to inspect or archive.
