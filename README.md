# studious-octo-engine-

This repository contains two small utilities:

- `Vault.py` — a Pythonista 3 encrypted vault for photos, videos, and other files.
- `advanced-ethical-data-tool.user.js` — a modern Tampermonkey userscript for consent-based research and visible-page data extraction.

## Pythonista vault

The vault stores staged files in an encrypted archive using AES-CTR plus HMAC verification. In a StaSh terminal, install the dependency and then run the script in Pythonista 3:

```sh
pip install pyaes
```

Then create or open `Vault.py` in Pythonista and run it.

## Ethical Research Assistant userscript

Install `advanced-ethical-data-tool.user.js` in Tampermonkey or another compatible userscript manager. The sidebar can scan visible page content, inventory media, extract metadata and structured data, optionally OCR visible images, redact common sensitive patterns, and export snapshots as JSON, CSV, or Markdown.

This userscript is intentionally consent-first: it does not bypass paywalls, authentication, DRM, or hidden form protections. Use it only on pages you are allowed to inspect.
