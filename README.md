# studious-octo-engine-

This repository contains two small utilities:

- `Vault.py` — a Pythonista 3 encrypted vault for photos, videos, and other files.
- `advanced-ethical-data-tool.user.js` — a modern Tampermonkey userscript for consent-based research and visible-page data extraction.

## Pythonista vault

The vault stores staged files in an encrypted archive using AES-CTR plus HMAC verification. In a StaSh terminal, install the dependency and then run the script in Pythonista 3:

```sh
pip install pyaes
exit stash then make a new entitled 
Vault.py
past code 
run

## Advanced Responsive Ethical Data Gathering Tool userscript

This repository also includes `advanced-responsive-ethical-data-tool.user.js`, a refreshed Tampermonkey userscript based on the v3.2 script. The update keeps the original research/extraction controls while making the sidebar easier to move out of the way:

- starts collapsed by default so it does not cover the page on load;
- can be expanded/collapsed from the header or the ⤢ button;
- can be dragged vertically, resized from the lower corner, docked left/right, and made more transparent;
- saves panel size, position, dock, opacity, and collapsed state in `localStorage` per site;
- adds a live-update pause/resume button to avoid the mutation observer constantly redrawing the panel while you inspect the page;
- escapes extracted text before rendering it in the sidebar to reduce accidental HTML injection from page content.

Install it by opening the file in Tampermonkey or copying its contents into a new userscript. If the panel is ever in the way, click the vertical collapsed tab or use **Reset Panel** from the expanded controls.
```

Then create or open `Vault.py` in Pythonista and run it.

## Ethical Research Assistant userscript

Install `advanced-ethical-data-tool.user.js` in Tampermonkey or another compatible userscript manager. The sidebar can scan visible page content, inventory media, extract metadata and structured data, optionally OCR visible images, redact common sensitive patterns, and export snapshots as JSON, CSV, or Markdown.

This userscript is intentionally consent-first: it does not bypass paywalls, authentication, DRM, or hidden form protections. Use it only on pages you are allowed to inspect.
