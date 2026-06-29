# studious-octo-engine-

This repository contains two small utilities:

- `Vault.py` — a Pythonista 3 encrypted vault for photos, videos, and other files.
- `advanced-ethical-data-tool.user.js` — a modern Tampermonkey userscript for consent-based research, visible-page data extraction, and media/stream intelligence.

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

### New life / “secret powers”

- **Stream Radar** detects HLS (`.m3u8`), DASH (`.mpd`), and direct video URLs from visible DOM nodes, media elements, attributes, browser performance entries, `fetch`, XHR, and response text.
- **Manifest intelligence** summarizes detected HLS manifests when the browser can read them, including variant count, segment count, duration, and whether an encryption tag is advertised.
- **One-click stream export** copies detected stream URLs or includes them in JSON, CSV, and Markdown exports.
- **Page brief** adds word count, estimated reading time, and top linked hosts to each snapshot for quicker triage.
- **Safer defaults** keep redaction enabled and keep the tool focused on visible or browser-advertised resources rather than bypassing access controls.

This userscript is intentionally consent-first: it does not bypass paywalls, authentication, DRM, or hidden form protections. Use it only on pages you are allowed to inspect or archive.

## No Middle Man userscript

Install `no-middle-man.user.js` in Tampermonkey, Violentmonkey, or another compatible userscript manager to modernize the classic “No Middle Man” redirect remover. The 2026 refresh keeps the original goal—turning redirect/tracking links into direct destination links—while using current userscript metadata, safer URL parsing, repeated percent-decoding for chained redirects, support for protocol-relative and bare `www.` destinations, and a `MutationObserver` so links added after page load are cleaned too.

## Facebook Debug Info Helper 2026 userscript

Install `facebook-debug-info-2026.user.js` in Tampermonkey to modernize the older one-off Facebook console snippet. The helper exposes `getFacebookDebugInfo2026(flag)` and a backwards-compatible `getDebugInfo(flag)` alias, supports current Facebook URL shapes such as numeric posts, `pfbid` posts, `story.php`, `permalink.php`, videos, reels, groups, and mobile/web hosts, and reports profile/post candidates from the rendered page, URL, anchors, metadata, and JSON-like script data.

The 2026 version is consent-first: it only inspects data already present in the current rendered page, does not call private APIs, does not bypass login or privacy controls, and can copy a JSON report through a Tampermonkey menu command. Supported flags include `ALL`, `PROFILEID`, `POSTID`, `POSTPFBID`, `COMBINE`, `JSON`, and `COPY`.

