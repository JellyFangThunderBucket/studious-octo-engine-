// ==UserScript==
// @name         Advanced Ethical Research Assistant v4.0
// @namespace    https://littlelooney.example/research-assistant
// @version      2026-05-07
// @description  Modern, responsive research helper for consent-based data collection: visible-page extraction, media inventory, metadata, OCR, exports, privacy redaction, and performance-safe live updates.
// @author       LittleLooney + OpenAI
// @license      Copyright (C) Littlelooney All rights reserved.
// @match        *://*/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=google.com
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(() => {
  'use strict';

  /**
   * Advanced Ethical Research Assistant v4.0
   * ------------------------------------------------------------
   * This version intentionally focuses on consent-based research of
   * data that is already available in the rendered page. It avoids
   * paywall/DRM bypass behavior and does not reveal hidden form values
   * by default. Use it only on pages you are allowed to inspect.
   */

  const APP_ID = 'aera-sidebar';
  const STORAGE_KEY = 'aera:v4:settings';
  const LOG_LIMIT = 250;
  const OCR_SRC = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';
  const DEFAULT_SETTINGS = Object.freeze({
    autoScan: true,
    includeShadowDom: false,
    includeHiddenMetadata: false,
    redactSensitive: true,
    compactMode: false,
    theme: 'dark',
    scanSelectionOnly: false,
  });

  const state = {
    settings: loadSettings(),
    latest: createEmptySnapshot(),
    logs: [],
    observer: null,
    scanController: null,
    isScanning: false,
    isPaused: false,
  };

  const idle = window.requestIdleCallback
    ? (callback) => window.requestIdleCallback(callback, { timeout: 1200 })
    : (callback) => window.setTimeout(() => callback({ timeRemaining: () => 0 }), 16);

  function loadSettings() {
    try {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  function saveSettings() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.settings));
  }

  function createEmptySnapshot() {
    return {
      url: location.href,
      title: document.title,
      capturedAt: new Date().toISOString(),
      counts: { textBlocks: 0, links: 0, images: 0, videos: 0, documents: 0, meta: 0, backgroundImages: 0 },
      textBlocks: [],
      links: [],
      images: [],
      videos: [],
      documents: [],
      meta: {},
      backgroundImages: [],
      headings: [],
      tables: [],
      structuredData: [],
      shadowText: [],
      performance: {},
    };
  }

  function log(level, message, details) {
    const entry = { at: new Date().toISOString(), level, message, details };
    state.logs.push(entry);
    if (state.logs.length > LOG_LIMIT) state.logs.shift();
    const method = console[level] ? level : 'log';
    console[method](`[AERA] ${entry.at} ${message}`, details || '');
    renderLogs();
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function normalizeText(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
  }

  function absoluteUrl(value) {
    if (!value) return '';
    try {
      return new URL(value, location.href).href;
    } catch {
      return value;
    }
  }

  function redactSensitiveText(value) {
    if (!state.settings.redactSensitive) return value;
    return String(value || '')
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted-email]')
      .replace(/\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g, '[redacted-phone]')
      .replace(/\b(?:\d[ -]*?){13,19}\b/g, '[redacted-number]');
  }

  function uniqueBy(items, keyFn) {
    const seen = new Set();
    return items.filter((item) => {
      const key = keyFn(item);
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function isVisible(el) {
    if (!(el instanceof Element)) return true;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function getScanRoot() {
    if (!state.settings.scanSelectionOnly) return document.body || document.documentElement;
    const selection = getSelection();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return document.body || document.documentElement;
    const range = selection.getRangeAt(0);
    const fragment = document.createElement('div');
    fragment.appendChild(range.cloneContents());
    return fragment;
  }

  async function scanPage(reason = 'manual') {
    if (state.isScanning) {
      state.scanController?.abort();
    }
    const controller = new AbortController();
    state.scanController = controller;
    state.isScanning = true;
    const started = performance.now();
    setStatus(`Scanning (${reason})...`);

    try {
      await new Promise((resolve) => idle(resolve));
      if (controller.signal.aborted) return;

      const root = getScanRoot();
      const snapshot = createEmptySnapshot();
      snapshot.textBlocks = extractText(root);
      snapshot.headings = extractHeadings(root);
      snapshot.links = extractLinks(root);
      snapshot.images = extractImages(root);
      snapshot.videos = extractVideos(root);
      snapshot.documents = snapshot.links.filter((link) => /\.(?:pdf|docx?|xlsx?|pptx?|csv|json|xml)(?:$|[?#])/i.test(link.href));
      snapshot.meta = extractMeta();
      snapshot.backgroundImages = extractBackgroundImages(root);
      snapshot.tables = extractTables(root);
      snapshot.structuredData = extractStructuredData();
      snapshot.shadowText = state.settings.includeShadowDom ? extractShadowText() : [];
      snapshot.counts = {
        textBlocks: snapshot.textBlocks.length,
        links: snapshot.links.length,
        images: snapshot.images.length,
        videos: snapshot.videos.length,
        documents: snapshot.documents.length,
        meta: Object.keys(snapshot.meta).length,
        backgroundImages: snapshot.backgroundImages.length,
      };
      snapshot.performance = { scanMs: Math.round(performance.now() - started), reason };
      state.latest = snapshot;
      renderData();
      setStatus(`Ready • scanned in ${snapshot.performance.scanMs}ms`);
      log('info', `Scan complete (${reason})`, snapshot.counts);
    } catch (error) {
      setStatus('Scan failed');
      log('error', `Scan failed: ${error.message || error}`, error);
    } finally {
      if (state.scanController === controller) {
        state.isScanning = false;
        state.scanController = null;
      }
    }
  }

  function extractText(root) {
    return Array.from(root.querySelectorAll('p, li, blockquote, figcaption, article, section'))
      .filter(isVisible)
      .map((el) => redactSensitiveText(normalizeText(el.innerText || el.textContent)))
      .filter((text) => text.length >= 24)
      .slice(0, 500);
  }

  function extractHeadings(root) {
    return Array.from(root.querySelectorAll('h1, h2, h3, h4, h5, h6'))
      .filter(isVisible)
      .map((el) => ({ level: el.tagName.toLowerCase(), text: redactSensitiveText(normalizeText(el.innerText || el.textContent)) }))
      .filter((item) => item.text);
  }

  function extractLinks(root) {
    return uniqueBy(Array.from(root.querySelectorAll('a[href]'))
      .filter(isVisible)
      .map((a) => ({
        text: redactSensitiveText(normalizeText(a.innerText || a.getAttribute('aria-label') || a.title || 'Untitled link')),
        href: absoluteUrl(a.getAttribute('href')),
        rel: a.rel || '',
        target: a.target || '',
      })), (link) => link.href);
  }

  function bestImageSource(img) {
    const candidates = [
      img.currentSrc,
      img.src,
      img.dataset?.src,
      img.dataset?.fullsrc,
      img.dataset?.original,
      img.getAttribute('data-lazy-src'),
    ].filter(Boolean);
    return absoluteUrl(candidates[0] || '');
  }

  function extractImages(root) {
    return uniqueBy(Array.from(root.querySelectorAll('img, picture img, source[srcset]'))
      .filter(isVisible)
      .map((el) => ({
        src: bestImageSource(el),
        srcset: el.getAttribute('srcset') || '',
        alt: redactSensitiveText(el.getAttribute('alt') || ''),
        title: redactSensitiveText(el.getAttribute('title') || ''),
        naturalWidth: el.naturalWidth || 0,
        naturalHeight: el.naturalHeight || 0,
        displayedWidth: el.clientWidth || 0,
        displayedHeight: el.clientHeight || 0,
        loading: el.getAttribute('loading') || '',
      }))
      .filter((image) => image.src || image.srcset), (image) => image.src || image.srcset);
  }

  function extractVideos(root) {
    const videos = [];
    root.querySelectorAll('video, video source, iframe[src]').forEach((el) => {
      if (!isVisible(el)) return;
      const tag = el.tagName.toLowerCase();
      const src = tag === 'video' ? (el.currentSrc || el.src) : el.getAttribute('src');
      videos.push({ type: tag, src: absoluteUrl(src), title: redactSensitiveText(el.title || el.getAttribute('aria-label') || '') });
    });
    return uniqueBy(videos.filter((video) => video.src), (video) => video.src);
  }

  function extractMeta() {
    const allowed = state.settings.includeHiddenMetadata
      ? 'meta[name], meta[property], link[rel="canonical"], link[rel="alternate"]'
      : 'meta[name="description"], meta[property^="og:"], meta[name^="twitter:"], link[rel="canonical"]';
    const meta = {};
    document.querySelectorAll(allowed).forEach((el) => {
      const key = el.getAttribute('property') || el.getAttribute('name') || `link:${el.getAttribute('rel')}`;
      const content = el.getAttribute('content') || el.getAttribute('href');
      if (key && content) meta[key] = redactSensitiveText(content);
    });
    return meta;
  }

  function extractBackgroundImages(root) {
    const urls = [];
    root.querySelectorAll('*').forEach((el) => {
      if (!isVisible(el)) return;
      const bg = getComputedStyle(el).backgroundImage;
      if (!bg || bg === 'none') return;
      for (const match of bg.matchAll(/url\(["']?(.*?)["']?\)/g)) urls.push(absoluteUrl(match[1]));
    });
    return [...new Set(urls)].slice(0, 200);
  }

  function extractTables(root) {
    return Array.from(root.querySelectorAll('table')).filter(isVisible).slice(0, 20).map((table) => ({
      caption: redactSensitiveText(normalizeText(table.querySelector('caption')?.innerText || '')),
      rows: Array.from(table.rows).slice(0, 25).map((row) => Array.from(row.cells).map((cell) => redactSensitiveText(normalizeText(cell.innerText))))
    }));
  }

  function extractStructuredData() {
    return Array.from(document.querySelectorAll('script[type="application/ld+json"]')).slice(0, 20).map((script, index) => {
      try {
        return { index, data: JSON.parse(script.textContent) };
      } catch {
        return { index, data: redactSensitiveText(script.textContent || '') };
      }
    });
  }

  function extractShadowText() {
    const results = [];
    document.querySelectorAll('*').forEach((el) => {
      if (!el.shadowRoot) return;
      const text = redactSensitiveText(normalizeText(el.shadowRoot.textContent));
      if (text) results.push({ host: el.tagName.toLowerCase(), text });
    });
    return results.slice(0, 100);
  }

  function forceLoadMedia() {
    let images = 0;
    let videos = 0;
    document.querySelectorAll('img').forEach((img) => {
      img.loading = 'eager';
      img.decoding = 'async';
      const src = bestImageSource(img);
      if (src && img.src !== src) img.src = src;
      images += 1;
    });
    document.querySelectorAll('video').forEach((video) => {
      video.preload = 'metadata';
      try { video.load(); } catch (error) { log('warn', `Video load skipped: ${error.message || error}`); }
      videos += 1;
    });
    log('info', `Requested media load for ${images} image(s) and ${videos} video(s).`);
    scanPage('media load');
  }

  function enableSelectionAssist() {
    const styleId = `${APP_ID}-selection-style`;
    document.getElementById(styleId)?.remove();
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = '* { -webkit-user-select: text !important; user-select: text !important; }';
    document.documentElement.appendChild(style);
    log('info', 'Selection assist enabled without changing page visibility or access controls.');
  }

  function copyToClipboard(text, label = 'text') {
    navigator.clipboard?.writeText(text)
      .then(() => log('info', `Copied ${label} to clipboard.`))
      .catch((error) => log('error', `Clipboard copy failed: ${error.message || error}`));
  }

  function exportSnapshot(format) {
    const snapshot = state.latest;
    if (format === 'clipboard') {
      copyToClipboard(JSON.stringify(snapshot, null, 2), 'JSON snapshot');
      return;
    }
    let mime = 'application/json';
    let extension = 'json';
    let content = JSON.stringify(snapshot, null, 2);
    if (format === 'markdown') {
      mime = 'text/markdown';
      extension = 'md';
      content = toMarkdown(snapshot);
    } else if (format === 'csv') {
      mime = 'text/csv';
      extension = 'csv';
      content = toCsv(snapshot.links.map((link) => ({ kind: 'link', text: link.text, url: link.href }))
        .concat(snapshot.images.map((image) => ({ kind: 'image', text: image.alt || image.title, url: image.src }))));
    }
    const blob = new Blob([content], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `research-snapshot-${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
    a.click();
    URL.revokeObjectURL(url);
    log('info', `Exported ${format.toUpperCase()} snapshot.`);
  }

  function toMarkdown(snapshot) {
    const lines = [`# ${snapshot.title}`, '', `- URL: ${snapshot.url}`, `- Captured: ${snapshot.capturedAt}`, '', '## Counts'];
    Object.entries(snapshot.counts).forEach(([key, value]) => lines.push(`- ${key}: ${value}`));
    lines.push('', '## Headings', ...snapshot.headings.map((h) => `${'#'.repeat(Number(h.level[1]) + 1)} ${h.text}`));
    lines.push('', '## Text excerpts', ...snapshot.textBlocks.slice(0, 25).map((text) => `- ${text}`));
    lines.push('', '## Links', ...snapshot.links.slice(0, 100).map((link) => `- [${link.text || link.href}](${link.href})`));
    return lines.join('\n');
  }

  function toCsv(rows) {
    const quote = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    return ['kind,text,url', ...rows.map((row) => [row.kind, row.text, row.url].map(quote).join(','))].join('\n');
  }

  function loadScriptOnce(src, globalName) {
    if (window[globalName]) return Promise.resolve(window[globalName]);
    return new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[src="${src}"]`);
      if (existing) {
        existing.addEventListener('load', () => resolve(window[globalName]), { once: true });
        existing.addEventListener('error', reject, { once: true });
        return;
      }
      const script = document.createElement('script');
      script.src = src;
      script.async = true;
      script.onload = () => resolve(window[globalName]);
      script.onerror = () => reject(new Error(`Failed to load ${src}`));
      document.head.appendChild(script);
    });
  }

  async function performOcr() {
    const output = document.getElementById(`${APP_ID}-ocr`);
    if (output) output.textContent = 'Loading OCR engine...';
    try {
      const Tesseract = await loadScriptOnce(OCR_SRC, 'Tesseract');
      const images = state.latest.images.slice(0, 5).filter((image) => image.src);
      if (!images.length) {
        if (output) output.textContent = 'No visible images found for OCR.';
        return;
      }
      const results = [];
      for (const [index, image] of images.entries()) {
        if (output) output.textContent = `OCR image ${index + 1}/${images.length}...`;
        const result = await Tesseract.recognize(image.src, 'eng');
        results.push(redactSensitiveText(normalizeText(result.data.text)));
      }
      if (output) output.textContent = results.join('\n\n---\n\n') || 'OCR completed with no text.';
      log('info', 'OCR completed.');
    } catch (error) {
      if (output) output.textContent = `OCR failed: ${error.message || error}`;
      log('error', `OCR failed: ${error.message || error}`);
    }
  }

  function createSidebar() {
    if (document.getElementById(APP_ID)) return;
    const style = document.createElement('style');
    style.id = `${APP_ID}-styles`;
    style.textContent = `
      #${APP_ID} { all: initial; position: fixed; top: 16px; right: 16px; width: min(420px, calc(100vw - 32px)); max-height: calc(100vh - 32px); z-index: 2147483647; color-scheme: dark; font: 13px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      #${APP_ID}, #${APP_ID} * { box-sizing: border-box; }
      #${APP_ID}.compact .aera-body { display: none; }
      #${APP_ID}.light { color-scheme: light; }
      #${APP_ID} .aera-panel { background: color-mix(in srgb, Canvas 92%, transparent); color: CanvasText; border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 18px; box-shadow: 0 18px 48px rgba(0,0,0,.28); overflow: hidden; backdrop-filter: blur(18px); }
      #${APP_ID} .aera-header { display: flex; gap: 8px; align-items: center; justify-content: space-between; padding: 12px 14px; border-bottom: 1px solid color-mix(in srgb, CanvasText 12%, transparent); cursor: move; }
      #${APP_ID} .aera-title { font-weight: 800; font-size: 14px; }
      #${APP_ID} .aera-status { opacity: .72; font-size: 12px; margin-top: 2px; }
      #${APP_ID} .aera-body { max-height: calc(100vh - 104px); overflow: auto; padding: 12px; }
      #${APP_ID} button, #${APP_ID} select { font: inherit; border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 10px; background: color-mix(in srgb, CanvasText 8%, transparent); color: CanvasText; padding: 7px 9px; cursor: pointer; }
      #${APP_ID} button:hover { background: color-mix(in srgb, Highlight 18%, transparent); }
      #${APP_ID} .aera-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-bottom: 12px; }
      #${APP_ID} .aera-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 8px 0; border-bottom: 1px solid color-mix(in srgb, CanvasText 10%, transparent); }
      #${APP_ID} .aera-counts { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 10px 0; }
      #${APP_ID} .aera-card { border: 1px solid color-mix(in srgb, CanvasText 12%, transparent); border-radius: 12px; padding: 9px; background: color-mix(in srgb, CanvasText 5%, transparent); }
      #${APP_ID} .aera-card strong { display: block; font-size: 18px; }
      #${APP_ID} details { margin: 8px 0; border: 1px solid color-mix(in srgb, CanvasText 12%, transparent); border-radius: 12px; overflow: hidden; }
      #${APP_ID} summary { padding: 9px; cursor: pointer; font-weight: 700; }
      #${APP_ID} pre { margin: 0; padding: 9px; max-height: 220px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; background: color-mix(in srgb, CanvasText 6%, transparent); }
      #${APP_ID} label { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      #${APP_ID} input[type="checkbox"] { width: 18px; height: 18px; }
      #${APP_ID} .aera-log { font-size: 12px; opacity: .86; }
      #${APP_ID} .aera-danger { color: #ffb4ab; }
    `;
    document.documentElement.appendChild(style);

    const sidebar = document.createElement('aside');
    sidebar.id = APP_ID;
    sidebar.className = `${state.settings.compactMode ? 'compact' : ''} ${state.settings.theme === 'light' ? 'light' : ''}`;
    sidebar.innerHTML = `
      <div class="aera-panel">
        <header class="aera-header" id="${APP_ID}-drag">
          <div><div class="aera-title">Ethical Research Assistant</div><div class="aera-status" id="${APP_ID}-status">Starting...</div></div>
          <div><button data-action="toggleCompact" title="Collapse/expand">↕</button><button data-action="close" title="Close">×</button></div>
        </header>
        <div class="aera-body">
          <div class="aera-grid">
            <button data-action="scan">Refresh Scan</button>
            <button data-action="media">Load Media</button>
            <button data-action="selection">Selection Assist</button>
            <button data-action="ocr">OCR Visible Images</button>
            <button data-action="copy">Copy JSON</button>
            <select data-action="export"><option value="">Export...</option><option value="json">JSON</option><option value="csv">Links + Images CSV</option><option value="markdown">Markdown</option></select>
          </div>
          <section class="aera-card"><strong>Ethics guardrail</strong><span>Only collect data you are allowed to inspect. This build does not bypass paywalls, authentication, DRM, or hidden form protections.</span></section>
          <section id="${APP_ID}-data"></section>
          <details><summary>Options</summary><div id="${APP_ID}-options" class="aera-card"></div></details>
          <details><summary>OCR Output</summary><pre id="${APP_ID}-ocr">OCR has not run.</pre></details>
          <details><summary>Logs</summary><pre id="${APP_ID}-logs" class="aera-log"></pre></details>
        </div>
      </div>`;
    document.documentElement.appendChild(sidebar);
    sidebar.addEventListener('click', handleAction);
    sidebar.addEventListener('change', handleChange);
    makeDraggable(sidebar, sidebar.querySelector(`#${APP_ID}-drag`));
    renderOptions();
    setStatus('Ready');
    log('info', 'Sidebar created.');
  }

  function handleAction(event) {
    const target = event.target.closest('[data-action]');
    if (!target || !target.matches('button')) return;
    const action = target.dataset.action;
    if (action === 'scan') scanPage('manual');
    if (action === 'media') forceLoadMedia();
    if (action === 'selection') enableSelectionAssist();
    if (action === 'ocr') performOcr();
    if (action === 'copy') exportSnapshot('clipboard');
    if (action === 'toggleCompact') toggleCompact();
    if (action === 'close') document.getElementById(APP_ID)?.remove();
  }

  function handleChange(event) {
    const target = event.target;
    if (target.matches('select[data-action="export"]') && target.value) {
      exportSnapshot(target.value);
      target.value = '';
      return;
    }
    if (!target.matches('[data-setting]')) return;
    const key = target.dataset.setting;
    state.settings[key] = target.type === 'checkbox' ? target.checked : target.value;
    saveSettings();
    renderOptions();
    if (key === 'theme') document.getElementById(APP_ID)?.classList.toggle('light', state.settings.theme === 'light');
    if (key === 'compactMode') document.getElementById(APP_ID)?.classList.toggle('compact', state.settings.compactMode);
    scanPage(`option: ${key}`);
  }

  function renderOptions() {
    const options = document.getElementById(`${APP_ID}-options`);
    if (!options) return;
    const rows = [
      ['autoScan', 'Live auto-scan'],
      ['scanSelectionOnly', 'Scan selection only'],
      ['includeShadowDom', 'Include open Shadow DOM text'],
      ['includeHiddenMetadata', 'Include extra metadata tags'],
      ['redactSensitive', 'Redact emails, phones, long numbers'],
      ['compactMode', 'Compact mode'],
    ];
    options.innerHTML = `${rows.map(([key, label]) => `<div class="aera-row"><label>${escapeHtml(label)}<input type="checkbox" data-setting="${key}" ${state.settings[key] ? 'checked' : ''}></label></div>`).join('')}
      <div class="aera-row"><label>Theme<select data-setting="theme"><option value="dark" ${state.settings.theme === 'dark' ? 'selected' : ''}>Dark/system</option><option value="light" ${state.settings.theme === 'light' ? 'selected' : ''}>Light</option></select></label></div>`;
  }

  function renderData() {
    const data = document.getElementById(`${APP_ID}-data`);
    if (!data) return;
    const snapshot = state.latest;
    data.innerHTML = `
      <div class="aera-counts">
        ${Object.entries(snapshot.counts).map(([key, value]) => `<div class="aera-card"><strong>${value}</strong><span>${escapeHtml(key)}</span></div>`).join('')}
      </div>
      ${details('Headings', snapshot.headings.slice(0, 25).map((h) => `${h.level}: ${h.text}`).join('\n'))}
      ${details('Text excerpts', snapshot.textBlocks.slice(0, 20).join('\n\n'))}
      ${details('Images', snapshot.images.slice(0, 25).map((img) => `${img.alt || '(no alt)'}\n${img.src}\n${img.naturalWidth}×${img.naturalHeight} natural, ${img.displayedWidth}×${img.displayedHeight} shown`).join('\n\n'))}
      ${details('Links', snapshot.links.slice(0, 50).map((link) => `${link.text}\n${link.href}`).join('\n\n'))}
      ${details('Documents', snapshot.documents.slice(0, 50).map((link) => `${link.text}\n${link.href}`).join('\n\n'))}
      ${details('Metadata', JSON.stringify(snapshot.meta, null, 2))}
      ${details('Tables', JSON.stringify(snapshot.tables, null, 2))}
      ${details('Structured data', JSON.stringify(snapshot.structuredData, null, 2))}
      ${snapshot.shadowText.length ? details('Shadow DOM text', JSON.stringify(snapshot.shadowText, null, 2)) : ''}
    `;
  }

  function details(title, content) {
    return `<details><summary>${escapeHtml(title)}</summary><pre>${escapeHtml(content || 'None found.')}</pre></details>`;
  }

  function renderLogs() {
    const logs = document.getElementById(`${APP_ID}-logs`);
    if (!logs) return;
    logs.textContent = state.logs.slice(-80).map((entry) => `[${entry.at}] [${entry.level}] ${entry.message}`).join('\n');
    logs.scrollTop = logs.scrollHeight;
  }

  function setStatus(message) {
    const status = document.getElementById(`${APP_ID}-status`);
    if (status) status.textContent = message;
  }

  function toggleCompact() {
    state.settings.compactMode = !state.settings.compactMode;
    saveSettings();
    document.getElementById(APP_ID)?.classList.toggle('compact', state.settings.compactMode);
    renderOptions();
  }

  function makeDraggable(panel, handle) {
    let start = null;
    handle.addEventListener('pointerdown', (event) => {
      if (event.target.closest('button')) return;
      start = { x: event.clientX, y: event.clientY, right: parseFloat(getComputedStyle(panel).right), top: parseFloat(getComputedStyle(panel).top) };
      handle.setPointerCapture(event.pointerId);
    });
    handle.addEventListener('pointermove', (event) => {
      if (!start) return;
      panel.style.right = `${Math.max(0, start.right - (event.clientX - start.x))}px`;
      panel.style.top = `${Math.max(0, start.top + (event.clientY - start.y))}px`;
    });
    handle.addEventListener('pointerup', () => { start = null; });
  }

  const scheduleScan = (() => {
    let timeout;
    return (reason) => {
      if (!state.settings.autoScan || state.isPaused) return;
      clearTimeout(timeout);
      timeout = setTimeout(() => scanPage(reason), 650);
    };
  })();

  function observeDomChanges() {
    if (!document.body) return;
    state.observer?.disconnect();
    state.observer = new MutationObserver((mutations) => {
      if (mutations.some((mutation) => !document.getElementById(APP_ID)?.contains(mutation.target))) {
        scheduleScan('dom change');
      }
    });
    state.observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'href', 'alt', 'title', 'style', 'class'] });
    log('info', 'DOM observer initialized.');
  }

  function init() {
    if (!document.body) {
      window.addEventListener('DOMContentLoaded', init, { once: true });
      return;
    }
    createSidebar();
    observeDomChanges();
    scanPage('initial');
  }

  init();
})();
