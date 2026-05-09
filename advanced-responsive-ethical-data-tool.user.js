// ==UserScript==
// @name         Advanced Responsive Ethical Data Gathering Tool v3.3
// @namespace    http://tampermonkey.net/
// @version      2026-05-07
// @description  Ethical data research helper with force media loading, CSS/canvas/OpenCV sharpening, hidden text/data discovery, accessibility fixes, OCR, export, live logs, and a movable/collapsible/resizable sidebar.
// @author       LittleLooney; UI refresh by Codex
// @license      Copyright (C) Littlelooney All rights reserved.
// @match        *://*/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=google.com
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    /**********************************
     * Utility Functions & Logging    *
     **********************************/

    const DEBUG = true;
    const STORAGE_KEY = 'ethicalDataTool.v3.3.uiState';
    const DEFAULT_UI_STATE = {
        dock: 'right',
        collapsed: true,
        width: 400,
        height: 80,
        top: 0,
        left: null,
        opacity: 0.94,
        observerPaused: false,
    };

    let uiState = loadUiState();
    let domObserver = null;
    let isUpdatingSidebar = false;

    function debounce(func, wait) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    function safeConsole(level, message) {
        const logger = typeof console[level] === 'function' ? console[level] : console.log;
        logger.call(console, message);
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function loadUiState() {
        try {
            const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
            return { ...DEFAULT_UI_STATE, ...stored };
        } catch (error) {
            return { ...DEFAULT_UI_STATE };
        }
    }

    function saveUiState() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(uiState));
        } catch (error) {
            safeConsole('warn', 'Unable to save Ethical Data Tool UI state: ' + error);
        }
    }

    function logMessage(level, message) {
        const timestamp = new Date().toISOString();
        const fullMessage = `[${timestamp}] [${level}] ${message}`;
        if (DEBUG) safeConsole(level, fullMessage);

        const logArea = document.getElementById('logArea');
        if (logArea) {
            const logEntry = document.createElement('div');
            logEntry.textContent = fullMessage;
            logEntry.style.borderBottom = '1px solid #444';
            logEntry.style.padding = '2px 0';
            logArea.appendChild(logEntry);
            logArea.scrollTop = logArea.scrollHeight;
        }
    }

    /**********************************
     * Force Media Loading Function   *
     **********************************/

    function forceLoadMedia() {
        try {
            const images = document.querySelectorAll('img');
            images.forEach(img => {
                if (img.hasAttribute('loading')) img.removeAttribute('loading');
                if (img.dataset?.fullsrc) img.src = img.dataset.fullsrc;
                if (img.dataset?.src) img.src = img.dataset.src;
                img.classList.remove('lazy', 'lazyload');
                if (!img.complete || img.naturalWidth === 0) img.src = img.src;
            });
            logMessage('info', `Force loaded ${images.length} image(s).`);

            const videos = document.querySelectorAll('video');
            videos.forEach(video => {
                video.setAttribute('preload', 'auto');
                video.load();
            });
            logMessage('info', `Force loaded ${videos.length} video(s).`);

            const iframes = document.querySelectorAll('iframe');
            iframes.forEach(iframe => {
                const src = iframe.getAttribute('src');
                if (src) iframe.src = src;
            });
            logMessage('info', `Force loaded ${iframes.length} iframe(s).`);
        } catch (error) {
            logMessage('error', `Error in forceLoadMedia: ${error}`);
        }
    }

    /**********************************
     * Unblurring Methods             *
     **********************************/

    function unblurElements() {
        try {
            const blurredElements = document.querySelectorAll('[style*="filter: blur"], .blurred');
            blurredElements.forEach(el => {
                el.style.filter = 'none';
                el.classList.remove('blurred');
            });
            logMessage('info', `Removed CSS blur filters from ${blurredElements.length} element(s).`);
        } catch (error) {
            logMessage('error', `Error in unblurElements: ${error}`);
        }
    }

    /**********************************
     * Canvas-Based Image Unblurring  *
     **********************************/

    function applyConvolution(imageData, kernel, kernelSize) {
        const { width, height, data: inputData } = imageData;
        const outputData = new Uint8ClampedArray(inputData.length);
        const half = Math.floor(kernelSize / 2);

        for (let y = 0; y < height; y++) {
            for (let x = 0; x < width; x++) {
                let r = 0, g = 0, b = 0, a = 0;
                for (let ky = -half; ky <= half; ky++) {
                    for (let kx = -half; kx <= half; kx++) {
                        const ix = x + kx;
                        const iy = y + ky;
                        if (ix >= 0 && ix < width && iy >= 0 && iy < height) {
                            const idx = (iy * width + ix) * 4;
                            const weight = kernel[(ky + half) * kernelSize + (kx + half)];
                            r += inputData[idx] * weight;
                            g += inputData[idx + 1] * weight;
                            b += inputData[idx + 2] * weight;
                            a += inputData[idx + 3] * weight;
                        }
                    }
                }
                const outIdx = (y * width + x) * 4;
                outputData[outIdx] = Math.min(255, Math.max(0, r));
                outputData[outIdx + 1] = Math.min(255, Math.max(0, g));
                outputData[outIdx + 2] = Math.min(255, Math.max(0, b));
                outputData[outIdx + 3] = Math.min(255, Math.max(0, a));
            }
        }
        return new ImageData(outputData, width, height);
    }

    function sharpenImageData(imageData) {
        const kernel = [-1, -1, -1, -1, 9, -1, -1, -1, -1];
        return applyConvolution(imageData, kernel, 3);
    }

    function advancedUnblurImages_Canvas() {
        try {
            const imgs = document.querySelectorAll('img');
            imgs.forEach(img => {
                try {
                    img.style.filter = 'none';
                    if (!img.complete || img.naturalWidth === 0) {
                        logMessage('warn', 'Skipping an image because it is not fully loaded.');
                        return;
                    }
                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');
                    canvas.width = img.naturalWidth;
                    canvas.height = img.naturalHeight;
                    context.drawImage(img, 0, 0);
                    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                    context.putImageData(sharpenImageData(imageData), 0, 0);
                    img.src = canvas.toDataURL();
                    logMessage('info', 'Canvas-based advanced unblurring applied to an image.');
                } catch (innerError) {
                    logMessage('error', 'Error in canvas-based unblur: ' + innerError);
                }
            });
        } catch (error) {
            logMessage('error', 'Error in advancedUnblurImages_Canvas: ' + error);
        }
    }

    /************************************
     * OpenCV.js-Based Image Unblurring *
     ************************************/

    function loadOpenCVJS(callback) {
        if (window.cv) {
            callback();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://docs.opencv.org/4.x/opencv.js';
        script.async = true;
        script.onload = function () {
            cv.onRuntimeInitialized = function () {
                logMessage('info', 'OpenCV.js runtime initialized.');
                callback();
            };
        };
        script.onerror = function () {
            logMessage('error', 'Failed to load OpenCV.js.');
        };
        document.body.appendChild(script);
    }

    function advancedUnblurImages_OpenCV() {
        loadOpenCVJS(() => {
            const imgs = document.querySelectorAll('img');
            imgs.forEach(img => {
                try {
                    img.style.filter = 'none';
                    if (!img.complete || img.naturalWidth === 0) {
                        logMessage('warn', 'Skipping an image (OpenCV) because it is not fully loaded.');
                        return;
                    }
                    const canvas = document.createElement('canvas');
                    canvas.width = img.naturalWidth;
                    canvas.height = img.naturalHeight;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0);
                    const src = cv.imread(canvas);
                    const dst = new cv.Mat();
                    const kernel = cv.matFromArray(3, 3, cv.CV_32F, [-1, -1, -1, -1, 9, -1, -1, -1, -1]);
                    cv.filter2D(src, dst, cv.CV_8U, kernel);
                    cv.imshow(canvas, dst);
                    src.delete();
                    dst.delete();
                    kernel.delete();
                    img.src = canvas.toDataURL();
                    logMessage('info', 'OpenCV-based advanced unblurring applied to an image.');
                } catch (e) {
                    logMessage('error', 'Error in advancedUnblurImages_OpenCV: ' + e);
                }
            });
        });
    }

    function advancedUnblurContent() {
        try {
            unblurElements();
            forceLoadMedia();
            advancedUnblurImages_Canvas();
            logMessage('info', 'Advanced unblur content executed.');
        } catch (error) {
            logMessage('error', 'Error in advancedUnblurContent: ' + error);
        }
    }

    /**********************************
     * Reveal Hidden Text Function    *
     **********************************/

    function revealHiddenText() {
        const textElements = document.querySelectorAll('.text_layer *');
        textElements.forEach(el => {
            try {
                const cs = window.getComputedStyle(el);
                if (cs.color === 'rgba(0, 0, 0, 0)' || cs.color === 'transparent') el.style.color = 'black';
                if (cs.textShadow && cs.textShadow !== 'none') el.style.textShadow = 'none';
                if (Number(cs.opacity) < 1) el.style.opacity = '1';
            } catch (e) {
                logMessage('error', 'Error in revealHiddenText on an element: ' + e);
            }
        });
        logMessage('info', 'Completed revealHiddenText() processing.');
    }

    /**********************************
     * Advanced Hidden Data Recovery  *
     **********************************/

    function advancedRecoverHiddenContent() {
        let recoveredCount = 0;
        const mediaElements = document.querySelectorAll('img, video, iframe, embed, object');
        mediaElements.forEach(el => {
            try {
                const cs = window.getComputedStyle(el);
                const zIndex = parseInt(cs.zIndex, 10) || 0;
                if (zIndex > 1000) return;
                const rect = el.getBoundingClientRect();
                const isHidden = cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0' || rect.width === 0 || rect.height === 0;
                if (isHidden) {
                    el.style.display = 'block';
                    el.style.visibility = 'visible';
                    el.style.opacity = '1';
                    if (el.tagName.toLowerCase() === 'img' && (!el.complete || el.naturalWidth === 0)) el.src = el.src;
                    recoveredCount++;
                }
            } catch (e) {
                logMessage('error', 'Error processing media element in advancedRecoverHiddenContent: ' + e);
            }
        });

        const textElements = document.querySelectorAll('p, span, div');
        textElements.forEach(el => {
            try {
                if (el.closest('#ethicalDataSidebar')) return;
                const cs = window.getComputedStyle(el);
                const zIndex = parseInt(cs.zIndex, 10) || 0;
                if (zIndex > 1000) return;
                const rect = el.getBoundingClientRect();
                const isHidden = cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0' || rect.width < 5 || rect.height < 5;
                const text = (el.innerText || '').trim();
                if (text.length > 5 && isHidden) {
                    el.style.display = 'block';
                    el.style.visibility = 'visible';
                    el.style.opacity = '1';
                    recoveredCount++;
                }
            } catch (e) {
                logMessage('error', 'Error processing text element in advancedRecoverHiddenContent: ' + e);
            }
        });

        logMessage('info', `Advanced recovered ${recoveredCount} content element(s).`);
    }

    /**********************************
     * Fix Elements for Accessibility *
     **********************************/

    function fixElementsForAccessibility() {
        try {
            const unselectableElements = document.querySelectorAll('[unselectable="on"]');
            unselectableElements.forEach(el => el.removeAttribute('unselectable'));
            logMessage('info', `Removed unselectable attribute from ${unselectableElements.length} element(s).`);

            const promoElements = document.querySelectorAll('.promo_div');
            promoElements.forEach(el => {
                el.style.display = 'none';
            });
            logMessage('info', `Hid ${promoElements.length} promo element(s).`);
        } catch (error) {
            logMessage('error', 'Error in fixElementsForAccessibility: ' + error);
        }
    }

    /**********************************
     * Data Extraction Functions      *
     **********************************/

    function extractData() {
        const data = { texts: [], images: [], videos: [], docs: [] };
        try {
            document.querySelectorAll('p, h1, h2, h3, h4, h5, h6').forEach(el => {
                if (el.closest('#ethicalDataSidebar')) return;
                const txt = (el.innerText || '').trim();
                if (txt) data.texts.push(txt);
            });
            data.images = Array.from(document.querySelectorAll('img')).map(img => ({
                src: img.dataset?.fullsrc || img.src,
                naturalWidth: img.naturalWidth,
                naturalHeight: img.naturalHeight,
                displayedWidth: img.width,
                displayedHeight: img.height,
                alt: img.alt || '',
            })).filter(obj => obj.src);
            data.videos = Array.from(document.querySelectorAll('video, iframe'))
                .map(el => (el.tagName.toLowerCase() === 'video' ? (el.currentSrc || el.src) : el.src))
                .filter(Boolean);
            data.docs = Array.from(document.querySelectorAll('a'))
                .map(a => a.href)
                .filter(href => /\.(pdf|docx?|xlsx?|pptx?)($|\?)/i.test(href));
            logMessage('info', 'Basic data extraction complete.');
        } catch (error) {
            logMessage('error', `Error in extractData: ${error}`);
        }
        return data;
    }

    function extractMetaTags() {
        const metaData = {};
        try {
            const metaTags = document.querySelectorAll('meta[property^="og:"], meta[name="description"], meta[name="keywords"], meta[name^="twitter:"]');
            metaTags.forEach(meta => {
                const key = meta.getAttribute('property') || meta.getAttribute('name');
                const content = meta.getAttribute('content');
                if (key && content) metaData[key] = content;
            });
            logMessage('info', `Extracted ${Object.keys(metaData).length} meta tag(s).`);
        } catch (error) {
            logMessage('error', `Error in extractMetaTags: ${error}`);
        }
        return metaData;
    }

    function extractBackgroundImages() {
        const backgroundImages = [];
        try {
            document.querySelectorAll('[style*="background-image"]').forEach(el => {
                if (el.closest('#ethicalDataSidebar')) return;
                const style = el.getAttribute('style') || '';
                const match = /background-image:\s*url\((['"]?)(.*?)\1\)/i.exec(style);
                if (match?.[2]) backgroundImages.push(match[2]);
            });
            logMessage('info', `Extracted ${backgroundImages.length} background image(s).`);
        } catch (error) {
            logMessage('error', `Error in extractBackgroundImages: ${error}`);
        }
        return backgroundImages;
    }

    function extractHiddenForms() {
        const formsData = [];
        try {
            document.querySelectorAll('form input[type="hidden"]').forEach(input => {
                formsData.push({
                    name: input.name,
                    value: input.value,
                    form: input.form ? (input.form.action || 'N/A') : 'N/A',
                });
            });
            logMessage('info', `Extracted ${formsData.length} hidden form field(s).`);
        } catch (error) {
            logMessage('error', `Error in extractHiddenForms: ${error}`);
        }
        return formsData;
    }

    function extractShadowDOMData() {
        const shadowData = [];
        try {
            function traverseShadow(root) {
                let collectedText = '';
                root.childNodes.forEach(node => {
                    if (node.nodeType === Node.TEXT_NODE) {
                        collectedText += node.textContent.trim() + ' ';
                    } else if (node.nodeType === Node.ELEMENT_NODE) {
                        collectedText += (node.innerText || '').trim() + ' ';
                        if (node.shadowRoot) collectedText += traverseShadow(node.shadowRoot);
                    }
                });
                return collectedText;
            }
            document.querySelectorAll('*').forEach(el => {
                if (el.id === 'ethicalDataSidebar') return;
                if (el.shadowRoot) shadowData.push({ host: el.tagName, text: traverseShadow(el.shadowRoot).trim() });
            });
            logMessage('info', `Extracted shadow DOM data from ${shadowData.length} element(s).`);
        } catch (error) {
            logMessage('error', `Error in extractShadowDOMData: ${error}`);
        }
        return shadowData;
    }

    function advancedExtractData() {
        const basicData = extractData();
        return {
            ...basicData,
            meta: extractMetaTags(),
            backgrounds: extractBackgroundImages(),
            hiddenForms: extractHiddenForms(),
            shadow: extractShadowDOMData(),
        };
    }

    /**********************************
     * OCR Functionality (Tesseract)  *
     **********************************/

    function loadTesseractJS(callback) {
        if (window.Tesseract) {
            callback();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@v2.1.5/dist/tesseract.min.js';
        script.onload = () => {
            logMessage('info', 'Tesseract.js loaded.');
            callback();
        };
        script.onerror = () => logMessage('error', 'Failed to load Tesseract.js.');
        document.body.appendChild(script);
    }

    function appendOutput(html) {
        const outputDiv = document.getElementById('dataOutput');
        if (outputDiv) outputDiv.insertAdjacentHTML('beforeend', html);
    }

    function performOCR() {
        try {
            appendOutput('<p>Starting OCR processing...</p>');
            loadTesseractJS(() => {
                const imgs = Array.from(document.querySelectorAll('img')).filter(img => img.src && !img.closest('#ethicalDataSidebar'));
                if (imgs.length === 0) {
                    appendOutput('<p>No images found for OCR.</p>');
                    logMessage('warn', 'No images available for OCR.');
                    return;
                }
                const ocrResults = [];
                let current = 0;
                function processNext() {
                    if (current >= imgs.length) {
                        appendOutput(`<p><strong>OCR Completed.</strong></p><details open><summary>OCR Results (first 3)</summary><pre style="white-space: pre-wrap;">${escapeHtml(ocrResults.slice(0, 3).join('\n\n'))}</pre></details>`);
                        logMessage('info', 'OCR processing completed.');
                        return;
                    }
                    const img = imgs[current];
                    appendOutput(`<p>Processing image ${current + 1} of ${imgs.length}...</p>`);
                    window.Tesseract.recognize(img.src, 'eng', { logger: m => safeConsole('log', m) })
                        .then(result => ocrResults.push(result.data.text.trim()))
                        .catch(err => {
                            ocrResults.push(`Error processing image: ${err}`);
                            logMessage('error', `OCR error on image ${current + 1}: ${err}`);
                        })
                        .finally(() => {
                            current++;
                            processNext();
                        });
                }
                processNext();
            });
        } catch (error) {
            logMessage('error', `Error in performOCR: ${error}`);
        }
    }

    /**********************************
     * Sidebar Interface & Controls   *
     **********************************/

    function createButton(id, text) {
        return `<button id="${id}" class="edt-btn" type="button">${escapeHtml(text)}</button>`;
    }

    function createSidebar() {
        let sidebar = document.getElementById('ethicalDataSidebar');
        if (sidebar) return sidebar;

        sidebar = document.createElement('div');
        sidebar.id = 'ethicalDataSidebar';
        sidebar.innerHTML = `
            <style>
                #ethicalDataSidebar, #ethicalDataSidebar * { box-sizing: border-box; }
                #ethicalDataSidebar {
                    position: fixed; z-index: 2147483647; color: #fff; background: rgba(0,0,0,var(--edt-opacity));
                    font-family: Arial, sans-serif; font-size: 14px; line-height: 1.4; box-shadow: 0 0 20px rgba(0,0,0,.45);
                    border: 1px solid rgba(255,255,255,.18); border-radius: 10px 0 0 10px; overflow: hidden;
                    min-width: 48px; max-width: min(95vw, 900px); max-height: 98vh;
                }
                #ethicalDataSidebar.edt-left { border-radius: 0 10px 10px 0; }
                #ethicalDataSidebar.edt-collapsed { width: 48px !important; height: auto !important; }
                #ethicalDataSidebar.edt-collapsed .edt-body, #ethicalDataSidebar.edt-collapsed .edt-title-text { display: none; }
                #ethicalDataSidebar.edt-collapsed .edt-header { writing-mode: vertical-rl; min-height: 210px; cursor: pointer; }
                .edt-header { display: flex; gap: 6px; align-items: center; padding: 8px; background: rgba(24,24,24,.96); cursor: move; user-select: none; }
                .edt-title-text { font-weight: 700; flex: 1; }
                .edt-icon-btn { border: 1px solid #666; background: #222; color: #fff; border-radius: 6px; cursor: pointer; min-width: 30px; height: 28px; }
                .edt-body { padding: 10px; overflow: auto; height: calc(100% - 45px); }
                .edt-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
                .edt-btn { padding: 7px; border: 1px solid #666; border-radius: 6px; background: #1f6feb; color: #fff; cursor: pointer; }
                .edt-btn:hover, .edt-icon-btn:hover { filter: brightness(1.15); }
                .edt-secondary { background: #30363d; }
                #dataOutput pre, #logArea { max-width: 100%; overflow: auto; background: #181818; border-radius: 6px; padding: 6px; }
                #logArea { max-height: 150px; font-size: 12px; }
                .edt-help { color: #c9d1d9; font-size: 12px; margin: 8px 0; }
                .edt-resizer { position: absolute; width: 14px; height: 14px; right: 0; bottom: 0; cursor: nwse-resize; background: linear-gradient(135deg, transparent 50%, #888 50%); }
                #ethicalDataSidebar.edt-left .edt-resizer { left: 0; right: auto; cursor: nesw-resize; transform: scaleX(-1); }
                .edt-range { width: 100%; }
            </style>
            <div class="edt-header" title="Drag to move. Double-click to collapse/expand.">
                <span class="edt-title-text">Data Extraction</span>
                <button id="edtDockBtn" class="edt-icon-btn" type="button" title="Dock left/right">⇄</button>
                <button id="edtCollapseBtn" class="edt-icon-btn" type="button" title="Collapse/expand">⤢</button>
            </div>
            <div class="edt-body">
                <div class="edt-help">Tip: collapse or drag this panel when it covers the page. Position, size, dock, opacity, and collapsed state are saved per site.</div>
                <div class="edt-actions">
                    ${createButton('refreshDataBtn', 'Refresh Data')}
                    ${createButton('forceLoadMediaBtn', 'Force Load Media')}
                    ${createButton('unblurContentBtn', 'Advanced Unblur (Canvas)')}
                    ${createButton('unblurContentOpenCVBtn', 'Advanced Unblur (OpenCV)')}
                    ${createButton('revealTextBtn', 'Reveal Hidden Text')}
                    ${createButton('recoverHiddenBtn', 'Recover Hidden Data')}
                    ${createButton('fixElementsBtn', 'Enable Selection / Remove Overlays')}
                    ${createButton('ocrImagesBtn', 'Perform OCR on Images')}
                    ${createButton('exportDataBtn', 'Export JSON')}
                    ${createButton('clearLogsBtn', 'Clear Logs')}
                    ${createButton('toggleObserverBtn', uiState.observerPaused ? 'Resume Live Updates' : 'Pause Live Updates')}
                    ${createButton('resetUiBtn', 'Reset Panel')}
                </div>
                <label class="edt-help" for="edtOpacityRange">Panel opacity</label>
                <input id="edtOpacityRange" class="edt-range" type="range" min="0.35" max="1" value="${uiState.opacity}" step="0.05">
                <div id="dataOutput" style="margin-top:10px;"></div>
                <hr>
                <h3>Logs</h3>
                <div id="logArea"></div>
            </div>
            <div class="edt-resizer" title="Resize panel"></div>
        `;
        document.body.appendChild(sidebar);

        wireSidebarEvents(sidebar);
        applySidebarState(sidebar);
        logMessage('info', 'Sidebar created and event listeners attached.');
        return sidebar;
    }

    function applySidebarState(sidebar = document.getElementById('ethicalDataSidebar')) {
        if (!sidebar) return;
        uiState.width = Math.max(260, Math.min(Number(uiState.width) || DEFAULT_UI_STATE.width, Math.min(window.innerWidth * 0.95, 900)));
        uiState.height = Math.max(260, Math.min(Number(uiState.height) || DEFAULT_UI_STATE.height, window.innerHeight * 0.98));
        sidebar.style.setProperty('--edt-opacity', String(uiState.opacity));
        sidebar.classList.toggle('edt-collapsed', Boolean(uiState.collapsed));
        sidebar.classList.toggle('edt-left', uiState.dock === 'left');
        sidebar.style.width = uiState.collapsed ? '48px' : `${uiState.width}px`;
        sidebar.style.height = uiState.collapsed ? 'auto' : `${uiState.height}px`;
        sidebar.style.top = `${Math.max(0, Math.min(Number(uiState.top) || 0, window.innerHeight - 48))}px`;
        sidebar.style.left = '';
        sidebar.style.right = '';
        if (uiState.dock === 'left') {
            sidebar.style.left = uiState.left == null ? '0px' : `${Math.max(0, Number(uiState.left) || 0)}px`;
        } else {
            sidebar.style.right = '0px';
        }
        const opacityRange = document.getElementById('edtOpacityRange');
        if (opacityRange) opacityRange.value = uiState.opacity;
        const toggleObserverBtn = document.getElementById('toggleObserverBtn');
        if (toggleObserverBtn) toggleObserverBtn.textContent = uiState.observerPaused ? 'Resume Live Updates' : 'Pause Live Updates';
        saveUiState();
    }

    function toggleCollapsed() {
        uiState.collapsed = !uiState.collapsed;
        applySidebarState();
    }

    function wireSidebarEvents(sidebar) {
        const header = sidebar.querySelector('.edt-header');
        const resizer = sidebar.querySelector('.edt-resizer');

        document.getElementById('refreshDataBtn').addEventListener('click', updateSidebarData);
        document.getElementById('forceLoadMediaBtn').addEventListener('click', () => { forceLoadMedia(); updateSidebarData(); });
        document.getElementById('unblurContentBtn').addEventListener('click', advancedUnblurContent);
        document.getElementById('unblurContentOpenCVBtn').addEventListener('click', advancedUnblurImages_OpenCV);
        document.getElementById('revealTextBtn').addEventListener('click', () => { revealHiddenText(); updateSidebarData(); });
        document.getElementById('recoverHiddenBtn').addEventListener('click', () => { advancedRecoverHiddenContent(); updateSidebarData(); });
        document.getElementById('fixElementsBtn').addEventListener('click', () => { fixElementsForAccessibility(); updateSidebarData(); });
        document.getElementById('ocrImagesBtn').addEventListener('click', performOCR);
        document.getElementById('exportDataBtn').addEventListener('click', exportData);
        document.getElementById('clearLogsBtn').addEventListener('click', () => {
            const logArea = document.getElementById('logArea');
            if (logArea) logArea.innerHTML = '';
        });
        document.getElementById('resetUiBtn').addEventListener('click', () => {
            uiState = { ...DEFAULT_UI_STATE, collapsed: false };
            applySidebarState();
        });
        document.getElementById('toggleObserverBtn').addEventListener('click', () => {
            uiState.observerPaused = !uiState.observerPaused;
            applySidebarState();
            logMessage('info', uiState.observerPaused ? 'Live DOM updates paused.' : 'Live DOM updates resumed.');
        });
        document.getElementById('edtCollapseBtn').addEventListener('click', toggleCollapsed);
        document.getElementById('edtDockBtn').addEventListener('click', () => {
            uiState.dock = uiState.dock === 'right' ? 'left' : 'right';
            uiState.left = 0;
            applySidebarState();
        });
        document.getElementById('edtOpacityRange').addEventListener('input', event => {
            uiState.opacity = Number(event.target.value);
            applySidebarState();
        });
        header.addEventListener('dblclick', toggleCollapsed);
        header.addEventListener('click', event => {
            if (uiState.collapsed && !event.target.closest('button')) toggleCollapsed();
        });

        let drag = null;
        header.addEventListener('pointerdown', event => {
            if (event.target.closest('button')) return;
            drag = { y: event.clientY, top: parseFloat(sidebar.style.top) || 0, x: event.clientX, left: sidebar.getBoundingClientRect().left };
            header.setPointerCapture(event.pointerId);
        });
        header.addEventListener('pointermove', event => {
            if (!drag) return;
            uiState.top = Math.max(0, Math.min(drag.top + event.clientY - drag.y, window.innerHeight - 48));
            if (uiState.dock === 'left') uiState.left = Math.max(0, Math.min(drag.left + event.clientX - drag.x, window.innerWidth - 48));
            applySidebarState();
        });
        header.addEventListener('pointerup', event => {
            drag = null;
            try { header.releasePointerCapture(event.pointerId); } catch (error) { /* no-op */ }
        });

        let resize = null;
        resizer.addEventListener('pointerdown', event => {
            event.preventDefault();
            resize = { x: event.clientX, y: event.clientY, width: sidebar.offsetWidth, height: sidebar.offsetHeight };
            resizer.setPointerCapture(event.pointerId);
        });
        resizer.addEventListener('pointermove', event => {
            if (!resize) return;
            const dx = uiState.dock === 'left' ? resize.x - event.clientX : event.clientX - resize.x;
            uiState.width = Math.max(260, Math.min(resize.width + dx, Math.min(window.innerWidth * 0.95, 900)));
            uiState.height = Math.max(260, Math.min(resize.height + event.clientY - resize.y, window.innerHeight * 0.98));
            uiState.collapsed = false;
            applySidebarState();
        });
        resizer.addEventListener('pointerup', event => {
            resize = null;
            try { resizer.releasePointerCapture(event.pointerId); } catch (error) { /* no-op */ }
        });
    }

    function updateSidebarData() {
        if (isUpdatingSidebar) return;
        isUpdatingSidebar = true;
        try {
            const detailsStates = {};
            document.querySelectorAll('#dataOutput details').forEach(d => {
                const summaryText = d.querySelector('summary')?.innerText || '';
                detailsStates[summaryText] = d.hasAttribute('open');
            });

            const data = advancedExtractData();
            const outputDiv = document.getElementById('dataOutput');
            if (!outputDiv) return;

            outputDiv.innerHTML = `
                <p><strong>Text Blocks:</strong> ${data.texts.length}</p>
                <p><strong>Images:</strong> ${data.images.length}</p>
                <p><strong>Videos:</strong> ${data.videos.length}</p>
                <p><strong>Document Links:</strong> ${data.docs.length}</p>
                <hr>
                <details><summary>View Text (first 5)</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.texts.slice(0, 5).join('\n\n'))}</pre></details>
                <details><summary>View Image Data (first 5)</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.images.slice(0, 5).map(img => `src: ${img.src}\nnatural: ${img.naturalWidth}x${img.naturalHeight}\ndisplayed: ${img.displayedWidth}x${img.displayedHeight}\nalt: ${img.alt}`).join('\n\n'))}</pre></details>
                <details><summary>View Video URLs (first 5)</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.videos.slice(0, 5).join('\n'))}</pre></details>
                <details><summary>View Document Links (first 5)</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.docs.slice(0, 5).join('\n'))}</pre></details>
                <hr>
                <details><summary>Meta Tags (${Object.keys(data.meta).length})</summary><pre style="white-space: pre-wrap;">${escapeHtml(JSON.stringify(data.meta, null, 2))}</pre></details>
                <details><summary>Background Images (${data.backgrounds.length})</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.backgrounds.slice(0, 5).join('\n'))}</pre></details>
                <details><summary>Hidden Form Fields (${data.hiddenForms.length})</summary><pre style="white-space: pre-wrap;">${escapeHtml(JSON.stringify(data.hiddenForms.slice(0, 5), null, 2))}</pre></details>
                <details><summary>Shadow DOM Data (${data.shadow.length})</summary><pre style="white-space: pre-wrap;">${escapeHtml(data.shadow.slice(0, 3).map(item => item.host + ': ' + item.text).join('\n\n'))}</pre></details>
            `;

            document.querySelectorAll('#dataOutput details').forEach(d => {
                const summaryText = d.querySelector('summary')?.innerText || '';
                if (detailsStates[summaryText]) d.setAttribute('open', '');
            });

            logMessage('info', 'Sidebar data updated.');
        } catch (error) {
            logMessage('error', `Error in updateSidebarData: ${error}`);
        } finally {
            setTimeout(() => { isUpdatingSidebar = false; }, 0);
        }
    }

    function exportData() {
        try {
            const data = advancedExtractData();
            const dataStr = JSON.stringify(data, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'extractedData.json';
            a.click();
            URL.revokeObjectURL(url);
            logMessage('info', 'Data exported as JSON.');
        } catch (error) {
            logMessage('error', `Error in exportData: ${error}`);
        }
    }

    /**********************************
     * Other Core Functionalities     *
     **********************************/

    function enableRightClickAndCopyPaste() {
        try {
            ['contextmenu', 'copy', 'cut', 'paste'].forEach(eventName => {
                document.addEventListener(eventName, function (e) {
                    try { e.stopPropagation(); } catch (err) { logMessage('error', `Error in ${eventName} event: ${err}`); }
                }, true);
            });
            logMessage('info', 'Right-click and copy-paste events re-enabled.');
        } catch (error) {
            logMessage('error', `Error in enableRightClickAndCopyPaste: ${error}`);
        }
    }

    function expandHiddenSections() {
        try {
            let clickCount = 0;
            document.querySelectorAll('button, a').forEach(btn => {
                try {
                    if (btn.closest('#ethicalDataSidebar')) return;
                    const txt = (btn.textContent || '').toLowerCase();
                    if (txt.includes('show more') || txt.includes('read more')) {
                        btn.click();
                        clickCount++;
                    }
                } catch (err) {
                    logMessage('error', `Error processing button: ${err}`);
                }
            });
            logMessage('info', `Clicked ${clickCount} "show more/read more" button(s).`);
        } catch (error) {
            logMessage('error', `Error in expandHiddenSections: ${error}`);
        }
    }

    /**********************************
     * Mutation Observer (Debounced)  *
     **********************************/

    const debouncedUpdate = debounce(() => {
        if (uiState.observerPaused || isUpdatingSidebar) return;
        try {
            unblurElements();
            expandHiddenSections();
            updateSidebarData();
        } catch (error) {
            logMessage('error', `Error in debounced DOM update: ${error}`);
        }
    }, 750);

    function observeDomChanges() {
        try {
            if (domObserver) domObserver.disconnect();
            domObserver = new MutationObserver(mutations => {
                if (mutations.every(m => m.target?.closest?.('#ethicalDataSidebar'))) return;
                debouncedUpdate();
            });
            domObserver.observe(document.body, { childList: true, subtree: true });
            logMessage('info', 'DOM observer initialized.');
        } catch (error) {
            logMessage('error', `Error in observeDomChanges: ${error}`);
        }
    }

    /**********************************
     * Initialization                 *
     **********************************/

    function init() {
        try {
            enableRightClickAndCopyPaste();
            unblurElements();
            expandHiddenSections();
            createSidebar();
            updateSidebarData();
            observeDomChanges();
            logMessage('info', 'Advanced Responsive Ethical Data Gathering Tool initialized.');
        } catch (error) {
            logMessage('error', `Error during init: ${error}`);
        }
    }

    window.addEventListener('load', init);
}());
