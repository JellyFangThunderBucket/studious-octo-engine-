// ==UserScript==
// @name         No Middle Man
// @namespace    https://fivethreenine.blogspot.com/2006/03/no-middle-man.html
// @version      2026.06.24
// @description  Rewrites common tracking and redirect links to point directly at their destination URL.
// @author       fivethreenine; 2026 refresh by OpenAI
// @license      MIT
// @match        http://*/*
// @match        https://*/*
// @exclude      http://del.icio.us/*
// @exclude      https://del.icio.us/*
// @exclude      http://*bloglines.com/*
// @exclude      https://*bloglines.com/*
// @exclude      http://web.archive.org/*
// @exclude      https://web.archive.org/*
// @exclude      http://*wists.com/*
// @exclude      https://*wists.com/*
// @exclude      http://www.google.*/*
// @exclude      https://www.google.*/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(() => {
  'use strict';

  const SKIP_PROTOCOLS = new Set(['javascript:', 'mailto:', 'tel:', 'sms:', 'data:', 'blob:']);
  const SKIP_HOSTS = ['geourl.org'];
  const DESTINATION_PARAMS = [
    'url', 'u', 'uri', 'target', 'to', 'dest', 'destination', 'redirect', 'redirect_url',
    'redirect_uri', 'redir', 'r', 'q', 'link', 'href', 'out', 'out_url', 'go', 'next',
    'continue', 'return', 'returnTo', 'return_to', 'source', 'amp;url', 'amp;u',
  ];
  const ABSOLUTE_URL_PATTERN = /https?(?::|%3a|%253a)(?:\/\/|%2f%2f|%252f%252f)/i;
  const WWW_PATTERN = /(?:^|[?&#/=])((?:www\.)[^\s?&#<>"']+\.[^\s?&#<>"']+)/i;

  function safelyDecode(value) {
    let decoded = String(value || '').replace(/&amp;/gi, '&');

    for (let i = 0; i < 5; i += 1) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }

    return decoded;
  }

  function normalizeUrl(value) {
    const decoded = safelyDecode(value).trim();
    if (!decoded) return '';

    if (/^\/\/[^/]/.test(decoded)) return `${location.protocol}${decoded}`;
    if (/^www\./i.test(decoded)) return `https://${decoded}`;

    try {
      return new URL(decoded, location.href).href;
    } catch {
      return '';
    }
  }

  function isHttpUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
      return false;
    }
  }

  function shouldSkip(link) {
    if (!link.href) return true;

    try {
      const current = new URL(link.href, location.href);
      return SKIP_PROTOCOLS.has(current.protocol) || SKIP_HOSTS.some((host) => current.hostname.endsWith(host));
    } catch {
      return true;
    }
  }

  function looksLikeDestination(value) {
    const decoded = safelyDecode(value).trim();
    return /^(?:https?:|https?%3a|https?%253a|\/\/|www\.)/i.test(decoded);
  }

  function fromKnownParameters(linkUrl) {
    const params = new URLSearchParams(linkUrl.search);

    for (const param of DESTINATION_PARAMS) {
      const value = params.get(param);
      if (!value || !looksLikeDestination(value)) continue;
      const candidate = normalizeUrl(value);
      if (candidate && isHttpUrl(candidate)) return candidate;
    }

    for (const value of params.values()) {
      if (!looksLikeDestination(value)) continue;
      const candidate = extractDestination(value);
      if (candidate) return candidate;
    }

    return '';
  }

  function fromEmbeddedAbsoluteUrl(rawHref) {
    let decoded = safelyDecode(rawHref);
    const match = decoded.match(ABSOLUTE_URL_PATTERN);
    if (!match || match.index <= 0) return '';

    decoded = decoded.slice(match.index);
    const end = decoded.search(/[&\s<>"']/);
    const candidate = normalizeUrl(end === -1 ? decoded : decoded.slice(0, end));
    return isHttpUrl(candidate) ? candidate : '';
  }

  function fromBareWww(rawHref) {
    const match = safelyDecode(rawHref).match(WWW_PATTERN);
    if (!match || !match[1]) return '';

    const candidate = normalizeUrl(match[1]);
    return isHttpUrl(candidate) ? candidate : '';
  }

  function extractDestination(rawHref) {
    if (!rawHref) return '';

    const normalized = normalizeUrl(rawHref);
    if (!normalized || !isHttpUrl(normalized)) return '';

    try {
      const linkUrl = new URL(normalized);
      return fromKnownParameters(linkUrl) || fromEmbeddedAbsoluteUrl(rawHref) || fromBareWww(rawHref);
    } catch {
      return fromEmbeddedAbsoluteUrl(rawHref) || fromBareWww(rawHref);
    }
  }

  function unwrapLink(link) {
    if (shouldSkip(link)) return false;

    const destination = extractDestination(link.href);
    if (!destination || destination === link.href) return false;

    link.href = destination;
    link.dataset.noMiddleManUnwrapped = 'true';
    return true;
  }

  function unwrapLinks(root = document) {
    root.querySelectorAll?.('a[href]').forEach(unwrapLink);
  }

  unwrapLinks();

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.matches?.('a[href]')) unwrapLink(node);
        unwrapLinks(node);
      });

      if (mutation.type === 'attributes' && mutation.target instanceof HTMLAnchorElement) {
        unwrapLink(mutation.target);
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['href'],
  });
})();
