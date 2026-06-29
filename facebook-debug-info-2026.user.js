// ==UserScript==
// @name         Facebook Debug Info Helper 2026
// @namespace    https://littlelooney.example/facebook-debug-info
// @version      2026-06-29
// @description  Consent-first helper that extracts visible Facebook profile/post identifiers and URLs from the current rendered page without bypassing authentication, privacy controls, or platform protections.
// @author       LittleLooney + OpenAI
// @license      Copyright (C) Littlelooney All rights reserved.
// @match        https://www.facebook.com/*
// @match        https://m.facebook.com/*
// @match        https://web.facebook.com/*
// @grant        GM_setClipboard
// @grant        GM_registerMenuCommand
// @run-at       document-idle
// ==/UserScript==

(() => {
  'use strict';

  /**
   * Facebook Debug Info Helper 2026
   * ------------------------------------------------------------
   * A safer modernization of the original console snippet.
   *
   * What it does:
   * - Reads identifiers already present in the rendered page, URL, anchors,
   *   metadata, and JSON-ish script text.
   * - Avoids fragile single-class selectors where possible.
   * - Supports modern Facebook URL forms such as /posts/pfbid..., /share/p/,
   *   story.php, permalink.php, photo.php, videos, reels, groups, and mobile hosts.
   * - Exposes a stable window.getFacebookDebugInfo2026(flag) function plus a
   *   small Tampermonkey menu command.
   *
   * What it does NOT do:
   * - It does not bypass login, privacy settings, paywalls, DRM, or rate limits.
   * - It does not call private APIs or exfiltrate data.
   * - It does not collect hidden form values or secrets.
   */

  const APP_NAME = 'FacebookDebugInfo2026';
  const BASE_HOST_RE = /^(?:www\.|m\.|web\.)?facebook\.com$/i;
  const ID_RE = /\b\d{5,}\b/g;
  const PFBID_RE = /pfbid[0-9A-Za-z_-]+/;
  const SAFE_TEXT_LIMIT = 1_500_000;
  const SCRIPT_SCAN_LIMIT = 120;

  const FLAG_ALIASES = Object.freeze({
    ALL: 'ALL',
    0: 'ALL',
    PROFILEID: 'PROFILE_ID',
    PROFILE_ID: 'PROFILE_ID',
    1: 'PROFILE_ID',
    POSTID: 'POST_ID',
    POST_ID: 'POST_ID',
    2: 'POST_ID',
    POSTPFBID: 'POST_PFBID',
    POST_PFBID: 'POST_PFBID',
    PFBID: 'POST_PFBID',
    COMBINE: 'COMBINED_URL',
    COMBINED: 'COMBINED_URL',
    COMBINED_URL: 'COMBINED_URL',
    3: 'COMBINED_URL',
    COPY: 'COPY',
    JSON: 'JSON',
  });

  function normalizeFlag(flag = 'ALL') {
    return FLAG_ALIASES[String(flag).toUpperCase()] || 'ALL';
  }

  function safeDecode(value) {
    if (!value) return '';
    let output = String(value);
    for (let index = 0; index < 3; index += 1) {
      try {
        const decoded = decodeURIComponent(output);
        if (decoded === output) break;
        output = decoded;
      } catch {
        break;
      }
    }
    return output;
  }

  function asFacebookUrl(value) {
    if (!value) return null;
    try {
      const url = new URL(value, location.href);
      return BASE_HOST_RE.test(url.hostname) ? url : null;
    } catch {
      return null;
    }
  }

  function cleanProfilePath(pathname) {
    const path = safeDecode(pathname).replace(/^\/+|\/+$/g, '');
    if (!path || /^(?:posts|groups|pages|photo|photos|videos|watch|reel|reels|stories|share|permalink\.php|story\.php|profile\.php)$/i.test(path)) {
      return '';
    }
    return path.split('/')[0] || '';
  }

  function uniq(values) {
    return [...new Set(values.filter(Boolean))];
  }

  function readScriptText() {
    const chunks = [];
    for (const script of [...document.scripts].slice(0, SCRIPT_SCAN_LIMIT)) {
      const text = script.textContent || '';
      if (!text) continue;
      if (/debug_info|profile_id|actorID|owning_profile|post_id|feedback_id|story_fbid|pfbid/i.test(text)) {
        chunks.push(text.slice(0, SAFE_TEXT_LIMIT / 4));
      }
      if (chunks.join('\n').length > SAFE_TEXT_LIMIT) break;
    }
    return chunks.join('\n').slice(0, SAFE_TEXT_LIMIT);
  }

  function extractDebugInfoIds(pageText) {
    const ids = [];
    const patterns = [
      /debug_info"\s*:\s*null\s*,\s*"id"\s*:\s*"([A-Za-z0-9+/=_-]{20,120})"/i,
      /debug_info&quot;\s*:\s*null\s*,\s*&quot;id&quot;\s*:\s*&quot;([A-Za-z0-9+/=_-]{20,120})/i,
    ];

    for (const pattern of patterns) {
      const match = pageText.match(pattern);
      if (!match) continue;
      const token = match[1].replace(/-/g, '+').replace(/_/g, '/');
      try {
        ids.push(...(atob(token).match(ID_RE) || []));
      } catch {
        // The token may not be base64 in all Facebook builds; ignore it.
      }
    }
    return uniq(ids);
  }

  function extractUrlFacts(url = new URL(location.href)) {
    const decodedHref = safeDecode(url.href);
    const path = safeDecode(url.pathname);
    const facts = {
      postPfbid: (decodedHref.match(PFBID_RE) || [])[0] || null,
      postID: null,
      profileID: null,
      profileURL: cleanProfilePath(path),
      urlMatches: [],
      contentType: 'unknown',
    };

    const postMatch = path.match(/\/posts\/(\d+|pfbid[0-9A-Za-z_-]+)/i);
    const storyFbid = url.searchParams.get('story_fbid') || url.searchParams.get('fbid');
    const profileIdParam = url.searchParams.get('id') || url.searchParams.get('profile_id');
    const groupPost = path.match(/\/groups\/([^/]+)\/posts\/(\d+|pfbid[0-9A-Za-z_-]+)/i);
    const videoMatch = path.match(/\/(?:videos|watch)\/(?:\?v=)?(\d+)/i) || decodedHref.match(/[?&]v=(\d+)/i);
    const reelMatch = path.match(/\/reel\/(\d+)/i);

    if (postMatch) {
      facts.contentType = 'post';
      if (/^pfbid/i.test(postMatch[1])) facts.postPfbid = postMatch[1];
      else facts.postID = postMatch[1];
    }
    if (groupPost) {
      facts.contentType = 'group_post';
      facts.profileURL = `groups/${groupPost[1]}`;
      if (/^pfbid/i.test(groupPost[2])) facts.postPfbid = groupPost[2];
      else facts.postID = groupPost[2];
    }
    if (storyFbid) {
      facts.contentType = facts.contentType === 'unknown' ? 'story_or_photo' : facts.contentType;
      facts.postID = facts.postID || storyFbid;
    }
    if (profileIdParam) facts.profileID = profileIdParam;
    if (videoMatch) {
      facts.contentType = 'video';
      facts.postID = facts.postID || videoMatch[1];
    }
    if (reelMatch) {
      facts.contentType = 'reel';
      facts.postID = facts.postID || reelMatch[1];
    }

    facts.urlMatches = uniq([
      facts.profileID,
      facts.profileURL,
      facts.postID,
      facts.postPfbid,
      decodedHref.match(/facebook\.com\/[^?#]+/i)?.[0],
    ]);
    return facts;
  }

  function extractProfileFromAnchors() {
    const selectors = [
      'a[role="link"][aria-label]',
      'strong a[href]',
      'h1 a[href]',
      'h2 a[href]',
      'a[href*="/profile.php?id="]',
      'a[href*="facebook.com/"]',
    ];

    for (const anchor of document.querySelectorAll(selectors.join(','))) {
      const href = anchor.getAttribute('href') || '';
      const url = asFacebookUrl(href);
      if (!url) continue;
      const pathName = cleanProfilePath(url.pathname);
      const id = url.searchParams.get('id') || null;
      const label = anchor.getAttribute('aria-label') || anchor.textContent || '';
      const name = label.replace(/,?\s*(?:view story|profile picture|verified).*$/i, '').trim();
      if (id || pathName || name) {
        return {
          profileID: id,
          profileName: name || null,
          profileURL: id ? `profile.php?id=${id}` : pathName || null,
        };
      }
    }
    return { profileID: null, profileName: null, profileURL: null };
  }

  function extractJsonishFacts(pageText) {
    const profileIds = [];
    const postIds = [];
    const profileNames = [];

    const profilePatterns = [
      /"(?:profile_id|actorID|owning_profile_id|authorID|userID)"\s*:\s*"?(\d{5,})"?/gi,
      /&quot;(?:profile_id|actorID|owning_profile_id|authorID|userID)&quot;\s*:\s*&quot;?(\d{5,})/gi,
    ];
    const postPatterns = [
      /"(?:post_id|story_fbid|legacy_fbid|top_level_post_id|subscription_target_id)"\s*:\s*"?(\d{5,})"?/gi,
      /&quot;(?:post_id|story_fbid|legacy_fbid|top_level_post_id|subscription_target_id)&quot;\s*:\s*&quot;?(\d{5,})/gi,
    ];
    const namePatterns = [
      /"name"\s*:\s*"([^"{}]{2,120})"\s*,\s*"(?:url|profile_picture)/gi,
      /&quot;name&quot;\s*:\s*&quot;([^&{}]{2,120})&quot;\s*,\s*&quot;(?:url|profile_picture)/gi,
    ];

    for (const pattern of profilePatterns) {
      for (const match of pageText.matchAll(pattern)) profileIds.push(match[1]);
    }
    for (const pattern of postPatterns) {
      for (const match of pageText.matchAll(pattern)) postIds.push(match[1]);
    }
    for (const pattern of namePatterns) {
      for (const match of pageText.matchAll(pattern)) profileNames.push(safeDecode(match[1].replace(/\\\//g, '/')).trim());
    }

    return {
      profileIDs: uniq(profileIds),
      postIDs: uniq(postIds),
      profileNames: uniq(profileNames),
    };
  }

  function buildCombinedUrl(info) {
    if (info.profileID && info.postID) return `https://www.facebook.com/${info.profileID}/posts/${info.postID}`;
    if (info.profileURL && info.postID) return `https://www.facebook.com/${info.profileURL}/posts/${info.postID}`;
    if (info.postPfbid) {
      const profilePath = info.profileURL ? `${info.profileURL}/` : '';
      return `https://www.facebook.com/${profilePath}posts/${info.postPfbid}`;
    }
    return null;
  }

  function getFacebookDebugInfo2026(flag = 'ALL') {
    const normalizedFlag = normalizeFlag(flag);
    const pageText = `${document.body?.outerHTML || ''}\n${readScriptText()}`.slice(0, SAFE_TEXT_LIMIT);
    const urlFacts = extractUrlFacts();
    const anchorFacts = extractProfileFromAnchors();
    const jsonishFacts = extractJsonishFacts(pageText);
    const debugInfoIds = extractDebugInfoIds(pageText);

    const info = {
      capturedAt: new Date().toISOString(),
      sourceURL: location.href,
      contentType: urlFacts.contentType,
      profileID: urlFacts.profileID || anchorFacts.profileID || jsonishFacts.profileIDs[0] || debugInfoIds[0] || null,
      postID: urlFacts.postID || jsonishFacts.postIDs[0] || debugInfoIds[1] || null,
      postPfbid: urlFacts.postPfbid || null,
      profileName: anchorFacts.profileName || jsonishFacts.profileNames[0] || document.querySelector('meta[property="og:title"]')?.content || document.title || null,
      profileURL: anchorFacts.profileURL || urlFacts.profileURL || null,
      combinedURL: null,
      candidates: {
        profileIDs: uniq([urlFacts.profileID, anchorFacts.profileID, ...jsonishFacts.profileIDs, debugInfoIds[0]]),
        postIDs: uniq([urlFacts.postID, ...jsonishFacts.postIDs, debugInfoIds[1]]),
        profileNames: uniq([anchorFacts.profileName, ...jsonishFacts.profileNames]),
      },
      urlMatch: urlFacts.urlMatches,
      notes: [
        'Only values present in the rendered page/URL were inspected.',
        'If a field is null, Facebook did not expose it in a stable, visible place for this page view.',
      ],
    };
    info.combinedURL = buildCombinedUrl(info);

    const printable = {
      'Profile ID': info.profileID,
      'Post ID': info.postID,
      'Post PFBID': info.postPfbid,
      'Profile Name': info.profileName,
      'Profile URL': info.profileURL,
      'Combined URL': info.combinedURL,
      'URL Match': info.urlMatch,
      Candidates: info.candidates,
    };

    if (normalizedFlag === 'PROFILE_ID') console.log('Profile ID:', info.profileID);
    else if (normalizedFlag === 'POST_ID') console.log('Post ID:', info.postID);
    else if (normalizedFlag === 'POST_PFBID') console.log('Post PFBID:', info.postPfbid);
    else if (normalizedFlag === 'COMBINED_URL') console.log('Combined URL:', info.combinedURL);
    else if (normalizedFlag === 'JSON') console.log(JSON.stringify(info, null, 2));
    else if (normalizedFlag === 'COPY') copyDebugInfo(info);
    else console.table(printable);

    console.log('DEBUG FLAG:', flag, 'normalized as', normalizedFlag);
    return info;
  }

  function copyDebugInfo(info = getFacebookDebugInfo2026('ALL')) {
    const payload = JSON.stringify(info, null, 2);
    if (typeof GM_setClipboard === 'function') GM_setClipboard(payload, 'text');
    else navigator.clipboard?.writeText(payload).catch(() => {});
    console.info(`[${APP_NAME}] Copied debug info JSON to clipboard.`);
    return payload;
  }

  window.getFacebookDebugInfo2026 = getFacebookDebugInfo2026;
  window.getDebugInfo = getFacebookDebugInfo2026;

  if (typeof GM_registerMenuCommand === 'function') {
    GM_registerMenuCommand('Facebook Debug Info 2026: log all', () => getFacebookDebugInfo2026('ALL'));
    GM_registerMenuCommand('Facebook Debug Info 2026: copy JSON', () => getFacebookDebugInfo2026('COPY'));
  }

  console.info(`[${APP_NAME}] Ready. Run getFacebookDebugInfo2026('ALL') in the console.`);
})();
