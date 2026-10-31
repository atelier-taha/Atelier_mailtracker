/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/lib/notification-engine.js
 * 
 * Decentralized Client-Side Polling & Notification Engine (SaaS Alerting)
 * Handles state diffing, read-receipt delta detection, desktop alert formatting,
 * 14-day expiration filtering, and draft storage capping.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AtelierNotificationEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000; // 14 days in milliseconds
  const MAX_DRAFTS_LIMIT = 100;

  /**
   * Resolves the full URL for the batch status endpoint (/api/status).
   */
  function resolveStatusEndpoint(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return null;
    let base = rawUrl.trim();
    if (!base.startsWith('http://') && !base.startsWith('https://')) {
      base = 'https://' + base;
    }

    try {
      const u = new URL(base);
      if (u.pathname.endsWith('/track')) {
        u.pathname = u.pathname.replace(/\/track$/, '/status');
      } else if (u.pathname.endsWith('/api/track')) {
        u.pathname = u.pathname.replace(/\/api\/track$/, '/api/status');
      } else if (!u.pathname.endsWith('/status') && !u.pathname.endsWith('/api/status')) {
        u.pathname = u.pathname.replace(/\/?$/, '/api/status');
      }
      return u.origin + u.pathname;
    } catch {
      return null;
    }
  }

  /**
   * Filters drafts to include only those sent within the last 14 days.
   */
  function filterActiveDrafts(drafts, now = Date.now(), maxAgeMs = FOURTEEN_DAYS_MS) {
    if (!Array.isArray(drafts)) return [];

    return drafts.filter((draft) => {
      if (!draft) return false;
      const ts = typeof draft.timestamp === 'number'
        ? draft.timestamp
        : new Date(draft.timestamp || 0).getTime();
      if (!ts || isNaN(ts)) return false;
      return (now - ts) < maxAgeMs;
    });
  }

  /**
   * Formats the desktop notification message with recipient, subject, and geo-location details.
   */
  function formatNotificationMessage(draft, newOpens = 1) {
    const recipient = (draft && draft.recipient && String(draft.recipient).trim())
      ? String(draft.recipient).trim()
      : 'Recipient';
    const subject = (draft && draft.subject && String(draft.subject).trim())
      ? String(draft.subject).trim()
      : '(No Subject)';

    let msg = `${recipient} opened "${subject}"`;

    const loc = draft ? draft.lastLocation : null;
    const locParts = [];
    if (loc && loc.city && String(loc.city).trim()) {
      locParts.push(String(loc.city).trim());
    }
    if (loc && loc.country && String(loc.country).trim()) {
      locParts.push(String(loc.country).trim());
    }

    if (locParts.length > 0) {
      msg += ` from ${locParts.join(', ')}`;
    }

    return msg;
  }

  /**
   * Builds the chrome.notifications.create options payload.
   */
  function buildNotificationPayload(draft, newOpens = 1) {
    const trackingId = (draft && (draft.trackingId || draft.id)) || 'unknown';
    return {
      notificationId: `open_${trackingId}_${Date.now()}`,
      options: {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Email Opened',
        message: formatNotificationMessage(draft, newOpens),
        priority: 2
      }
    };
  }

  /**
   * Diffs stored drafts against live server status records.
   * Detects new read events by checking if serverRecord.openCount > (draft.lastNotifiedOpenCount || 0).
   * Updates draft state and returns notification payloads for all detected new opens.
   */
  function diffDraftOpenEvents(drafts, statusData) {
    const result = {
      hasUpdates: false,
      notifications: [],
      updatedDrafts: []
    };

    if (!Array.isArray(drafts) || !statusData || typeof statusData !== 'object') {
      return result;
    }

    for (const draft of drafts) {
      if (!draft) continue;
      const trackingId = draft.trackingId || draft.id;
      if (!trackingId) continue;

      const serverRecord = statusData[trackingId];
      if (!serverRecord) continue;

      const serverOpenCount = Number(serverRecord.openCount) || 0;
      const lastNotified = Number(draft.lastNotifiedOpenCount) || 0;

      if (serverOpenCount > lastNotified) {
        const newOpens = serverOpenCount - lastNotified;

        // Update draft state
        draft.lastNotifiedOpenCount = serverOpenCount;
        draft.openCount = serverOpenCount;
        draft.clickCount = Number(serverRecord.clickCount) || 0;
        if (serverRecord.lastLocation) {
          draft.lastLocation = {
            city: serverRecord.lastLocation.city || null,
            country: serverRecord.lastLocation.country || null
          };
        }

        const payload = buildNotificationPayload(draft, newOpens);
        result.notifications.push(payload);
        result.updatedDrafts.push(draft);
        result.hasUpdates = true;
      } else if (
        serverOpenCount !== draft.openCount ||
        (serverRecord.clickCount !== undefined && Number(serverRecord.clickCount) !== draft.clickCount)
      ) {
        // Synchronize counters even if no new open notification is triggered
        draft.openCount = serverOpenCount;
        draft.clickCount = Number(serverRecord.clickCount) || 0;
        if (serverRecord.lastLocation) {
          draft.lastLocation = {
            city: serverRecord.lastLocation.city || null,
            country: serverRecord.lastLocation.country || null
          };
        }
        result.updatedDrafts.push(draft);
        result.hasUpdates = true;
      }
    }

    return result;
  }

  /**
   * Synchronizes popup UI drafts with server status, aligning lastNotifiedOpenCount
   * to prevent duplicate notifications after viewing.
   */
  function syncDraftReadCounts(drafts, statusData) {
    if (!Array.isArray(drafts) || !statusData || typeof statusData !== 'object') {
      return false;
    }

    let updated = false;
    for (const draft of drafts) {
      if (!draft) continue;
      const trackingId = draft.trackingId || draft.id;
      if (!trackingId) continue;

      const serverRecord = statusData[trackingId];
      if (!serverRecord) continue;

      const serverOpenCount = Number(serverRecord.openCount) || 0;
      draft.openCount = serverOpenCount;
      draft.lastNotifiedOpenCount = Math.max(Number(draft.lastNotifiedOpenCount) || 0, serverOpenCount);
      draft.clickCount = Number(serverRecord.clickCount) || 0;
      if (serverRecord.lastLocation) {
        draft.lastLocation = {
          city: serverRecord.lastLocation.city || null,
          country: serverRecord.lastLocation.country || null
        };
      }
      updated = true;
    }

    return updated;
  }

  /**
   * Caps local draft storage array to the most recent items.
   */
  function capDraftsList(drafts, maxLimit = MAX_DRAFTS_LIMIT) {
    if (!Array.isArray(drafts)) return [];
    return drafts.slice(0, maxLimit);
  }

  return {
    FOURTEEN_DAYS_MS,
    MAX_DRAFTS_LIMIT,
    resolveStatusEndpoint,
    filterActiveDrafts,
    formatNotificationMessage,
    buildNotificationPayload,
    diffDraftOpenEvents,
    syncDraftReadCounts,
    capDraftsList
  };
}));
