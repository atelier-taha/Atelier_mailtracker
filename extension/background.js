/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/background.js
 * 
 * MV3 Service Worker:
 * Fetches raw email message headers via Gmail's authenticated endpoint (?view=om&th=...)
 * across session boundaries.
 */

/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/background.js
 * 
 * MV3 Service Worker:
 * 1. Fetches raw email message headers via Gmail's authenticated endpoint (?view=om&th=...)
 *    across session boundaries.
 * 2. Background polling service for desktop notifications of email read receipts.
 */

try {
  importScripts('lib/notification-engine.js');
} catch (err) {
  console.warn('[Atelier Background] Failed to importScripts notification-engine:', err);
}

const ALARM_NAME = 'CHECK_MAIL_OPENS';

/**
 * Ensures the polling alarm is scheduled with periodInMinutes: 1.
 */
function setupAlarm() {
  if (typeof chrome !== 'undefined' && chrome.alarms) {
    chrome.alarms.get(ALARM_NAME, (alarm) => {
      if (!alarm) {
        chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
      }
    });
  }
}

if (typeof chrome !== 'undefined' && chrome.runtime) {
  if (chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      setupAlarm();
    });
  }

  if (chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(() => {
      setupAlarm();
    });
  }
}

// Initial alarm registration when service worker initializes
setupAlarm();

/**
 * Checks server status for active tracked drafts, diffs open counts,
 * and triggers native desktop notifications for new open events.
 */
async function checkMailOpens() {
  const engine = (typeof self !== 'undefined' && self.AtelierNotificationEngine)
    ? self.AtelierNotificationEngine
    : (typeof AtelierNotificationEngine !== 'undefined' ? AtelierNotificationEngine : null);

  if (!engine) return;

  try {
    const local = await new Promise((resolve) => {
      chrome.storage.local.get(['tracked_drafts', 'api_base_url', 'backendUrl'], resolve);
    });
    const sync = await new Promise((resolve) => {
      chrome.storage.sync.get(['backendUrl', 'api_base_url'], resolve);
    });

    const rawUrl = local.api_base_url || local.backendUrl || sync.backendUrl || sync.api_base_url || '';
    const statusEndpoint = engine.resolveStatusEndpoint(rawUrl);
    if (!statusEndpoint) return;

    const allDrafts = local.tracked_drafts || [];
    if (!Array.isArray(allDrafts) || allDrafts.length === 0) return;

    const activeDrafts = engine.filterActiveDrafts(allDrafts);
    if (activeDrafts.length === 0) return;

    const ids = activeDrafts.map((d) => d.trackingId || d.id).filter(Boolean);
    if (ids.length === 0) return;

    const fetchUrl = `${statusEndpoint}?ids=${encodeURIComponent(ids.join(','))}`;
    const res = await fetch(fetchUrl, {
      method: 'GET',
      cache: 'no-store'
    });

    if (!res.ok) return;
    const json = await res.json();
    if (!json || !json.success || !json.data) return;

    const { hasUpdates, notifications } = engine.diffDraftOpenEvents(allDrafts, json.data);

    // Dispatch native desktop notifications
    for (const notif of notifications) {
      if (chrome.notifications && chrome.notifications.create) {
        chrome.notifications.create(notif.notificationId, notif.options);
      }
    }

    // Persist updated draft state back to chrome.storage.local
    if (hasUpdates) {
      await new Promise((resolve) => {
        chrome.storage.local.set({ tracked_drafts: allDrafts }, resolve);
      });
    }
  } catch (err) {
    console.warn('[Atelier Background] Polling error in checkMailOpens:', err.message);
  }
}

// Alarm Listener
if (typeof chrome !== 'undefined' && chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === ALARM_NAME) {
      await checkMailOpens();
    }
  });
}

// Notification Click Handler: Focuses Gmail tab or opens a new tab
if (typeof chrome !== 'undefined' && chrome.notifications && chrome.notifications.onClicked) {
  chrome.notifications.onClicked.addListener((notificationId) => {
    if (notificationId && notificationId.startsWith('open_')) {
      chrome.tabs.query({ url: 'https://mail.google.com/*' }, (tabs) => {
        if (tabs && tabs.length > 0) {
          const targetTab = tabs[0];
          chrome.tabs.update(targetTab.id, { active: true }, () => {
            if (targetTab.windowId) {
              chrome.windows.update(targetTab.windowId, { focused: true });
            }
          });
        } else {
          chrome.tabs.create({ url: 'https://mail.google.com/' });
        }
      });
    }
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'FETCH_RAW_HEADERS' || request.action === 'FETCH_GMAIL_RAW_MESSAGE') {
    const rawMessageId = request.messageId;
    const rawAccountIndex = request.accountIndex;

    if (!rawMessageId || typeof rawMessageId !== 'string') {
      sendResponse({ success: false, error: 'Missing or invalid messageId' });
      return true;
    }

    // Sanitize accountIndex: only digits, default '0'
    const sanitizedIndex = String(rawAccountIndex || '0').replace(/\D/g, '') || '0';

    // Validate messageId format: strict hexadecimal / alphanumeric check
    const trimmedId = rawMessageId.trim();
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedId)) {
      sendResponse({ success: false, error: `Invalid messageId format: "${rawMessageId}"` });
      return true;
    }

    // Gmail's raw message viewer endpoint with dynamic account partition
    const rawUrl = `https://mail.google.com/mail/u/${sanitizedIndex}/?view=om&th=${encodeURIComponent(trimmedId)}`;

    fetch(rawUrl, {
      method: 'GET',
      credentials: 'include',
      cache: 'no-store'
    })
      .then(async (response) => {
        if (!response.ok) {
          sendResponse({
            success: false,
            error: `HTTP ${response.status} ${response.statusText}`
          });
          return;
        }
        const text = await response.text();
        
        // Basic check if response looks like an RFC 5322 header
        if (text.includes('Received:') || text.includes('Delivered-To:') || text.includes('From:')) {
          sendResponse({ success: true, rawHeaders: text });
        } else {
          sendResponse({
            success: false,
            error: 'Endpoint returned non-header content (session boundary or auth challenge)'
          });
        }
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message || 'Fetch request failed' });
      });

    return true; // Keep message channel open for async response
  }
});
