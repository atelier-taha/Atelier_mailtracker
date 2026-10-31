/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * api/lib/storage.js
 * 
 * Lightweight Redis / Vercel KV REST Storage Layer with automatic in-memory fallback.
 * Zero external runtime dependencies.
 * 
 * Key format: mailtracker:event:${trackingId}
 * Retention: 90 days (7,776,000 seconds)
 */

'use strict';

const TTL_SECONDS = 7776000; // 90 days in seconds
const EVENT_HISTORY_CAP = 20;

// Internal in-memory fallback store for local development / unit tests / resiliency
const inMemoryStore = new Map();

function isRemoteKvConfigured() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return Boolean(url && token);
}

async function executeRemoteKvCommand(commandArray) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) return null;

  const endpoint = url.endsWith('/') ? url : `${url}/`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(commandArray)
  });

  if (!response.ok) {
    throw new Error(`KV REST HTTP ${response.status}: ${response.statusText}`);
  }

  const json = await response.json();
  return json.result;
}

/**
 * Retrieves the full tracking record for a given trackingId.
 * Returns null if not found.
 */
async function getTrackingRecord(trackingId) {
  if (!trackingId || typeof trackingId !== 'string') return null;

  const key = `mailtracker:event:${trackingId}`;

  if (isRemoteKvConfigured()) {
    try {
      const result = await executeRemoteKvCommand(['GET', key]);
      if (!result) return null;
      return typeof result === 'string' ? JSON.parse(result) : result;
    } catch (err) {
      console.warn(`[MailTracker Storage] Remote KV GET failed for ${trackingId}, falling back to memory:`, err.message);
    }
  }

  return inMemoryStore.has(key) ? JSON.parse(JSON.stringify(inMemoryStore.get(key))) : null;
}

/**
 * Saves a tracking record to Upstash/KV or in-memory fallback.
 */
async function saveTrackingRecord(trackingId, record) {
  const key = `mailtracker:event:${trackingId}`;
  const serialized = JSON.stringify(record);

  // Always update in-memory mirror
  inMemoryStore.set(key, JSON.parse(serialized));

  if (isRemoteKvConfigured()) {
    try {
      await executeRemoteKvCommand(['SET', key, serialized, 'EX', TTL_SECONDS]);
    } catch (err) {
      console.warn(`[MailTracker Storage] Remote KV SET failed for ${trackingId}:`, err.message);
    }
  }

  return record;
}

/**
 * Records an email open event for trackingId.
 */
async function recordOpenEvent(trackingId, metadata = {}) {
  if (!trackingId || trackingId === 'unspecified_id') return null;

  const now = Date.now();
  let record = await getTrackingRecord(trackingId);

  if (!record) {
    record = {
      trackingId,
      createdAt: now,
      openCount: 0,
      clickCount: 0,
      firstOpenedAt: null,
      lastOpenedAt: null,
      lastLocation: {
        city: null,
        country: null,
        region: null
      },
      events: []
    };
  }

  record.openCount = (record.openCount || 0) + 1;
  if (!record.firstOpenedAt) {
    record.firstOpenedAt = now;
  }
  record.lastOpenedAt = now;

  if (metadata.city !== undefined || metadata.country !== undefined || metadata.region !== undefined) {
    record.lastLocation = {
      city: metadata.city || record.lastLocation?.city || null,
      country: metadata.country || record.lastLocation?.country || null,
      region: metadata.region || record.lastLocation?.region || null
    };
  }

  const openEvent = {
    type: 'open',
    timestamp: now
  };
  if (metadata.city) openEvent.city = metadata.city;
  if (metadata.country) openEvent.country = metadata.country;
  if (metadata.userAgent) openEvent.userAgent = metadata.userAgent;

  record.events = [...(record.events || []), openEvent].slice(-EVENT_HISTORY_CAP);

  await saveTrackingRecord(trackingId, record);
  return record;
}

/**
 * Records a link click event for trackingId.
 */
async function recordClickEvent(trackingId, targetUrl, metadata = {}) {
  if (!trackingId || trackingId === 'unspecified_id') return null;

  const now = Date.now();
  let record = await getTrackingRecord(trackingId);

  if (!record) {
    record = {
      trackingId,
      createdAt: now,
      openCount: 0,
      clickCount: 0,
      firstOpenedAt: null,
      lastOpenedAt: null,
      lastLocation: {
        city: null,
        country: null,
        region: null
      },
      events: []
    };
  }

  record.clickCount = (record.clickCount || 0) + 1;

  if (metadata.city !== undefined || metadata.country !== undefined || metadata.region !== undefined) {
    record.lastLocation = {
      city: metadata.city || record.lastLocation?.city || null,
      country: metadata.country || record.lastLocation?.country || null,
      region: metadata.region || record.lastLocation?.region || null
    };
  }

  const clickEvent = {
    type: 'click',
    timestamp: now,
    targetUrl: targetUrl || ''
  };
  if (metadata.city) clickEvent.city = metadata.city;
  if (metadata.country) clickEvent.country = metadata.country;
  if (metadata.userAgent) clickEvent.userAgent = metadata.userAgent;

  record.events = [...(record.events || []), clickEvent].slice(-EVENT_HISTORY_CAP);

  await saveTrackingRecord(trackingId, record);
  return record;
}

/**
 * Batch retrieves status summaries for multiple tracking IDs.
 */
async function getMultipleRecords(trackingIds = []) {
  const result = {};

  for (const id of trackingIds) {
    if (!id || typeof id !== 'string') continue;
    const cleanId = id.trim();
    if (!cleanId) continue;

    const record = await getTrackingRecord(cleanId);
    if (record) {
      result[cleanId] = {
        openCount: record.openCount || 0,
        clickCount: record.clickCount || 0,
        firstOpenedAt: record.firstOpenedAt || null,
        lastOpenedAt: record.lastOpenedAt || null,
        lastLocation: record.lastLocation || { city: null, country: null, region: null }
      };
    } else {
      result[cleanId] = {
        openCount: 0,
        clickCount: 0,
        firstOpenedAt: null,
        lastOpenedAt: null,
        lastLocation: { city: null, country: null, region: null }
      };
    }
  }

  return result;
}

/**
 * Resets in-memory storage (useful for unit tests).
 */
function _resetInMemoryStore() {
  inMemoryStore.clear();
}

module.exports = {
  TTL_SECONDS,
  EVENT_HISTORY_CAP,
  getTrackingRecord,
  saveTrackingRecord,
  recordOpenEvent,
  recordClickEvent,
  getMultipleRecords,
  _resetInMemoryStore
};
