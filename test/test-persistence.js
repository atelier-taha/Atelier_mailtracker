/**
 * Automated Unit Tests for Event Persistence & Status Analytics
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * 
 * Tests:
 * 1. Mock Storage Engine: record initialization, open/click counts, capping at 20, TTL.
 * 2. Status Endpoint Resolution (/api/status): single, batch, empty, error handling.
 * 3. End-to-End Tracking Lifecycle: track open -> click -> status verification.
 */

const assert = require('assert');
const storage = require('../api/lib/storage.js');
const trackHandler = require('../api/track.js');
const clickHandler = require('../api/click.js');
const statusHandler = require('../api/status.js');

function createMockReq({ query = {}, headers = {}, method = 'GET' }) {
  return {
    query,
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestClient/1.0',
      'x-forwarded-for': '203.0.113.195',
      'referer': 'https://mail.google.com/',
      ...headers
    },
    method,
    socket: { remoteAddress: '127.0.0.1' }
  };
}

function createMockRes() {
  const headers = {};
  let statusCode = 200;
  let responseData = null;

  const res = {
    setHeader(key, val) {
      headers[key.toLowerCase()] = val;
    },
    getHeader(key) {
      return headers[key.toLowerCase()];
    },
    writeHead(code, headHeaders = {}) {
      statusCode = code;
      Object.keys(headHeaders).forEach((k) => {
        headers[k.toLowerCase()] = headHeaders[k];
      });
      return this;
    },
    status(code) {
      statusCode = code;
      return this;
    },
    json(data) {
      responseData = data;
      return this;
    },
    send(data) {
      responseData = data;
      return this;
    },
    end(data) {
      if (data !== undefined && responseData === null) {
        responseData = data;
      }
      return this;
    },
    _getHeaders: () => headers,
    _getStatusCode: () => statusCode,
    _getData: () => responseData
  };

  return res;
}

async function runPersistenceTests() {
  console.log('=== Starting Atelier Persistence & Status Test Suite ===\n');

  // Reset in-memory store before running tests
  storage._resetInMemoryStore();

  // Test 1: Storage Layer Operations
  {
    console.log('Test 1: Storage Layer - Initialization, Increments & Event History Capping...');

    const testId = 'test_store_init_01';

    // 1. Initial Open
    const rec1 = await storage.recordOpenEvent(testId, {
      city: 'Berlin',
      country: 'DE',
      region: 'BE',
      userAgent: 'Mozilla/5.0 (Windows) Thunderbird/115.0'
    });

    assert.strictEqual(rec1.openCount, 1, 'First open should set openCount to 1');
    assert.strictEqual(rec1.clickCount, 0, 'Click count should be 0');
    assert.ok(rec1.firstOpenedAt, 'firstOpenedAt should be populated');
    assert.strictEqual(rec1.firstOpenedAt, rec1.lastOpenedAt, 'First and last opened timestamps should match initially');
    assert.strictEqual(rec1.lastLocation.city, 'Berlin');
    assert.strictEqual(rec1.lastLocation.country, 'DE');
    assert.strictEqual(rec1.events.length, 1);
    assert.strictEqual(rec1.events[0].type, 'open');

    // 2. Second Open from different location
    const rec2 = await storage.recordOpenEvent(testId, {
      city: 'Munich',
      country: 'DE'
    });
    assert.strictEqual(rec2.openCount, 2, 'Second open should increment openCount to 2');
    assert.strictEqual(rec2.lastLocation.city, 'Munich');
    assert.strictEqual(rec2.events.length, 2);

    // 3. Click Event
    const rec3 = await storage.recordClickEvent(testId, 'https://example.com/spec', {
      city: 'Munich',
      country: 'DE'
    });
    assert.strictEqual(rec3.clickCount, 1, 'Click should increment clickCount to 1');
    assert.strictEqual(rec3.events.length, 3);
    assert.strictEqual(rec3.events[2].type, 'click');
    assert.strictEqual(rec3.events[2].targetUrl, 'https://example.com/spec');

    // 4. Verify Event History Capping at 20 events
    for (let i = 0; i < 25; i++) {
      await storage.recordOpenEvent(testId, { city: `City_${i}` });
    }
    const cappedRecord = await storage.getTrackingRecord(testId);
    assert.strictEqual(cappedRecord.openCount, 27);
    assert.strictEqual(cappedRecord.events.length, storage.EVENT_HISTORY_CAP, 'Events array should be capped at 20 items');
    assert.strictEqual(storage.TTL_SECONDS, 7776000, 'TTL constant should equal 90 days');

    console.log('✓ Test 1 Passed: Storage lifecycle, event capping, and metadata tracking verified.\n');
  }

  // Test 2: Status Endpoint Resolution (/api/status)
  {
    console.log('Test 2: Status Endpoint (/api/status) Query Handling...');

    // Non-existent ID returns zero counts
    const reqNonExistent = createMockReq({ query: { id: 'non_existent_trk_999' } });
    const resNonExistent = createMockRes();
    await statusHandler(reqNonExistent, resNonExistent);

    assert.strictEqual(resNonExistent._getStatusCode(), 200);
    const data1 = resNonExistent._getData();
    assert.strictEqual(data1.success, true);
    assert.deepStrictEqual(data1.data['non_existent_trk_999'], {
      openCount: 0,
      clickCount: 0,
      firstOpenedAt: null,
      lastOpenedAt: null,
      lastLocation: { city: null, country: null, region: null }
    });

    // Batch query with multiple IDs
    const reqBatch = createMockReq({ query: { ids: 'test_store_init_01, nonexistent_02' } });
    const resBatch = createMockRes();
    await statusHandler(reqBatch, resBatch);

    assert.strictEqual(resBatch._getStatusCode(), 200);
    const batchData = resBatch._getData();
    assert.strictEqual(batchData.success, true);
    assert.strictEqual(batchData.data['test_store_init_01'].openCount, 27);
    assert.strictEqual(batchData.data['test_store_init_01'].clickCount, 1);
    assert.strictEqual(batchData.data['nonexistent_02'].openCount, 0);

    // Missing query parameter
    const reqEmpty = createMockReq({ query: {} });
    const resEmpty = createMockRes();
    await statusHandler(reqEmpty, resEmpty);
    assert.strictEqual(resEmpty._getStatusCode(), 400);

    // Preflight OPTIONS request
    const reqOptions = createMockReq({ method: 'OPTIONS' });
    const resOptions = createMockRes();
    await statusHandler(reqOptions, resOptions);
    assert.strictEqual(resOptions._getStatusCode(), 200);

    console.log('✓ Test 2 Passed: Status endpoint single and batch resolution verified.\n');
  }

  // Test 3: End-to-End Tracking Lifecycle Simulation
  {
    console.log('Test 3: End-to-End Simulation (track -> click -> status)...');

    const liveId = 'tr_live_simulation_' + Date.now().toString(36);

    // 1. Initial State: Status should show 0 opens
    const reqPre = createMockReq({ query: { id: liveId } });
    const resPre = createMockRes();
    await statusHandler(reqPre, resPre);
    assert.strictEqual(resPre._getData().data[liveId].openCount, 0);

    // 2. Recipient opens email: Hit /api/track
    const reqTrack = createMockReq({
      query: { id: liveId },
      headers: {
        'x-vercel-ip-city': 'San%20Francisco',
        'x-vercel-ip-country': 'US',
        'x-vercel-ip-country-region': 'CA',
        'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'
      }
    });
    const resTrack = createMockRes();
    await trackHandler(reqTrack, resTrack);
    assert.strictEqual(resTrack._getStatusCode(), 200);
    assert.strictEqual(resTrack.getHeader('content-type'), 'image/gif');

    // 3. Recipient clicks link: Hit /api/click
    const reqClick = createMockReq({
      query: { id: liveId, url: 'https://atelierforge.tools/demo' },
      headers: {
        'x-vercel-ip-city': 'San%20Francisco',
        'x-vercel-ip-country': 'US'
      }
    });
    const resClick = createMockRes();
    await clickHandler(reqClick, resClick);
    assert.strictEqual(resClick._getStatusCode(), 302);
    assert.strictEqual(resClick.getHeader('location'), 'https://atelierforge.tools/demo');

    // 4. Query /api/status to verify persistent receipt
    const reqPost = createMockReq({ query: { id: liveId } });
    const resPost = createMockRes();
    await statusHandler(reqPost, resPost);

    const postData = resPost._getData().data[liveId];
    assert.strictEqual(postData.openCount, 1, 'Should record 1 open event');
    assert.strictEqual(postData.clickCount, 1, 'Should record 1 click event');
    assert.strictEqual(postData.lastLocation.city, 'San Francisco');
    assert.strictEqual(postData.lastLocation.country, 'US');
    assert.strictEqual(postData.lastLocation.region, 'CA');
    assert.ok(postData.firstOpenedAt > 0);
    assert.ok(postData.lastOpenedAt >= postData.firstOpenedAt);

    console.log('✓ Test 3 Passed: End-to-end open, click, and status parity verified.\n');
  }

  console.log('🎉 All Persistence & Status tests passed with 100% success!\n');
}

if (require.main === module) {
  runPersistenceTests().catch((err) => {
    console.error('Persistence test failed:', err);
    process.exit(1);
  });
}

module.exports = runPersistenceTests;
