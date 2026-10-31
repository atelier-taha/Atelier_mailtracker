/**
 * Automated Unit Tests for Native Desktop Notifications Engine (SaaS Alerting)
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * 
 * Tests:
 * 1. Delta Detection Logic (openCount diffing against lastNotifiedOpenCount, multiple opens, no duplicate alerts).
 * 2. 14-Day Expiration Cutoff (excluding stale drafts from batch polling).
 * 3. Notification Payload Builder (formatting recipient, subject, city/country location, fallbacks).
 * 4. Draft Capping (limiting storage array to 100 entries).
 * 5. Status Endpoint URL Resolver (normalizing user input to /api/status).
 * 6. Popup UI Read Count Synchronization (aligning lastNotifiedOpenCount).
 */

const assert = require('assert');
const notificationEngine = require('../extension/lib/notification-engine.js');

async function runNotificationTests() {
  console.log('=== Starting Atelier Native Notifications & SaaS Alerting Test Suite ===\n');

  // Test 1: Delta Detection Logic
  {
    console.log('Test 1: Delta Detection & Baseline State Updates...');

    const draft = {
      trackingId: 'tr_notif_001',
      recipient: 'investor@fund.vc',
      subject: 'Series A Pitch Deck',
      timestamp: Date.now(),
      openCount: 0,
      clickCount: 0,
      lastNotifiedOpenCount: 0,
      lastLocation: { city: null, country: null }
    };

    const draftsList = [draft];

    // Scenario A: First open event detected (server openCount = 1)
    const serverData1 = {
      tr_notif_001: {
        openCount: 1,
        clickCount: 0,
        lastLocation: { city: 'New York', country: 'US' }
      }
    };

    const result1 = notificationEngine.diffDraftOpenEvents(draftsList, serverData1);
    assert.strictEqual(result1.hasUpdates, true, 'Should mark hasUpdates as true');
    assert.strictEqual(result1.notifications.length, 1, 'Should generate exactly 1 notification');
    assert.strictEqual(result1.notifications[0].options.title, 'Email Opened');
    assert.strictEqual(
      result1.notifications[0].options.message,
      'investor@fund.vc opened "Series A Pitch Deck" from New York, US'
    );
    assert.strictEqual(draft.lastNotifiedOpenCount, 1, 'lastNotifiedOpenCount should update to 1');
    assert.strictEqual(draft.openCount, 1, 'openCount should update to 1');
    assert.strictEqual(draft.lastLocation.city, 'New York');
    assert.strictEqual(draft.lastLocation.country, 'US');

    // Scenario B: Subsequent check where openCount remains 1 (No duplicate notification)
    const result2 = notificationEngine.diffDraftOpenEvents(draftsList, serverData1);
    assert.strictEqual(result2.notifications.length, 0, 'Should NOT trigger notification when openCount has not increased');
    assert.strictEqual(draft.lastNotifiedOpenCount, 1, 'Baseline should remain 1');

    // Scenario C: Increment from 1 to 3 (Two new opens detected)
    const serverData3 = {
      tr_notif_001: {
        openCount: 3,
        clickCount: 1,
        lastLocation: { city: 'Boston', country: 'US' }
      }
    };

    const result3 = notificationEngine.diffDraftOpenEvents(draftsList, serverData3);
    assert.strictEqual(result3.hasUpdates, true);
    assert.strictEqual(result3.notifications.length, 1, 'Should trigger 1 notification for the batch jump');
    assert.strictEqual(draft.lastNotifiedOpenCount, 3, 'lastNotifiedOpenCount should update to 3');
    assert.strictEqual(draft.openCount, 3, 'openCount should update to 3');
    assert.strictEqual(draft.clickCount, 1, 'clickCount should update to 1');
    assert.strictEqual(draft.lastLocation.city, 'Boston');

    console.log('✓ Test 1 Passed: Delta detection, zero duplicate alerts, and baseline tracking verified.\n');
  }

  // Test 2: 14-Day Expiration Cutoff
  {
    console.log('Test 2: 14-Day Expiration Cutoff Filtering...');

    const now = Date.now();
    const oneDayAgo = now - (1 * 24 * 60 * 60 * 1000);
    const thirteenDaysAgo = now - (13 * 24 * 60 * 60 * 1000);
    const fifteenDaysAgo = now - (15 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);

    const testDrafts = [
      { trackingId: 'tr_fresh_1', timestamp: oneDayAgo },
      { trackingId: 'tr_fresh_13', timestamp: thirteenDaysAgo },
      { trackingId: 'tr_expired_15', timestamp: fifteenDaysAgo },
      { trackingId: 'tr_expired_30', timestamp: thirtyDaysAgo }
    ];

    const activeDrafts = notificationEngine.filterActiveDrafts(testDrafts, now);
    assert.strictEqual(activeDrafts.length, 2, 'Should only include drafts within the 14-day window');
    assert.strictEqual(activeDrafts[0].trackingId, 'tr_fresh_1');
    assert.strictEqual(activeDrafts[1].trackingId, 'tr_fresh_13');

    // Verify cutoff constant equals 14 days in milliseconds
    assert.strictEqual(notificationEngine.FOURTEEN_DAYS_MS, 14 * 24 * 60 * 60 * 1000);

    console.log('✓ Test 2 Passed: 14-day cutoff cleanly excludes expired drafts from polling.\n');
  }

  // Test 3: Notification Payload Builder
  {
    console.log('Test 3: Notification Payload Builder & Fallback Formatting...');

    // Scenario A: Full location (city + country)
    const draftFull = {
      trackingId: 'tr_fmt_01',
      recipient: 'ceo@partner.org',
      subject: 'Partnership Agreement',
      lastLocation: { city: 'London', country: 'GB' }
    };
    const payloadFull = notificationEngine.buildNotificationPayload(draftFull, 1);
    assert.strictEqual(payloadFull.options.title, 'Email Opened');
    assert.strictEqual(payloadFull.options.type, 'basic');
    assert.strictEqual(payloadFull.options.priority, 2);
    assert.strictEqual(payloadFull.options.iconUrl, 'icons/icon128.png');
    assert.strictEqual(payloadFull.options.message, 'ceo@partner.org opened "Partnership Agreement" from London, GB');
    assert.ok(payloadFull.notificationId.startsWith('open_tr_fmt_01_'));

    // Scenario B: Missing location (null/empty city and country)
    const draftNoLoc = {
      trackingId: 'tr_fmt_02',
      recipient: 'client@domain.com',
      subject: 'Invoice #1042',
      lastLocation: { city: null, country: null }
    };
    const payloadNoLoc = notificationEngine.buildNotificationPayload(draftNoLoc, 1);
    assert.strictEqual(payloadNoLoc.options.message, 'client@domain.com opened "Invoice #1042"');

    // Scenario C: City only
    const draftCityOnly = {
      trackingId: 'tr_fmt_03',
      recipient: 'user@domain.com',
      subject: 'Welcome',
      lastLocation: { city: 'Toronto', country: null }
    };
    const payloadCity = notificationEngine.buildNotificationPayload(draftCityOnly, 1);
    assert.strictEqual(payloadCity.options.message, 'user@domain.com opened "Welcome" from Toronto');

    // Scenario D: Missing recipient and subject (Fallbacks)
    const draftFallbacks = {
      trackingId: 'tr_fmt_04',
      recipient: '',
      subject: ''
    };
    const payloadFallbacks = notificationEngine.buildNotificationPayload(draftFallbacks, 1);
    assert.strictEqual(payloadFallbacks.options.message, 'Recipient opened "(No Subject)"');

    console.log('✓ Test 3 Passed: Payload formatting handles city, country, and empty fallbacks cleanly.\n');
  }

  // Test 4: Draft Capping
  {
    console.log('Test 4: Draft Storage Capping at 100 entries...');

    const longList = [];
    for (let i = 0; i < 150; i++) {
      longList.push({
        trackingId: `tr_cap_${i}`,
        recipient: `user${i}@example.com`,
        subject: `Email #${i}`,
        timestamp: Date.now() - (i * 1000)
      });
    }

    const capped = notificationEngine.capDraftsList(longList);
    assert.strictEqual(capped.length, 100, 'Array should be capped to 100 items');
    assert.strictEqual(capped[0].trackingId, 'tr_cap_0', 'Most recent draft should be preserved at index 0');
    assert.strictEqual(capped[99].trackingId, 'tr_cap_99', '100th draft should be preserved');
    assert.strictEqual(notificationEngine.MAX_DRAFTS_LIMIT, 100);

    console.log('✓ Test 4 Passed: Draft storage array capping at 100 confirmed.\n');
  }

  // Test 5: Status Endpoint URL Resolver
  {
    console.log('Test 5: Status Endpoint URL Resolution...');

    assert.strictEqual(
      notificationEngine.resolveStatusEndpoint('https://my-tracker.vercel.app/api/track'),
      'https://my-tracker.vercel.app/api/status'
    );
    assert.strictEqual(
      notificationEngine.resolveStatusEndpoint('https://my-tracker.vercel.app/track'),
      'https://my-tracker.vercel.app/status'
    );
    assert.strictEqual(
      notificationEngine.resolveStatusEndpoint('https://my-tracker.vercel.app'),
      'https://my-tracker.vercel.app/api/status'
    );
    assert.strictEqual(
      notificationEngine.resolveStatusEndpoint('my-tracker.vercel.app/'),
      'https://my-tracker.vercel.app/api/status'
    );
    assert.strictEqual(notificationEngine.resolveStatusEndpoint(''), null);
    assert.strictEqual(notificationEngine.resolveStatusEndpoint(null), null);

    console.log('✓ Test 5 Passed: Dynamic endpoint resolution verified across standard paths.\n');
  }

  // Test 6: Popup UI Synchronization
  {
    console.log('Test 6: Popup UI Read Count Synchronization...');

    const drafts = [
      {
        trackingId: 'tr_sync_1',
        openCount: 0,
        lastNotifiedOpenCount: 0
      }
    ];

    const statusData = {
      tr_sync_1: {
        openCount: 2,
        clickCount: 1,
        lastLocation: { city: 'Berlin', country: 'DE' }
      }
    };

    const synced = notificationEngine.syncDraftReadCounts(drafts, statusData);
    assert.strictEqual(synced, true);
    assert.strictEqual(drafts[0].openCount, 2);
    assert.strictEqual(drafts[0].lastNotifiedOpenCount, 2, 'lastNotifiedOpenCount aligned to prevent duplicate alert');
    assert.strictEqual(drafts[0].clickCount, 1);

    // After syncing, diffDraftOpenEvents should NOT trigger any notification
    const diffAfterSync = notificationEngine.diffDraftOpenEvents(drafts, statusData);
    assert.strictEqual(diffAfterSync.notifications.length, 0, 'No notification should fire after popup synchronization');

    console.log('✓ Test 6 Passed: Popup synchronization prevents duplicate alerts on subsequent alarm cycles.\n');
  }

  console.log('🎉 All Native Notification & SaaS Alerting tests passed with 100% success!\n');
}

if (require.main === module) {
  runNotificationTests().catch((err) => {
    console.error('Notification test failed:', err);
    process.exit(1);
  });
}

module.exports = runNotificationTests;
