/**
 * Automated Unit Tests for Compose Link Tracking & Security Hardening
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * 
 * Tests:
 * 1. Link Rewriting Logic & Exclusions (mailto:, #anchors, already-wrapped, javascript:).
 * 2. Open-Redirect Defenses (Scheme enforcement, CRLF injection, protocol-relative rejection).
 * 3. HMAC Link Signature Verification & Tamper Detection.
 * 4. SSRF Webhook Protection (Private IP ranges, loopback, cloud metadata).
 */

const assert = require('assert');
const security = require('../api/lib/security.js');
const clickHandler = require('../api/click.js');
const trackHandler = require('../api/track.js');

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

  return {
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
}

/**
 * Pure model of the DOM link rewriting algorithm implemented in extension/content.js
 */
function rewriteLinksInHtml(html, trackingId, clickEndpoint) {
  return html.replace(/<a\s+([^>]*?)href=(["'])(.*?)\2([^>]*)>/gi, (match, before, quote, href, after) => {
    const trimmedHref = href.trim();

    // 1. Skip local anchors
    if (!trimmedHref || trimmedHref.startsWith('#')) return match;

    // 2. Skip communication schemes
    if (/^(mailto|tel|sms):/i.test(trimmedHref)) return match;

    // 3. Skip already wrapped tracking links
    if (trimmedHref.includes('/api/click') || match.includes('data-mailtracker-wrapped')) return match;

    // 4. Skip script / insecure pseudo-protocols
    if (/^(javascript|data|vbscript|file):/i.test(trimmedHref)) return match;

    const delimiter = clickEndpoint.includes('?') ? '&' : '?';
    const wrappedUrl = `${clickEndpoint}${delimiter}id=${encodeURIComponent(trackingId)}&url=${encodeURIComponent(trimmedHref)}`;

    return `<a ${before}href=${quote}${wrappedUrl}${quote} data-mailtracker-wrapped="true"${after}>`;
  });
}

async function runComposeLinkSecurityTests() {
  console.log('=== Starting Atelier Compose Link & Security Test Suite ===\n');

  // Test 1: Link Rewriting & Exclusions
  {
    console.log('Test 1: Compose Link Rewriting Logic & Exclusions...');

    const clickEndpoint = 'https://tracker.atelierforge.tools/api/click';
    const trkId = 'trk_sample_888';

    const inputHtml = [
      '<p>Here is the <a href="https://example.com/proposal">proposal</a>.</p>',
      '<p>Secondary link: <a href="http://docs.partner.org/spec?v=2&lang=en">Documentation</a></p>',
      '<p>Jump to <a href="#details">Details Section</a></p>',
      '<p>Contact <a href="mailto:support@company.com">Support</a></p>',
      '<p>Phone: <a href="tel:+1234567890">Call us</a></p>',
      '<p>Malicious: <a href="javascript:alert(1)">Click here</a></p>',
      `<p>Already wrapped: <a href="${clickEndpoint}?id=trk_prev&url=https%3A%2F%2Fother.com">Old</a></p>`
    ].join('\n');

    const outputHtml = rewriteLinksInHtml(inputHtml, trkId, clickEndpoint);

    // 1. External HTTPS and HTTP links should be wrapped
    assert.ok(
      outputHtml.includes(`href="https://tracker.atelierforge.tools/api/click?id=trk_sample_888&url=https%3A%2F%2Fexample.com%2Fproposal"`),
      'HTTPS link should be rewritten with click tracker'
    );
    assert.ok(
      outputHtml.includes(`href="https://tracker.atelierforge.tools/api/click?id=trk_sample_888&url=http%3A%2F%2Fdocs.partner.org%2Fspec%3Fv%3D2%26lang%3Den"`),
      'HTTP link should be rewritten with click tracker'
    );

    // 2. Anchors, mailto, tel, javascript must be preserved untouched
    assert.ok(outputHtml.includes('href="#details"'), 'Local anchor #details should NOT be rewritten');
    assert.ok(outputHtml.includes('href="mailto:support@company.com"'), 'mailto: should NOT be rewritten');
    assert.ok(outputHtml.includes('href="tel:+1234567890"'), 'tel: should NOT be rewritten');
    assert.ok(outputHtml.includes('href="javascript:alert(1)"'), 'javascript: should NOT be rewritten');

    // 3. Already wrapped links should NOT be double wrapped
    const doubleWrappedCount = (outputHtml.match(/api\/click/g) || []).length;
    assert.strictEqual(doubleWrappedCount, 3, 'Should contain exactly 3 click URLs (2 newly wrapped + 1 preexisting)');

    console.log('✓ Test 1 Passed: Selective hyperlink rewriting and protocol preservation verified.\n');
  }

  // Test 2: Open-Redirect & Header Splitting Defenses in /api/click
  {
    console.log('Test 2: Open-Redirect & HTTP Header Splitting Defenses in /api/click...');

    // 1. Valid destination redirection
    const reqValid = createMockReq({
      query: { id: 'tr_sec_1', url: 'https://github.com/trending' }
    });
    const resValid = createMockRes();
    await clickHandler(reqValid, resValid);
    assert.strictEqual(resValid._getStatusCode(), 302);
    assert.strictEqual(resValid.getHeader('location'), 'https://github.com/trending');

    // 2. Reject javascript: scheme
    const reqJs = createMockReq({
      query: { id: 'tr_sec_2', url: 'javascript:alert(document.cookie)' }
    });
    const resJs = createMockRes();
    await clickHandler(reqJs, resJs);
    assert.strictEqual(resJs._getStatusCode(), 400);

    // 3. Reject data: scheme
    const reqData = createMockReq({
      query: { id: 'tr_sec_3', url: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' }
    });
    const resData = createMockRes();
    await clickHandler(reqData, resData);
    assert.strictEqual(resData._getStatusCode(), 400);

    // 4. Reject protocol-relative URLs (//evil.com)
    const reqProtoRel = createMockReq({
      query: { id: 'tr_sec_4', url: '//attacker.com/phish' }
    });
    const resProtoRel = createMockRes();
    await clickHandler(reqProtoRel, resProtoRel);
    assert.strictEqual(resProtoRel._getStatusCode(), 400);

    // 5. Reject CRLF / HTTP Response Splitting attempts
    const reqSplitting = createMockReq({
      query: { id: 'tr_sec_5', url: 'https://example.com/\r\nSet-Cookie: sessionId=attacker_val' }
    });
    const resSplitting = createMockRes();
    await clickHandler(reqSplitting, resSplitting);
    assert.strictEqual(resSplitting._getStatusCode(), 400);

    console.log('✓ Test 2 Passed: Open-redirect schemes, protocol-relative bypasses, and CRLF injection blocked.\n');
  }

  // Test 3: HMAC URL Integrity Signing
  {
    console.log('Test 3: HMAC Link Integrity Signing & Tamper Verification...');

    const secretKey = 'cyber_secret_key_ultra_secure_99';
    process.env.TRACKING_SECRET = secretKey;

    try {
      const trkId = 'trk_sig_100';
      const target = 'https://enterprise.internal.portal/dashboard';

      // 1. Generate legitimate signature
      const validSig = security.generateLinkSignature(trkId, target, secretKey);
      assert.ok(validSig, 'Signature should be generated');

      // 2. Valid signature succeeds
      const reqValidSig = createMockReq({
        query: { id: trkId, url: target, sig: validSig }
      });
      const resValidSig = createMockRes();
      await clickHandler(reqValidSig, resValidSig);
      assert.strictEqual(resValidSig._getStatusCode(), 302);
      assert.strictEqual(resValidSig.getHeader('location'), target);

      // 3. Tampered destination URL fails
      const reqTampered = createMockReq({
        query: { id: trkId, url: 'https://evil-phishing-site.xyz/login', sig: validSig }
      });
      const resTampered = createMockRes();
      await clickHandler(reqTampered, resTampered);
      assert.strictEqual(resTampered._getStatusCode(), 400);

      // 4. Missing signature when secret is enforced fails
      const reqMissingSig = createMockReq({
        query: { id: trkId, url: target }
      });
      const resMissingSig = createMockRes();
      await clickHandler(reqMissingSig, resMissingSig);
      assert.strictEqual(resMissingSig._getStatusCode(), 400);
    } finally {
      delete process.env.TRACKING_SECRET;
    }

    console.log('✓ Test 3 Passed: HMAC signing, verification, and tamper rejection confirmed.\n');
  }

  // Test 4: SSRF Filtering & Webhook Protection
  {
    console.log('Test 4: SSRF Webhook Protection...');

    // 1. Block Cloud Metadata (169.254.169.254)
    assert.strictEqual(security.isSafeWebhookUrl('http://169.254.169.254/latest/meta-data/'), false);

    // 2. Block Loopback / Localhost (127.0.0.1, localhost, [::1])
    assert.strictEqual(security.isSafeWebhookUrl('http://localhost:8080/webhook'), false);
    assert.strictEqual(security.isSafeWebhookUrl('http://127.0.0.1:9000/webhook'), false);
    assert.strictEqual(security.isSafeWebhookUrl('http://[::1]:8080/'), false);

    // 3. Block RFC 1918 Private Ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    assert.strictEqual(security.isSafeWebhookUrl('https://10.0.1.15/webhook'), false);
    assert.strictEqual(security.isSafeWebhookUrl('https://172.20.5.1/webhook'), false);
    assert.strictEqual(security.isSafeWebhookUrl('https://192.168.1.100/webhook'), false);

    // 4. Block Non-HTTPS Webhooks
    assert.strictEqual(security.isSafeWebhookUrl('http://discord.com/api/webhooks/123/abc'), false);

    // 5. Block Arbitrary Unauthorized Domains
    assert.strictEqual(security.isSafeWebhookUrl('https://attacker-controlled-server.com/sink'), false);

    // 6. Allow Valid Verified Webhook Providers
    assert.strictEqual(security.isSafeWebhookUrl('https://discord.com/api/webhooks/123456/token_abc'), true);
    assert.strictEqual(security.isSafeWebhookUrl('https://discordapp.com/api/webhooks/123456/token_abc'), true);
    assert.strictEqual(security.isSafeWebhookUrl('https://api.telegram.org/bot123456:ABC/sendMessage'), true);

    console.log('✓ Test 4 Passed: SSRF mitigation verified for cloud metadata, loopback, private CIDRs, and unauthorized hosts.\n');
  }

  console.log('🎉 All Compose Link & Security tests passed with 100% success!\n');
}

if (require.main === module) {
  runComposeLinkSecurityTests().catch((err) => {
    console.error('Compose link test failed:', err);
    process.exit(1);
  });
}

module.exports = runComposeLinkSecurityTests;
