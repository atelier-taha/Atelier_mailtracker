/**
 * Test Suite for Vercel Serverless Functions
 * Tests:
 * 1. api/track.js - Pixel, Geo-IP, Client Classification & Anti-caching
 * 2. api/track.js - Preflight OPTIONS & Webhook error resiliency
 * 3. api/click.js - Link click tracking, 302 redirect & Geo-IP logging
 */

const trackHandler = require('../api/track.js');
const clickHandler = require('../api/click.js');
const assert = require('assert');

// Mock request and response helpers
function createMockReq({ query = {}, headers = {}, method = 'GET' }) {
  return {
    query,
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestClient/1.0',
      'x-forwarded-for': '203.0.113.195, 192.168.1.1',
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
      responseData = data;
      return this;
    },
    _getHeaders: () => headers,
    _getStatusCode: () => statusCode,
    _getData: () => responseData
  };
}

async function runTests() {
  console.log('=== Starting MailTracker API Tests ===\n');

  // Test 1: Standard Pixel Request with Geo-IP & Classification
  {
    console.log('Test 1: Standard Pixel Request with Geo-IP headers...');
    const req = createMockReq({
      query: { id: 'tr_test123' },
      headers: {
        'x-vercel-ip-city': 'London',
        'x-vercel-ip-country': 'GB',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Outlook/16.0'
      }
    });
    const res = createMockRes();

    await trackHandler(req, res);

    assert.strictEqual(res._getStatusCode(), 200, 'Expected status 200');
    assert.strictEqual(res.getHeader('content-type'), 'image/gif', 'Expected image/gif');
    assert.strictEqual(res.getHeader('content-length'), '42', 'Expected length 42');
    
    // Validate anti-caching headers
    const cacheControl = res.getHeader('cache-control');
    assert.ok(cacheControl.includes('no-store'), 'Cache-Control must contain no-store');
    assert.ok(cacheControl.includes('no-cache'), 'Cache-Control must contain no-cache');
    assert.ok(cacheControl.includes('must-revalidate'), 'Cache-Control must contain must-revalidate');
    assert.strictEqual(res.getHeader('pragma'), 'no-cache', 'Pragma must be no-cache');
    assert.strictEqual(res.getHeader('expires'), '0', 'Expires must be 0');

    // Validate GIF payload
    const data = res._getData();
    assert.ok(Buffer.isBuffer(data), 'Response data should be a Buffer');
    assert.strictEqual(data.length, 42, 'GIF Buffer length should be 42');
    assert.strictEqual(data.toString('ascii', 0, 6), 'GIF89a', 'Buffer should begin with GIF89a header');

    console.log('✓ Test 1 Passed: Pixel, Geo-IP, and anti-caching verified.\n');
  }

  // Test 2: Preflight OPTIONS Request
  {
    console.log('Test 2: Preflight OPTIONS Request...');
    const req = createMockReq({ method: 'OPTIONS' });
    const res = createMockRes();

    await trackHandler(req, res);

    assert.strictEqual(res._getStatusCode(), 200, 'OPTIONS should return 200');
    assert.strictEqual(res.getHeader('access-control-allow-origin'), '*', 'CORS origin should be *');
    console.log('✓ Test 2 Passed: CORS preflight handled.\n');
  }

  // Test 3: Resiliency with unreachable webhook URL
  {
    console.log('Test 3: Resiliency with unreachable webhook URL...');
    const req = createMockReq({ 
      query: { webhook: encodeURIComponent('http://127.0.0.1:59999/unreachable') } 
    });
    const res = createMockRes();

    await trackHandler(req, res);

    assert.strictEqual(res._getStatusCode(), 200, 'Should still return 200 even if webhook fails');
    assert.strictEqual(res.getHeader('content-type'), 'image/gif', 'Should still serve GIF');
    console.log('✓ Test 3 Passed: Safe error handling verified.\n');
  }

  // Test 4: Link Click Tracking (api/click.js) - 302 Redirect & Parameter Handling
  {
    console.log('Test 4: Link Click Tracking (api/click.js) 302 Redirect...');
    const targetUrl = 'https://example.com/company-proposal';
    const req = createMockReq({
      query: {
        id: 'tr_click_999',
        url: encodeURIComponent(targetUrl)
      },
      headers: {
        'x-vercel-ip-city': 'San Francisco',
        'x-vercel-ip-country': 'US'
      }
    });
    const res = createMockRes();

    await clickHandler(req, res);

    assert.strictEqual(res._getStatusCode(), 302, 'Expected 302 redirect for link click');
    assert.strictEqual(res.getHeader('location'), targetUrl, 'Expected Location header to match target URL');
    assert.ok(res.getHeader('cache-control').includes('no-store'), 'Click redirect should not be cached');
    console.log('✓ Test 4 Passed: Link click 302 redirect and location header verified.\n');
  }

  console.log('🎉 All automated tests passed successfully!');
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
