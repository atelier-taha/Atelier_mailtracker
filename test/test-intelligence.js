/**
 * Automated Forensic & Mail Intelligence Test Suite
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * 
 * Tests:
 * 1. RFC 5322 multiline unfolding and RFC 2047 MIME decoding (UTF-8 B64 & Q-encoded).
 * 2. Hop chronology inversion, IP/rDNS extraction, latency delta (Δt), and clock skew.
 * 3. Strict vs. Relaxed DMARC alignment across multipart TLDs (e.g. .co.uk, .com.pk).
 * 4. Advanced spoof heuristics (Display-name mismatch, Reply-To drift, Homoglyphs).
 * 5. Forensic dossier generators (JSON, Markdown, Printable HTML).
 */

const assert = require('assert');
const headerParser = require('../extension/lib/header-parser');
const authVerifier = require('../extension/lib/auth-verifier');
const spoofDetector = require('../extension/lib/spoof-detector');
const forensicExporter = require('../extension/lib/forensic-exporter');

async function runIntelligenceTests() {
  console.log('=== Starting Atelier Mail Intelligence Test Suite ===\n');

  // Test 1: RFC 5322 Unfolding & RFC 2047 MIME Decoded-Words
  {
    console.log('Test 1: RFC 5322 Unfolding & MIME Decoded-Words...');
    
    // Test MIME decode Base64 and Quoted-Printable
    const b64Decoded = headerParser.decodeMimeWord('=?UTF-8?B?W0dpdEh1Yl0gQ3JpdGljYWwgQWxlcnQ=?=');
    assert.strictEqual(b64Decoded, '[GitHub] Critical Alert', 'Base64 MIME encoded-word should be decoded');

    const qpDecoded = headerParser.decodeMimeWord('=?ISO-8859-1?Q?Security_Warning=3F?=');
    assert.strictEqual(qpDecoded, 'Security Warning?', 'Quoted-Printable MIME encoded-word should be decoded');

    // Test Multiline Header Unfolding
    const foldedSample = `From: "Support Team"
 <support@example.com>
Subject: Security
 Update Notification
X-Custom: Value 1
    Value 2 continuation`;

    const { map } = headerParser.unfoldAndLexHeaders(foldedSample);
    assert.strictEqual(map['from'][0], '"Support Team" <support@example.com>', 'From header should be unfolded');
    assert.strictEqual(map['subject'][0], 'Security Update Notification', 'Subject header should be unfolded');
    assert.strictEqual(map['x-custom'][0], 'Value 1 Value 2 continuation', 'Multi-space folded header should be normalized');

    console.log('✓ Test 1 Passed: RFC 5322 unfolding and RFC 2047 MIME decoding verified.\n');
  }

  // Test 2: Hop Chronology Inversion, IP Extraction, and Inter-Hop Latency
  {
    console.log('Test 2: Hop Chronology Inversion & Latency Delta...');

    const receivedHeaders = [
      // Top Received header (Destination MX, latest time)
      'by mx.google.com with ESMTPS id abc1; Mon, 05 Oct 2026 10:14:35 -0700',
      // Middle Hop (Relay MTA)
      'from relay.out.com (relay.out.com [192.0.2.10]) by in.relay.com with ESMTP id def2; Mon, 05 Oct 2026 10:14:30 -0700',
      // Bottom Received header (Origin MTA, earliest time)
      'from internal.host.com (internal.host.com [10.0.0.5]) by relay.out.com with ESMTPA id ghi3; Mon, 05 Oct 2026 10:14:20 -0700'
    ];

    const hops = headerParser.parseHopChronology(receivedHeaders);
    
    assert.strictEqual(hops.length, 3, 'Should have 3 parsed hops');
    
    // Hop 1 must be the origin MTA (bottom-most in raw headers)
    assert.strictEqual(hops[0].hopNumber, 1, 'First hop should be Hop 1');
    assert.strictEqual(hops[0].isOrigin, true, 'First hop should be marked isOrigin');
    assert.strictEqual(hops[0].fromMta, 'internal.host.com', 'Origin MTA should be internal.host.com');
    assert.strictEqual(hops[0].ip, '10.0.0.5', 'Origin IP should be 10.0.0.5');

    // Hop 2
    assert.strictEqual(hops[1].hopNumber, 2);
    assert.strictEqual(hops[1].ip, '192.0.2.10');
    assert.strictEqual(hops[1].deltaTimeSeconds, 10, 'Hop 2 delta time should be 10 seconds (10:14:30 - 10:14:20)');

    // Hop 3 (Destination MX)
    assert.strictEqual(hops[2].hopNumber, 3);
    assert.strictEqual(hops[2].isDestination, true, 'Final hop should be marked isDestination');
    assert.strictEqual(hops[2].deltaTimeSeconds, 5, 'Hop 3 delta time should be 5 seconds (10:14:35 - 10:14:30)');

    // Test Clock Skew and Delay Anomaly detection
    const anomalyHeaders = [
      'by dest.mx.com; Mon, 05 Oct 2026 10:14:00 -0700', // Time jumped backwards (-20s)
      'from origin.mta.com; Mon, 05 Oct 2026 10:14:20 -0700'
    ];
    const anomalyHops = headerParser.parseHopChronology(anomalyHeaders);
    assert.strictEqual(anomalyHops[1].clockSkewAnomaly, true, 'Negative latency should flag clock skew');

    console.log('✓ Test 2 Passed: Hop chronology inversion, rDNS/IP, and latency anomalies verified.\n');
  }

  // Test 3: Strict vs. Relaxed DMARC Alignment with Multipart TLDs
  {
    console.log('Test 3: Strict vs. Relaxed DMARC Alignment & Multipart TLDs...');

    // Base domain extraction
    assert.strictEqual(authVerifier.extractBaseDomain('sub.example.com'), 'example.com');
    assert.strictEqual(authVerifier.extractBaseDomain('mail.server.example.co.uk'), 'example.co.uk', 'Multi-part ccTLD .co.uk should resolve to 3-part base domain');
    assert.strictEqual(authVerifier.extractBaseDomain('node1.infra.corp.com.pk'), 'corp.com.pk', 'Multi-part ccTLD .com.pk should resolve to corp.com.pk');

    // Alignment test: Relaxed alignment (subdomain matches base domain)
    const relaxedAlignment = authVerifier.verifyDmarcAlignment(
      'accounts.google.com',
      'bounces.google.com',
      'google.com'
    );
    assert.strictEqual(relaxedAlignment.spf.relaxedAligned, true, 'SPF should be relaxed aligned');
    assert.strictEqual(relaxedAlignment.spf.strictAligned, false, 'SPF should NOT be strict aligned');
    assert.strictEqual(relaxedAlignment.dkim.relaxedAligned, true, 'DKIM should be relaxed aligned');
    assert.strictEqual(relaxedAlignment.hasDmarcAlignment, true, 'DMARC alignment should pass on relaxed');

    // Strict alignment test
    const strictAlignment = authVerifier.verifyDmarcAlignment(
      'example.org',
      'example.org',
      'example.org'
    );
    assert.strictEqual(strictAlignment.spf.strictAligned, true, 'SPF should be strict aligned');
    assert.strictEqual(strictAlignment.dkim.strictAligned, true, 'DKIM should be strict aligned');

    console.log('✓ Test 3 Passed: Multi-part TLD parsing and strict/relaxed alignment verified.\n');
  }

  // Test 4: Advanced Spoof Heuristics & Deterministic Scoring
  {
    console.log('Test 4: Advanced Spoof Detection & Threat Scoring...');

    // Scenario A: Clean Authenticated Email
    {
      const cleanSummary = {
        from: { name: 'GitHub Support', email: 'support@github.com', domain: 'github.com' },
        returnPath: { name: '', email: 'support@github.com', domain: 'github.com' },
        replyTo: { name: '', email: 'support@github.com', domain: 'github.com' }
      };
      const cleanAuth = {
        verdict: 'AUTHENTICATED',
        spf: { status: 'pass', domain: 'github.com', pass: true, aligned: true },
        dkim: { status: 'pass', domain: 'github.com', pass: true, aligned: true },
        dmarc: { status: 'pass', computedPass: true, aligned: true, disposition: 'none' }
      };

      const result = spoofDetector.detectSpoofingThreats(cleanSummary, cleanAuth);
      assert.strictEqual(result.threatScore, 0, 'Clean email should have threat score 0');
      assert.strictEqual(result.riskLevel, 'SAFE', 'Clean email should be SAFE');
      assert.strictEqual(result.isSpoofed, false);
    }

    // Scenario B: Display Name Email Mismatch Spoofing
    {
      const spoofSummary = {
        from: {
          name: 'Security Alert <security@paypal.com>',
          email: 'attacker@evil-phish.xyz',
          domain: 'evil-phish.xyz'
        },
        returnPath: { name: '', email: 'bounce@evil-phish.xyz', domain: 'evil-phish.xyz' },
        replyTo: { name: '', email: '', domain: '' }
      };
      const failAuth = {
        verdict: 'UNAUTHENTICATED / FAILED',
        spf: { status: 'fail', pass: false },
        dkim: { status: 'fail', pass: false },
        dmarc: { status: 'fail', computedPass: false }
      };

      const result = spoofDetector.detectSpoofingThreats(spoofSummary, failAuth);
      assert.ok(result.threatScore >= 50, 'Display name mismatch + auth fail should be HIGH RISK (>= 50)');
      assert.strictEqual(result.riskLevel, 'HIGH RISK');
      assert.strictEqual(result.isSpoofed, true);
      assert.ok(result.findings.some(f => f.code === 'DISPLAY_NAME_EMAIL_MISMATCH'), 'Should flag DISPLAY_NAME_EMAIL_MISMATCH');
    }

    // Scenario C: Reply-To Drift Trap
    {
      const driftSummary = {
        from: { name: 'Support', email: 'support@bank.com', domain: 'bank.com' },
        returnPath: { name: '', email: 'bounce@bank.com', domain: 'bank.com' },
        replyTo: { name: 'Trap', email: 'divert@malicious-harvest.net', domain: 'malicious-harvest.net' }
      };
      const result = spoofDetector.detectSpoofingThreats(driftSummary, null);
      assert.ok(result.findings.some(f => f.code === 'REPLY_TO_DRIFT_TRAP'), 'Should flag deceptive REPLY_TO_DRIFT_TRAP');
    }

    // Scenario D: Homoglyph / Punycode Domain
    {
      const homoglyphSummary = {
        from: { name: 'Admin', email: 'service@xn--pypal-4ve.com', domain: 'xn--pypal-4ve.com' },
        returnPath: { email: '', domain: '' },
        replyTo: { email: '', domain: '' }
      };
      const result = spoofDetector.detectSpoofingThreats(homoglyphSummary, null);
      assert.ok(result.findings.some(f => f.code === 'PUNYCODE_IDN_DOMAIN'), 'Should flag PUNYCODE_IDN_DOMAIN');
    }

    console.log('✓ Test 4 Passed: Spoof heuristics and deterministic threat scoring verified.\n');
  }

  // Test 5: Forensic Dossier Exporters (JSON, Markdown, Standalone HTML)
  {
    console.log('Test 5: Forensic Dossier Exporters...');

    const sampleParsed = {
      summary: {
        from: { raw: 'Test <test@example.com>', domain: 'example.com' },
        to: { raw: 'User <user@target.com>' },
        returnPath: { raw: 'test@example.com' },
        replyTo: { raw: '' },
        subject: 'Audit Report',
        date: 'Mon, 05 Oct 2026 12:00:00 UTC',
        messageId: '<id-12345@example.com>'
      },
      hops: [
        { hopNumber: 1, isOrigin: true, isDestination: false, fromMta: 'origin.net', byMta: 'mx.target.com', ip: '192.0.2.1', deltaTimeSeconds: 0 }
      ],
      headers: { 'from': ['test@example.com'] }
    };

    const sampleAuth = {
      verdict: 'AUTHENTICATED',
      spf: { status: 'pass', domain: 'example.com', aligned: true, pass: true },
      dkim: { status: 'pass', domain: 'example.com', aligned: true, pass: true },
      dmarc: { status: 'pass', computedPass: true, aligned: true, disposition: 'none' },
      alignment: { spf: { aligned: true }, dkim: { aligned: true } }
    };

    const sampleSpoof = {
      threatScore: 0,
      riskLevel: 'SAFE',
      isSpoofed: false,
      findings: []
    };

    // 1. JSON Export
    const jsonStr = forensicExporter.exportAsJson(sampleParsed, sampleAuth, sampleSpoof);
    const parsedJson = JSON.parse(jsonStr);
    assert.strictEqual(parsedJson.threatAssessment.riskLevel, 'SAFE');
    assert.strictEqual(parsedJson.transmissionHops.totalHops, 1);

    // 2. Markdown Export
    const mdStr = forensicExporter.exportAsMarkdown(sampleParsed, sampleAuth, sampleSpoof);
    assert.ok(mdStr.includes('## 1. Executive Threat Assessment'));
    assert.ok(mdStr.includes('## 4. Transmission Hop Chronology'));

    // 3. Standalone HTML Export
    const htmlStr = forensicExporter.exportAsHtml(sampleParsed, sampleAuth, sampleSpoof);
    assert.ok(htmlStr.startsWith('<!DOCTYPE html>'));
    assert.ok(htmlStr.includes('atelierforge-tools // <span>MAIL INTELLIGENCE</span>'));
    assert.ok(htmlStr.includes('@media print'));

    console.log('✓ Test 5 Passed: JSON, Markdown, and Printable HTML exporters verified.\n');
  }

  console.log('🎉 All 5 Atelier Mail Intelligence test suites passed with 100% success!');
}

runIntelligenceTests().catch(err => {
  console.error('❌ Intelligence test failed:', err);
  process.exit(1);
});
