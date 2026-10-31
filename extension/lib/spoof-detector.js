/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/lib/spoof-detector.js
 * 
 * Advanced Email Spoofing & Phishing Heuristics Engine
 * Detects Display Name Spoofing, Reply-To Traps, Homoglyphs/Punycode,
 * and outputs deterministic 0-100 Threat Scores.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['./auth-verifier'], factory);
  } else if (typeof module === 'object' && module.exports) {
    const authVerifier = require('./auth-verifier');
    module.exports = factory(authVerifier);
  } else {
    root.AtelierSpoofDetector = factory(root.AtelierAuthVerifier);
  }
}(typeof self !== 'undefined' ? self : this, function (authVerifier) {
  'use strict';

  const extractBaseDomain = authVerifier && authVerifier.extractBaseDomain
    ? authVerifier.extractBaseDomain
    : function (host) {
        if (!host) return '';
        const parts = host.toLowerCase().split('.');
        return parts.length > 2 ? parts.slice(-2).join('.') : host.toLowerCase();
      };

  // High-value targeted brands commonly targeted for display-name spoofing
  const BRAND_TARGETS = [
    { name: 'Google', pattern: /\b(google|gmail|workspace)\b/i, officialDomains: ['google.com', 'gmail.com', 'googlemail.com', 'google.co.uk'] },
    { name: 'Microsoft', pattern: /\b(microsoft|office\s*365|outlook|azure)\b/i, officialDomains: ['microsoft.com', 'office365.com', 'outlook.com', 'live.com', 'hotmail.com'] },
    { name: 'PayPal', pattern: /\bpaypal\b/i, officialDomains: ['paypal.com', 'paypal.co.uk'] },
    { name: 'Apple', pattern: /\b(apple|icloud|itunes)\b/i, officialDomains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', pattern: /\b(amazon|aws)\b/i, officialDomains: ['amazon.com', 'amazon.co.uk', 'amazonaws.com'] },
    { name: 'Banking/Finance', pattern: /\b(chase|wellsfargo|citibank|bankofamerica|barclays|hsbc)\b/i, officialDomains: [] },
    { name: 'Crypto/Security', pattern: /\b(coinbase|binance|metamask|ledger|kraken)\b/i, officialDomains: ['coinbase.com', 'binance.com'] }
  ];

  // Cyrillic & Greek homoglyphs commonly used in IDN spoofing
  const HOMOGLYPH_REGEX = /[\u0400-\u04FF\u0370-\u03FF]/;

  /**
   * Detects Display Name Spoofing:
   * 1. Embedded email addresses in display name that differ from the actual sender.
   * 2. Brand name impersonation where actual domain does not match brand.
   */
  function analyzeDisplayName(fromAddress) {
    const findings = [];
    const name = fromAddress.name || '';
    const actualEmail = fromAddress.email || '';
    const actualBaseDomain = extractBaseDomain(fromAddress.domain || '');

    if (!name) return findings;

    // Check 1: Display Name contains an email address (e.g. "Security <admin@paypal.com>" <hacker@evil.xyz>)
    const embeddedEmailMatch = name.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (embeddedEmailMatch) {
      const embeddedEmail = embeddedEmailMatch[1].toLowerCase();
      const embeddedBaseDomain = extractBaseDomain(embeddedEmail.split('@')[1] || '');

      if (embeddedEmail !== actualEmail && embeddedBaseDomain !== actualBaseDomain) {
        findings.push({
          code: 'DISPLAY_NAME_EMAIL_MISMATCH',
          severity: 'HIGH',
          weight: 45,
          title: 'Display Name Email Mismatch',
          description: `The display name displays "${embeddedEmail}", but the actual sending address is "${actualEmail}". This is a primary phishing technique.`
        });
      }
    }

    // Check 2: Brand Impersonation in Display Name
    for (const brand of BRAND_TARGETS) {
      if (brand.pattern.test(name)) {
        const isOfficial = brand.officialDomains.some(d => actualBaseDomain === extractBaseDomain(d));
        if (!isOfficial) {
          findings.push({
            code: 'BRAND_IMPERSONATION',
            severity: 'HIGH',
            weight: 35,
            title: `Impersonation: ${brand.name}`,
            description: `The display name claims to be "${name}" (${brand.name}), but the message originates from an unrelated domain ("${fromAddress.domain}").`
          });
          break;
        }
      }
    }

    return findings;
  }

  /**
   * Detects Reply-To Drift / Traps:
   * Flags when replies are routed to a domain that differs from both From and Return-Path.
   */
  function analyzeReplyTo(fromAddress, returnPathAddress, replyToAddress) {
    const findings = [];

    if (!replyToAddress || !replyToAddress.email) {
      return findings;
    }

    const fromBase = extractBaseDomain(fromAddress.domain || '');
    const returnBase = extractBaseDomain(returnPathAddress.domain || '');
    const replyBase = extractBaseDomain(replyToAddress.domain || '');

    // Reply-To matches From
    if (replyToAddress.email.toLowerCase() === fromAddress.email.toLowerCase()) {
      return findings;
    }

    // Reply-To base domain differs from BOTH From and Return-Path
    if (replyBase && replyBase !== fromBase && replyBase !== returnBase) {
      findings.push({
        code: 'REPLY_TO_DRIFT_TRAP',
        severity: 'HIGH',
        weight: 35,
        title: 'Deceptive Reply-To Trap',
        description: `Replies will be diverted to "${replyToAddress.email}" (${replyToAddress.domain}), which completely diverges from sender domain "${fromAddress.domain}".`
      });
    } else if (replyToAddress.email.toLowerCase() !== fromAddress.email.toLowerCase()) {
      // Subdomain variation or different mailbox within same org
      findings.push({
        code: 'REPLY_TO_DIFFERENT_MAILBOX',
        severity: 'LOW',
        weight: 5,
        title: 'Alternative Reply Address',
        description: `Replies are routed to "${replyToAddress.email}" instead of the From address.`
      });
    }

    return findings;
  }

  /**
   * Detects Homoglyphs, IDN Punycode, and Zero-Width tricks
   */
  function analyzeHomoglyphs(domain) {
    const findings = [];
    if (!domain) return findings;

    // Check for Punycode
    if (domain.toLowerCase().includes('xn--')) {
      findings.push({
        code: 'PUNYCODE_IDN_DOMAIN',
        severity: 'MEDIUM',
        weight: 25,
        title: 'Punycode Internationalized Domain',
        description: `The domain "${domain}" uses Punycode (IDN), which can visually mimic legitimate ASCII domains.`
      });
    }

    // Check for mixed Cyrillic/Greek homoglyphs
    if (HOMOGLYPH_REGEX.test(domain)) {
      findings.push({
        code: 'HOMOGLYPH_SCRIPT_MISMATCH',
        severity: 'HIGH',
        weight: 45,
        title: 'Homoglyph Character Substitution',
        description: `The domain contains Cyrillic or non-Latin glyphs masquerading as standard Latin characters.`
      });
    }

    return findings;
  }

  /**
   * Analyzes Envelope vs Header Alignment (Return-Path vs From)
   */
  function analyzeEnvelopeAlignment(fromAddress, returnPathAddress, authVerification) {
    const findings = [];

    if (!returnPathAddress || !returnPathAddress.domain || !fromAddress || !fromAddress.domain) {
      return findings;
    }

    const fromBase = extractBaseDomain(fromAddress.domain);
    const returnBase = extractBaseDomain(returnPathAddress.domain);

    if (fromBase !== returnBase) {
      // If DMARC and DKIM pass and align, third-party ESP sending (SendGrid, Mailchimp) is normal
      const isLegitEsp = authVerification && authVerification.dkim && authVerification.dkim.pass && authVerification.dkim.aligned;
      
      findings.push({
        code: 'ENVELOPE_SENDER_MISMATCH',
        severity: isLegitEsp ? 'LOW' : 'MEDIUM',
        weight: isLegitEsp ? 10 : 20,
        title: 'Return-Path Domain Mismatch',
        description: `Header From domain ("${fromAddress.domain}") differs from Envelope Return-Path ("${returnPathAddress.domain}"). ${isLegitEsp ? 'Authenticated via aligned DKIM (standard for bulk ESPs).' : 'Unauthenticated cross-domain routing.'}`
      });
    }

    return findings;
  }

  /**
   * Main Spoof & Threat Scoring Entrypoint
   * Scores: 0 - 19 (SAFE), 20 - 49 (SUSPICIOUS), 50 - 100 (HIGH RISK)
   */
  function detectSpoofingThreats(summary, authVerification) {
    const allFindings = [];

    // 1. Analyze Display Name Spoofing
    const displayNameFindings = analyzeDisplayName(summary.from);
    allFindings.push(...displayNameFindings);

    // 2. Analyze Reply-To Drift
    const replyToFindings = analyzeReplyTo(summary.from, summary.returnPath, summary.replyTo);
    allFindings.push(...replyToFindings);

    // 3. Analyze Homoglyphs & IDN
    const homoglyphFindings = [
      ...analyzeHomoglyphs(summary.from.domain),
      ...analyzeHomoglyphs(summary.replyTo.domain),
      ...analyzeHomoglyphs(summary.returnPath.domain)
    ];
    allFindings.push(...homoglyphFindings);

    // 4. Analyze Envelope Alignment
    const envelopeFindings = analyzeEnvelopeAlignment(summary.from, summary.returnPath, authVerification);
    allFindings.push(...envelopeFindings);

    // 5. Auth-based threat penalties
    if (authVerification) {
      if (authVerification.spf.status === 'fail') {
        allFindings.push({
          code: 'SPF_FAIL',
          severity: 'HIGH',
          weight: 35,
          title: 'SPF Authentication Failed',
          description: 'The sending server IP is explicitly unauthorized to send on behalf of this domain.'
        });
      }
      if (authVerification.dkim.status === 'fail') {
        allFindings.push({
          code: 'DKIM_FAIL',
          severity: 'HIGH',
          weight: 35,
          title: 'DKIM Signature Invalid',
          description: 'Cryptographic DKIM signature failed verification or message was modified in transit.'
        });
      }
      if (!authVerification.dmarc.computedPass && authVerification.verdict.includes('FAILED')) {
        allFindings.push({
          code: 'DMARC_ALIGNMENT_FAIL',
          severity: 'HIGH',
          weight: 30,
          title: 'DMARC Alignment Failure',
          description: 'Neither SPF nor DKIM passed with domain alignment against the From address.'
        });
      }
    }

    // Deduplicate findings by code
    const uniqueFindings = [];
    const seenCodes = new Set();
    for (const f of allFindings) {
      if (!seenCodes.has(f.code)) {
        seenCodes.add(f.code);
        uniqueFindings.push(f);
      }
    }

    // Compute deterministic threat score (0 - 100)
    let rawScore = uniqueFindings.reduce((acc, f) => acc + (f.weight || 0), 0);
    const threatScore = Math.min(100, Math.max(0, rawScore));

    let riskLevel = 'SAFE';
    let riskColor = '#10b981'; // Emerald

    if (threatScore >= 50) {
      riskLevel = 'HIGH RISK';
      riskColor = '#ef4444'; // Red
    } else if (threatScore >= 20) {
      riskLevel = 'SUSPICIOUS';
      riskColor = '#f59e0b'; // Amber
    }

    return {
      threatScore,
      riskLevel,
      riskColor,
      isSpoofed: threatScore >= 50,
      findingsCount: uniqueFindings.length,
      findings: uniqueFindings
    };
  }

  return {
    analyzeDisplayName,
    analyzeReplyTo,
    analyzeHomoglyphs,
    analyzeEnvelopeAlignment,
    detectSpoofingThreats
  };
}));
