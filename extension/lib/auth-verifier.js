/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/lib/auth-verifier.js
 * 
 * Domain Authentication Verifier (SPF, DKIM, DMARC, ARC)
 * with Strict vs. Relaxed DMARC Alignment Engine and Multipart TLD Parsing.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AtelierAuthVerifier = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Comprehensive multi-part second-level public suffixes
  const MULTI_PART_TLDS = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'com.pk', 'org.pk', 'edu.pk', 'net.pk', 'gov.pk',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
    'co.za', 'org.za', 'gov.za',
    'com.sg', 'edu.sg', 'gov.sg',
    'com.mx', 'org.mx', 'gob.mx',
    'com.tr', 'edu.tr', 'gov.tr',
    'co.kr', 'ne.kr', 're.kr',
    'com.ar', 'gov.ar',
    'com.my', 'edu.my', 'gov.my'
  ]);

  /**
   * Extracts the organizational / root domain from a full hostname.
   * Handles multi-part ccTLDs correctly (e.g. "sub.example.co.uk" -> "example.co.uk").
   */
  function extractBaseDomain(hostname) {
    if (!hostname || typeof hostname !== 'string') return '';
    const cleanHost = hostname.trim().toLowerCase().replace(/\.$/, '');
    const parts = cleanHost.split('.');

    if (parts.length <= 2) {
      return cleanHost;
    }

    // Check if the last two parts match a known multi-part TLD
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_TLDS.has(lastTwo)) {
      // Base domain includes 3 parts: e.g. domain.co.uk
      return parts.slice(-3).join('.');
    }

    // Standard single-part TLD: e.g. sub.domain.com -> domain.com
    return parts.slice(-2).join('.');
  }

  /**
   * Parses Authentication-Results header tokens
   */
  function parseAuthResults(authResultsHeaders) {
    const verdict = {
      spf: { status: 'none', domain: '', ip: '', reason: '' },
      dkim: { status: 'none', domain: '', selector: '', reason: '' },
      dmarc: { status: 'none', policy: '', disposition: '', reason: '' },
      arc: { status: 'none' },
      raw: []
    };

    if (!authResultsHeaders || !Array.isArray(authResultsHeaders) || authResultsHeaders.length === 0) {
      return verdict;
    }

    for (const header of authResultsHeaders) {
      verdict.raw.push(header);

      // Parse SPF
      const spfMatch = header.match(/spf=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:\s+smtp\.(?:mailfrom|mfrom)=([^\s;]+))?/i);
      if (spfMatch && verdict.spf.status === 'none') {
        verdict.spf.status = spfMatch[1].toLowerCase();
        verdict.spf.reason = spfMatch[2] || '';
        verdict.spf.domain = (spfMatch[3] || '').replace(/[<>]/g, '');
      }

      // Parse DKIM
      const dkimMatch = header.match(/dkim=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:\s+header\.(?:i|d)=([^\s;]+))?(?:\s+header\.s=([^\s;]+))?/i);
      if (dkimMatch && verdict.dkim.status === 'none') {
        verdict.dkim.status = dkimMatch[1].toLowerCase();
        verdict.dkim.reason = dkimMatch[2] || '';
        verdict.dkim.domain = (dkimMatch[3] || '').replace(/[<>@]/g, '');
        verdict.dkim.selector = dkimMatch[4] || '';
      }

      // Parse DMARC
      const dmarcMatch = header.match(/dmarc=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:\s+header\.from=([^\s;]+))?(?:\s+action=([^\s;]+))?/i);
      if (dmarcMatch && verdict.dmarc.status === 'none') {
        verdict.dmarc.status = dmarcMatch[1].toLowerCase();
        verdict.dmarc.reason = dmarcMatch[2] || '';
        if (dmarcMatch[4]) {
          verdict.dmarc.disposition = dmarcMatch[4].toLowerCase();
        }
      }
    }

    return verdict;
  }

  /**
   * Fallback: Parses Received-SPF header if Authentication-Results was missing SPF
   */
  function parseReceivedSpf(receivedSpfHeader) {
    if (!receivedSpfHeader) return null;
    const match = receivedSpfHeader.match(/^([a-zA-Z]+)\b(?:\s+\(([^)]+)\))?/i);
    if (!match) return null;

    const status = match[1].toLowerCase();
    const details = match[2] || '';
    
    const domainMatch = details.match(/domain of\s+([^\s]+)/i) || receivedSpfHeader.match(/identity=(?:mailfrom|mfrom);.*?domain=([^\s;]+)/i);
    const ipMatch = details.match(/client-ip=([^\s;]+)/i) || details.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);

    return {
      status,
      domain: domainMatch ? domainMatch[1].replace(/[<>]/g, '') : '',
      ip: ipMatch ? ipMatch[1] : '',
      raw: receivedSpfHeader
    };
  }

  /**
   * Evaluates Strict vs. Relaxed DMARC Alignment against the RFC 5322 From: domain.
   * RFC 7489 Section 3.1:
   * - Strict: From Domain === Authenticated Domain
   * - Relaxed: Base/Org Domain(From) === Base/Org Domain(Authenticated)
   */
  function verifyDmarcAlignment(fromDomain, spfDomain, dkimDomain) {
    const cleanFrom = (fromDomain || '').trim().toLowerCase();
    const cleanSpf = (spfDomain || '').trim().toLowerCase();
    const cleanDkim = (dkimDomain || '').trim().toLowerCase();

    const fromBase = extractBaseDomain(cleanFrom);
    const spfBase = extractBaseDomain(cleanSpf);
    const dkimBase = extractBaseDomain(cleanDkim);

    // SPF Alignment
    const spfStrict = Boolean(cleanFrom && cleanSpf && cleanFrom === cleanSpf);
    const spfRelaxed = Boolean(fromBase && spfBase && fromBase === spfBase);

    // DKIM Alignment
    const dkimStrict = Boolean(cleanFrom && cleanDkim && cleanFrom === cleanDkim);
    const dkimRelaxed = Boolean(fromBase && dkimBase && fromBase === dkimBase);

    return {
      fromDomain: cleanFrom,
      fromBaseDomain: fromBase,
      spf: {
        domain: cleanSpf,
        baseDomain: spfBase,
        strictAligned: spfStrict,
        relaxedAligned: spfRelaxed,
        aligned: spfRelaxed // By default DMARC relaxes alignment unless aspf=s specified
      },
      dkim: {
        domain: cleanDkim,
        baseDomain: dkimBase,
        strictAligned: dkimStrict,
        relaxedAligned: dkimRelaxed,
        aligned: dkimRelaxed // By default DMARC relaxes alignment unless adkim=s specified
      },
      hasDmarcAlignment: (spfRelaxed || dkimRelaxed)
    };
  }

  /**
   * Main Domain Authentication Verification Entrypoint
   */
  function verifyEmailAuthentication(securityData, fromAddress, returnPathAddress) {
    const authVerdict = parseAuthResults(securityData.authResults || []);

    // Fallback to Received-SPF if needed
    if (authVerdict.spf.status === 'none' && securityData.receivedSpf) {
      const fallbackSpf = parseReceivedSpf(securityData.receivedSpf);
      if (fallbackSpf) {
        authVerdict.spf.status = fallbackSpf.status;
        authVerdict.spf.domain = fallbackSpf.domain || returnPathAddress.domain;
        authVerdict.spf.ip = fallbackSpf.ip;
      }
    }

    // Fallback SPF domain from envelope Return-Path
    if (!authVerdict.spf.domain && returnPathAddress && returnPathAddress.domain) {
      authVerdict.spf.domain = returnPathAddress.domain;
    }

    // Fallback DKIM domain from DKIM-Signature header
    if (!authVerdict.dkim.domain && securityData.dkimSignatures && securityData.dkimSignatures.length > 0) {
      const dkimSig = securityData.dkimSignatures[0];
      const dMatch = dkimSig.match(/\bd=([^\s;]+)/i);
      const sMatch = dkimSig.match(/\bs=([^\s;]+)/i);
      if (dMatch) authVerdict.dkim.domain = dMatch[1];
      if (sMatch) authVerdict.dkim.selector = sMatch[1];
    }

    // Compute DMARC Alignment
    const alignment = verifyDmarcAlignment(
      fromAddress.domain,
      authVerdict.spf.domain,
      authVerdict.dkim.domain
    );

    // Compute Overall Composite Verdict
    const spfPass = authVerdict.spf.status === 'pass';
    const dkimPass = authVerdict.dkim.status === 'pass';
    const dmarcExplicitPass = authVerdict.dmarc.status === 'pass';

    // DMARC passes if explicit DMARC pass, OR at least one authenticated mechanism passes and is aligned
    const computedDmarcPass = dmarcExplicitPass ||
      (spfPass && alignment.spf.aligned) ||
      (dkimPass && alignment.dkim.aligned);

    const overallVerdict = (computedDmarcPass && (spfPass || dkimPass))
      ? 'AUTHENTICATED'
      : (spfPass || dkimPass)
        ? 'PARTIALLY AUTHENTICATED'
        : 'UNAUTHENTICATED / FAILED';

    return {
      verdict: overallVerdict,
      spf: {
        status: authVerdict.spf.status,
        domain: authVerdict.spf.domain,
        ip: authVerdict.spf.ip,
        aligned: alignment.spf.aligned,
        strictAligned: alignment.spf.strictAligned,
        pass: spfPass
      },
      dkim: {
        status: authVerdict.dkim.status,
        domain: authVerdict.dkim.domain,
        selector: authVerdict.dkim.selector,
        aligned: alignment.dkim.aligned,
        strictAligned: alignment.dkim.strictAligned,
        pass: dkimPass
      },
      dmarc: {
        status: authVerdict.dmarc.status,
        computedPass: computedDmarcPass,
        aligned: alignment.hasDmarcAlignment,
        disposition: authVerdict.dmarc.disposition || 'none',
        reason: authVerdict.dmarc.reason
      },
      alignment
    };
  }

  return {
    extractBaseDomain,
    parseAuthResults,
    parseReceivedSpf,
    verifyDmarcAlignment,
    verifyEmailAuthentication
  };
}));
