/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/lib/header-parser.js
 * 
 * RFC 5322 Header Parser, RFC 2047 MIME Decoded-Words Engine,
 * and Ordered Transmission Hop Chronology & Latency Analyzer.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AtelierHeaderParser = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Decodes RFC 2047 MIME encoded-word tokens:
   * =?charset?encoding?encoded_text?=
   * Supports B (Base64) and Q (Quoted-Printable) in UTF-8, ISO-8859-1, ASCII, etc.
   */
  function decodeMimeWord(mimeWord) {
    const regex = /=\?([^?]+)\?([bBqQ])\?([^?]+)\?=/gi;
    return mimeWord.replace(regex, (match, charset, encoding, text) => {
      try {
        const enc = encoding.toUpperCase();
        const charUpper = charset.toUpperCase();

        if (enc === 'B') {
          // Base64 decoding with safe UTF-8 multibyte conversion
          if (typeof Buffer !== 'undefined') {
            return Buffer.from(text, 'base64').toString('utf8');
          } else {
            const binary = atob(text.replace(/\s/g, ''));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
              bytes[i] = binary.charCodeAt(i);
            }
            const decoder = new TextDecoder(charUpper.includes('UTF-8') ? 'utf-8' : charset);
            return decoder.decode(bytes);
          }
        } else if (enc === 'Q') {
          // Quoted-Printable: replace underscores with spaces, decode =XX hex
          const qp = text.replace(/_/g, ' ');
          const unescaped = qp.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
            return String.fromCharCode(parseInt(hex, 16));
          });
          try {
            return decodeURIComponent(escape(unescaped));
          } catch {
            return unescaped;
          }
        }
      } catch (err) {
        // Fallback to original text if decoding fails
        return text;
      }
      return match;
    });
  }

  /**
   * Unfolds multiline RFC 5322 headers and parses into key-value map.
   * Repeatable headers (e.g. Received, Authentication-Results, DKIM-Signature)
   * are stored as arrays.
   */
  function unfoldAndLexHeaders(rawText) {
    if (!rawText || typeof rawText !== 'string') {
      return { map: {}, rawLines: [] };
    }

    // Step 1: RFC 5322 Section 2.2.3 Header Unfolding:
    // Any CRLF or LF immediately followed by WSP (space or tab) is unfolded to a single space.
    const unfolded = rawText.replace(/\r?\n[ \t]+/g, ' ');

    // Split headers into lines until empty line (end of headers)
    const lines = unfolded.split(/\r?\n/);
    const headerMap = {};
    const rawLines = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) {
        // First empty line denotes the end of email headers in RFC 5322
        break;
      }

      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;

      const rawKey = line.substring(0, colonIdx).trim();
      const lowerKey = rawKey.toLowerCase();
      const rawVal = line.substring(colonIdx + 1).trim();
      const decodedVal = decodeMimeWord(rawVal);

      rawLines.push({ key: rawKey, value: decodedVal });

      if (!headerMap[lowerKey]) {
        headerMap[lowerKey] = [];
      }
      headerMap[lowerKey].push(decodedVal);
    }

    return { map: headerMap, rawLines };
  }

  /**
   * Extracts clean display name, email address, and root domain from an address field.
   * e.g. "Google Security <no-reply@accounts.google.com>"
   */
  function parseAddress(raw) {
    if (!raw) return { raw: '', name: '', email: '', domain: '' };
    const decoded = decodeMimeWord(raw.trim());

    // Matches Name <email@domain.com>
    const match = decoded.match(/^(?:["']?([^"']*)["']?\s*)?<([^>]+)>/);
    if (match) {
      const name = (match[1] || '').trim();
      const email = (match[2] || '').trim().toLowerCase();
      const domain = email.split('@')[1] || '';
      return { raw: decoded, name, email, domain };
    }

    // Bare email or display name only
    const emailMatch = decoded.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) {
      const email = emailMatch[1].toLowerCase();
      const domain = email.split('@')[1] || '';
      const name = decoded.replace(emailMatch[0], '').replace(/[<>"']/g, '').trim();
      return { raw: decoded, name, email, domain };
    }

    return { raw: decoded, name: decoded, email: '', domain: '' };
  }

  /**
   * Extracts IPv4, IPv6, and hostnames from Received: line
   */
  function extractHopDetails(receivedLine) {
    const hop = {
      fromMta: '',
      fromDeclared: '',
      byMta: '',
      ip: '',
      rdns: '',
      protocol: '',
      tlsCipher: '',
      timestamp: null,
      rawDate: '',
      raw: receivedLine
    };

    // Extract Date (typically after the last semicolon)
    const lastSemicolon = receivedLine.lastIndexOf(';');
    if (lastSemicolon !== -1) {
      hop.rawDate = receivedLine.substring(lastSemicolon + 1).trim();
      const parsedEpoch = Date.parse(hop.rawDate);
      if (!isNaN(parsedEpoch)) {
        hop.timestamp = parsedEpoch;
      }
    }

    const routePart = lastSemicolon !== -1 ? receivedLine.substring(0, lastSemicolon) : receivedLine;

    // Extract "from <hostname> (<rdns> [<ip>])"
    const fromMatch = routePart.match(/\bfrom\s+([^\s]+)(?:\s+\(([^)]+)\))?/i);
    if (fromMatch) {
      hop.fromDeclared = fromMatch[1] || '';
      const bracketContent = fromMatch[2] || '';

      // Look for IPv4 or IPv6 inside parentheses
      const ipMatch = bracketContent.match(/\[([0-9a-fA-F:.]+)\]/) || routePart.match(/\[([0-9a-fA-F:.]+)\]/);
      if (ipMatch) {
        hop.ip = ipMatch[1];
      }

      // Reverse DNS / verified host
      const rdnsMatch = bracketContent.match(/^([^\s[]+)/);
      if (rdnsMatch && rdnsMatch[1] && !rdnsMatch[1].startsWith('[')) {
        hop.rdns = rdnsMatch[1].replace(/[,;]/g, '');
      }
      hop.fromMta = hop.rdns || hop.fromDeclared || hop.ip || 'Unknown Origin';
    }

    // Extract "by <hostname>"
    const byMatch = routePart.match(/\bby\s+([^\s]+)/i);
    if (byMatch) {
      hop.byMta = byMatch[1];
    }

    // Extract "with <protocol/cipher>"
    const withMatch = routePart.match(/\bwith\s+([^;]+?)(?:\s+id|\s+for|\s*$)/i);
    if (withMatch) {
      hop.protocol = withMatch[1].trim();
      if (hop.protocol.toUpperCase().includes('TLS')) {
        hop.tlsCipher = hop.protocol;
      }
    }

    return hop;
  }

  /**
   * Chronologically maps server hops and calculates inter-hop latency.
   * RFC 5322 prepends Received headers; inverting them guarantees Hop 1 is Origin MTA.
   */
  function parseHopChronology(receivedHeaders) {
    if (!receivedHeaders || !Array.isArray(receivedHeaders) || receivedHeaders.length === 0) {
      return [];
    }

    // Invert so Hop 1 = Origin MTA, Final Hop = Destination MX
    const chronologicalRaw = [...receivedHeaders].reverse();
    const hops = [];

    for (let i = 0; i < chronologicalRaw.length; i++) {
      const parsed = extractHopDetails(chronologicalRaw[i]);
      parsed.hopNumber = i + 1;
      parsed.isOrigin = (i === 0);
      parsed.isDestination = (i === chronologicalRaw.length - 1);
      parsed.deltaTimeSeconds = 0;
      parsed.clockSkewAnomaly = false;
      parsed.delayAnomaly = false;

      if (i > 0 && parsed.timestamp && hops[i - 1].timestamp) {
        const deltaMs = parsed.timestamp - hops[i - 1].timestamp;
        const deltaSec = Math.round(deltaMs / 1000);
        parsed.deltaTimeSeconds = deltaSec;

        // Negative latency indicates clock skew between non-NTP synchronized MTAs
        if (deltaSec < -5) {
          parsed.clockSkewAnomaly = true;
        }
        // Delays > 30s flag potential MTA queuing or inspection scanning
        if (deltaSec > 30) {
          parsed.delayAnomaly = true;
        }
      }

      hops.push(parsed);
    }

    return hops;
  }

  /**
   * Main Parsing Entrypoint
   */
  function parseRawEmailHeaders(rawHeaders) {
    const { map, rawLines } = unfoldAndLexHeaders(rawHeaders);

    const fromRaw = map['from'] ? map['from'][0] : '';
    const from = parseAddress(fromRaw);

    const toRaw = map['to'] ? map['to'][0] : '';
    const to = parseAddress(toRaw);

    const returnPathRaw = map['return-path'] ? map['return-path'][0] : '';
    const returnPath = parseAddress(returnPathRaw);

    const replyToRaw = map['reply-to'] ? map['reply-to'][0] : '';
    const replyTo = parseAddress(replyToRaw);

    const subject = map['subject'] ? map['subject'][0] : '(No Subject)';
    const date = map['date'] ? map['date'][0] : '';
    const messageId = map['message-id'] ? map['message-id'][0] : '';

    const receivedHeaders = map['received'] || [];
    const hops = parseHopChronology(receivedHeaders);

    const authResults = map['authentication-results'] || [];
    const receivedSpf = map['received-spf'] ? map['received-spf'][0] : '';
    const dkimSignatures = map['dkim-signature'] || [];
    const arcResults = map['arc-authentication-results'] || [];

    return {
      headers: map,
      rawLines,
      summary: {
        from,
        to,
        returnPath,
        replyTo,
        subject,
        date,
        messageId,
        hopCount: hops.length
      },
      hops,
      security: {
        authResults,
        receivedSpf,
        dkimSignatures,
        arcResults
      }
    };
  }

  return {
    decodeMimeWord,
    unfoldAndLexHeaders,
    parseAddress,
    parseHopChronology,
    parseRawEmailHeaders
  };
}));
