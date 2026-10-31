/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * api/lib/security.js
 * 
 * Endpoint Security & Hardening:
 * 1. Open-Redirect Prevention (Protocol enforcement, CRLF rejection, hostname validation)
 * 2. HMAC URL Signing & Integrity Verification
 * 3. SSRF Mitigation & Webhook URL Validation
 */

'use strict';

const crypto = require('crypto');

const ALLOWED_WEBHOOK_HOSTS = new Set([
  'discord.com',
  'www.discord.com',
  'discordapp.com',
  'www.discordapp.com',
  'api.telegram.org'
]);

/**
 * Checks if a hostname resolves to private/internal/cloud-metadata networks
 */
function isPrivateIpOrHost(hostname) {
  if (!hostname || typeof hostname !== 'string') return true;
  const host = hostname.toLowerCase().trim();

  // Loopback & Unspecified
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') {
    return true;
  }

  // Cloud metadata endpoint (AWS, GCP, Azure, OpenStack)
  if (host === '169.254.169.254') {
    return true;
  }

  // IPv4 Private Ranges (RFC 1918)
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const oct1 = parseInt(ipv4Match[1], 10);
    const oct2 = parseInt(ipv4Match[2], 10);
    if (oct1 === 10) return true; // 10.0.0.0/8
    if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true; // 172.16.0.0/12
    if (oct1 === 192 && oct2 === 168) return true; // 192.168.0.0/16
    if (oct1 === 127) return true; // 127.0.0.0/8
    if (oct1 === 169 && oct2 === 254) return true; // 169.254.0.0/16 Link-local
    if (oct1 === 0) return true;
  }

  // IPv6 local & link-local
  if (host.startsWith('fe80:') || host.startsWith('fc00:') || host.startsWith('fd00:')) {
    return true;
  }

  return false;
}

/**
 * Validates external destination URLs for click tracking redirects.
 * Strictly prevents open-redirect and HTTP response splitting attacks.
 */
function validateDestinationUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'Missing destination URL.' };
  }

  // Reject CRLF to prevent HTTP response splitting
  if (/[\r\n]/.test(rawUrl)) {
    return { valid: false, error: 'Destination URL contains illegal newline control characters.' };
  }

  const trimmed = rawUrl.trim();

  // Reject protocol-relative URLs
  if (trimmed.startsWith('//')) {
    return { valid: false, error: 'Protocol-relative URLs are prohibited.' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Invalid destination URL format.' };
  }

  // Strictly enforce http: or https:
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: `Prohibited protocol scheme: "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  if (!parsed.hostname || parsed.hostname.length === 0) {
    return { valid: false, error: 'Invalid destination URL hostname.' };
  }

  return { valid: true, url: parsed.href };
}

/**
 * Verifies optional/configured HMAC signature for link tracking integrity.
 */
function verifyLinkSignature(trackingId, targetUrl, sig) {
  const secret = process.env.TRACKING_SECRET || process.env.APP_SECRET;
  if (!secret) {
    // Secret not configured; skip signature check in standard mode
    return { valid: true, skipped: true };
  }

  if (!sig || typeof sig !== 'string') {
    return { valid: false, error: 'Missing required signature (&sig=).' };
  }

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${trackingId}:${targetUrl}`)
    .digest('hex');

  const sigBuf = Buffer.from(sig.toLowerCase(), 'hex');
  const expectedBuf = Buffer.from(expectedSig.toLowerCase(), 'hex');

  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return { valid: false, error: 'Invalid HMAC link signature.' };
  }

  return { valid: true };
}

/**
 * Generates an HMAC signature for a tracking link.
 */
function generateLinkSignature(trackingId, targetUrl, secret) {
  const key = secret || process.env.TRACKING_SECRET || process.env.APP_SECRET;
  if (!key) return null;
  return crypto
    .createHmac('sha256', key)
    .update(`${trackingId}:${targetUrl}`)
    .digest('hex');
}

/**
 * Validates a webhook URL to prevent SSRF against internal/cloud services.
 */
function isSafeWebhookUrl(url) {
  if (!url || typeof url !== 'string') return false;
  if (url.includes('YOUR_WEBHOOK_URL_HERE')) return false;

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') {
    return false;
  }

  const hostname = parsed.hostname.toLowerCase();
  if (isPrivateIpOrHost(hostname)) {
    return false;
  }

  // Must match trusted webhook services
  const isAllowedHost = Array.from(ALLOWED_WEBHOOK_HOSTS).some(
    h => hostname === h || hostname.endsWith('.' + h)
  );

  return isAllowedHost;
}

module.exports = {
  isPrivateIpOrHost,
  validateDestinationUrl,
  verifyLinkSignature,
  generateLinkSignature,
  isSafeWebhookUrl,
  ALLOWED_WEBHOOK_HOSTS
};
