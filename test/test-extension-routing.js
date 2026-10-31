/**
 * Automated Unit Tests for Gmail Multi-Account & Message ID Resolution
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * 
 * Tests:
 * 1. Dynamic account index parsing from window pathname (/mail/u/0/, /mail/u/2/, fallback).
 * 2. Message ID resolution & prefix stripping (#msg-f:, #msg-a:, clean hex).
 * 3. Alphanumeric / hex format validation & input sanitization.
 */

const assert = require('assert');

function getGmailAccountIndexFromPath(pathname) {
  const match = pathname.match(/\/mail\/u\/(\d+)\//);
  return match ? match[1] : '0';
}

function cleanMessageId(rawId) {
  if (!rawId || typeof rawId !== 'string') return null;
  const trimmed = rawId.trim();
  const cleaned = trimmed.replace(/^#?msg-[a-zA-Z0-9]+:/, '');
  if (!/^[a-zA-Z0-9_-]+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function sanitizeAccountIndex(rawIndex) {
  return String(rawIndex || '0').replace(/\D/g, '') || '0';
}

function buildRawMessageUrl(accountIndex, messageId) {
  const sanitizedIndex = sanitizeAccountIndex(accountIndex);
  const cleanedId = cleanMessageId(messageId);
  if (!cleanedId) return null;
  return `https://mail.google.com/mail/u/${sanitizedIndex}/?view=om&th=${encodeURIComponent(cleanedId)}`;
}

console.log('=== Starting Atelier Extension Routing & Resolution Test Suite ===\n');

// Test 1: Account Index Resolution
{
  console.log('Test 1: Gmail Account Index Resolution...');
  assert.strictEqual(getGmailAccountIndexFromPath('/mail/u/0/'), '0');
  assert.strictEqual(getGmailAccountIndexFromPath('/mail/u/1/#inbox'), '1');
  assert.strictEqual(getGmailAccountIndexFromPath('/mail/u/4/#all/18a1b2c3'), '4');
  assert.strictEqual(getGmailAccountIndexFromPath('/mail/u/12/settings'), '12');
  assert.strictEqual(getGmailAccountIndexFromPath('/mail'), '0');
  assert.strictEqual(getGmailAccountIndexFromPath('/'), '0');
  console.log('✓ Test 1 Passed: Account index extraction verified for single and multi-account paths.\n');
}

// Test 2: Message ID Prefix Stripping & Validation
{
  console.log('Test 2: Message ID Cleaning & Validation...');
  assert.strictEqual(cleanMessageId('18a1b2c3d4e5f678'), '18a1b2c3d4e5f678');
  assert.strictEqual(cleanMessageId('#msg-f:1759684465123456789'), '1759684465123456789');
  assert.strictEqual(cleanMessageId('#msg-a:r-1234567890'), 'r-1234567890');
  assert.strictEqual(cleanMessageId('  18a1b2c3d4  '), '18a1b2c3d4');
  assert.strictEqual(cleanMessageId('invalid id with spaces'), null);
  assert.strictEqual(cleanMessageId('invalid<script>'), null);
  assert.strictEqual(cleanMessageId('../path/traversal'), null);
  assert.strictEqual(cleanMessageId(null), null);
  console.log('✓ Test 2 Passed: Message ID prefix normalization and security sanitization verified.\n');
}

// Test 3: Raw Message URL Formatting
{
  console.log('Test 3: URL Target Construction...');
  const url1 = buildRawMessageUrl('2', '#msg-f:1759684465');
  assert.strictEqual(url1, 'https://mail.google.com/mail/u/2/?view=om&th=1759684465');

  const urlDefault = buildRawMessageUrl(undefined, '18a1b2c3');
  assert.strictEqual(urlDefault, 'https://mail.google.com/mail/u/0/?view=om&th=18a1b2c3');

  const urlInvalid = buildRawMessageUrl('0', 'bad id!');
  assert.strictEqual(urlInvalid, null);

  console.log('✓ Test 3 Passed: Dynamic URL targets properly partitioned across user accounts.\n');
}

console.log('🎉 All Extension Routing & Resolution tests passed successfully!\n');
