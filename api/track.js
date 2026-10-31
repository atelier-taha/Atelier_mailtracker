/**
 * Vercel Serverless Function: Invisible Email Tracker
 * Endpoint: /api/track
 * 
 * Captures email open events, extracts client metadata (IP, Location, User-Agent, Client Type),
 * triggers instant webhook notifications (Discord, Telegram, or custom webhook),
 * and serves a 1x1 transparent GIF with strict anti-caching HTTP headers.
 */

const storage = require('./lib/storage');
const security = require('./lib/security');

// 1x1 Transparent GIF base64 string (42 bytes)
const PIXEL_BASE64 = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
const PIXEL_BUFFER = Buffer.from(PIXEL_BASE64, 'base64');

// Default placeholder webhook URL (can be overridden via environment variable WEBHOOK_URL or query param)
const DEFAULT_WEBHOOK_URL = process.env.WEBHOOK_URL || 'https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE';

/**
 * Classifies the requesting email client, detecting Google Image Proxy,
 * Apple Mail Privacy Protection (MPP), and corporate webmail.
 */
function classifyClient(userAgent = '', ip = '') {
  const ua = userAgent.toLowerCase();
  
  if (userAgent.includes('GoogleImageProxy') || ip.startsWith('66.249.')) {
    return { client: 'Google Image Proxy', note: 'Gmail Web or Mobile App' };
  }
  if (userAgent.includes('AppleImageProxy') || (ua.includes('applewebkit') && ua.includes('mobile') && !ua.includes('safari'))) {
    return { client: 'Apple Mail (MPP)', note: 'Apple Mail (may be background pre-fetch)' };
  }
  if (ua.includes('outlook') || ua.includes('office') || ua.includes('microsoft')) {
    return { client: 'Microsoft Outlook / 365', note: 'Corporate / Org Client' };
  }
  if (ua.includes('thunderbird')) {
    return { client: 'Mozilla Thunderbird', note: 'Desktop Mail Client' };
  }
  if (ua.includes('spacemail') || ua.includes('roundcube') || ua.includes('rainloop')) {
    return { client: 'Organizational Webmail', note: 'Spacemail / Custom Webmail' };
  }
  return { client: 'Direct Email Client', note: 'Desktop or Mobile Client' };
}

/**
 * Dispatches an event payload to a webhook destination (Discord, Telegram, or generic JSON).
 * Safe and non-blocking: errors or timeouts will never prevent the tracking pixel from loading.
 */
async function sendWebhookNotification(webhookUrl, data) {
  if (!security.isSafeWebhookUrl(webhookUrl)) {
    console.log('[MailTracker] Webhook skipped: Unsafe or unconfigured webhook URL.');
    return;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3500); // 3.5s timeout safeguard

  try {
    let payload;
    let headers = { 'Content-Type': 'application/json' };

    // Format for Discord Webhooks
    if (webhookUrl.includes('discord.com/api/webhooks')) {
      payload = JSON.stringify({
        username: 'MailTracker Bot',
        avatar_url: 'https://cdn-icons-png.flaticon.com/512/561/561127.png',
        embeds: [
          {
            title: '📬 Email Opened!',
            color: 0x22c55e, // Emerald Green
            description: `An email with tracking ID **\`${data.id}\`** was opened.`,
            fields: [
              { name: 'Tracking ID', value: `\`${data.id}\``, inline: true },
              { name: 'IP Address', value: `\`${data.ip}\``, inline: true },
              { name: '📍 Location', value: data.location || 'Unknown', inline: true },
              { name: '🖥️ Client Type', value: `**${data.clientInfo.client}**\n_${data.clientInfo.note}_`, inline: false },
              { name: 'Timestamp (UTC)', value: data.timestamp, inline: false },
              { name: 'Referer', value: data.referer || 'Direct / Email Client', inline: false },
              { name: 'User-Agent', value: `\`\`\`${data.userAgent}\`\`\``, inline: false }
            ],
            footer: {
              text: 'MailTracker • Serverless Email Beacon'
            },
            timestamp: new Date().toISOString()
          }
        ]
      });
    } 
    // Format for Telegram Bot API
    else if (webhookUrl.includes('api.telegram.org')) {
      const text = `📬 *Email Opened!*\n\n` +
        `*ID:* \`${data.id}\`\n` +
        `*Client:* ${data.clientInfo.client} (${data.clientInfo.note})\n` +
        `*Location:* ${data.location || 'Unknown'}\n` +
        `*IP:* \`${data.ip}\`\n` +
        `*Time:* ${data.timestamp}\n` +
        `*User-Agent:* \`${data.userAgent}\``;
      
      payload = JSON.stringify({
        text: text,
        parse_mode: 'Markdown'
      });
    } 
    // Generic JSON Webhook Payload
    else {
      payload = JSON.stringify({
        event: 'email_opened',
        ...data
      });
    }

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: headers,
      body: payload,
      signal: controller.signal
    });

    if (!response.ok) {
      console.error(`[MailTracker] Webhook error response: ${response.status} ${response.statusText}`);
    }
  } catch (error) {
    console.error('[MailTracker] Failed to dispatch webhook notification:', error.message);
  } finally {
    clearTimeout(timeoutId);
  }
}

module.exports = async function handler(req, res) {
  // 1. Extract Tracking Identifier
  const id = req.query.id || req.query.trackId || 'unspecified_id';
  
  // Optional webhook override passed via query parameter (URL-encoded) or default env var
  const webhookUrl = req.query.webhook ? decodeURIComponent(req.query.webhook) : DEFAULT_WEBHOOK_URL;

  // 2. Gather Client & Request Metadata
  const rawForwardedFor = req.headers['x-forwarded-for'];
  const ip = (rawForwardedFor ? rawForwardedFor.split(',')[0].trim() : null)
    || req.headers['x-real-ip']
    || req.socket?.remoteAddress
    || 'Unknown IP';

  const userAgent = req.headers['user-agent'] || 'Unknown User-Agent';
  const referer = req.headers['referer'] || req.headers['referrer'] || 'Direct / Hidden';
  const timestamp = new Date().toUTCString();

  // Vercel Free Geo-IP headers
  const city = req.headers['x-vercel-ip-city'] ? decodeURIComponent(req.headers['x-vercel-ip-city']) : '';
  const country = req.headers['x-vercel-ip-country'] || '';
  const region = req.headers['x-vercel-ip-country-region'] || req.headers['x-vercel-ip-region'] || '';
  const location = (city && country) ? `${city}, ${country}` : (country || 'Unknown Location');

  // Client Classification
  const clientInfo = classifyClient(userAgent, ip);

  const eventData = {
    id,
    ip,
    location,
    clientInfo,
    userAgent,
    referer,
    timestamp
  };

  console.log(`[MailTracker] Open event for ID: ${id} | Client: ${clientInfo.client} | Location: ${location}`);

  // Persist tracking event asynchronously
  try {
    await storage.recordOpenEvent(id, {
      city: city || null,
      country: country || null,
      region: region || null,
      userAgent,
      ip
    });
  } catch (storageErr) {
    console.error('[MailTracker Storage] Failed to record open event:', storageErr.message);
  }

  // 3. Dispatch Webhook Notification asynchronously
  await sendWebhookNotification(webhookUrl, eventData);

  // 4. Set Strict Anti-Caching Headers (Crucial for email clients)
  res.setHeader('Content-Type', 'image/gif');
  res.setHeader('Content-Length', PIXEL_BUFFER.length.toString());
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  
  // CORS & Security headers for cross-origin image requests
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // Handle pre-flight OPTIONS request
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // 5. Serve the 1x1 Transparent Pixel
  res.status(200).end(PIXEL_BUFFER);
};
