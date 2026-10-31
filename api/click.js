/**
 * Vercel Serverless Function: Email Link Click Tracker
 * Endpoint: /api/click
 * 
 * Captures email link clicks, extracts client metadata (IP, Location, User-Agent),
 * triggers instant webhook notifications (Discord, Telegram, or custom webhook),
 * and issues an immediate 302 redirect to the destination URL.
 * 
 * This bypasses remote image blocking in Spacemail, Outlook, and corporate mail.
 */

const storage = require('./lib/storage');
const security = require('./lib/security');

// Default placeholder webhook URL (can be overridden via environment variable WEBHOOK_URL or query param)
const DEFAULT_WEBHOOK_URL = process.env.WEBHOOK_URL || 'https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE';

/**
 * Dispatches an event payload to a webhook destination (Discord, Telegram, or generic JSON).
 */
async function sendWebhookNotification(webhookUrl, data) {
  if (!security.isSafeWebhookUrl(webhookUrl)) {
    console.log('[MailTracker Click] Webhook skipped: Unsafe or unconfigured webhook URL.');
    return;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3500);

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
            title: '🔗 Email Link Clicked!',
            color: 0x3b82f6, // Blue
            description: `A link inside email **\`${data.id}\`** was clicked by the recipient!`,
            fields: [
              { name: 'Target URL', value: `[${data.targetUrl}](${data.targetUrl})`, inline: false },
              { name: 'Tracking ID', value: `\`${data.id}\``, inline: true },
              { name: 'IP Address', value: `\`${data.ip}\``, inline: true },
              { name: '📍 Location', value: data.location || 'Unknown', inline: true },
              { name: 'Timestamp (UTC)', value: data.timestamp, inline: false },
              { name: 'User-Agent', value: `\`\`\`${data.userAgent}\`\`\``, inline: false }
            ],
            footer: {
              text: 'MailTracker • Click Tracking Beacon'
            },
            timestamp: new Date().toISOString()
          }
        ]
      });
    } 
    // Format for Telegram Bot API
    else if (webhookUrl.includes('api.telegram.org')) {
      const text = `🔗 *Email Link Clicked!*\n\n` +
        `*ID:* \`${data.id}\`\n` +
        `*Target URL:* ${data.targetUrl}\n` +
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
        event: 'link_clicked',
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
      console.error(`[MailTracker Click] Webhook error response: ${response.status} ${response.statusText}`);
    }
  } catch (error) {
    console.error('[MailTracker Click] Failed to dispatch webhook notification:', error.message);
  } finally {
    clearTimeout(timeoutId);
  }
}

module.exports = async function handler(req, res) {
  // 1. Extract Tracking Identifier & Target URL
  const id = req.query.id || req.query.trackId || 'unspecified_id';
  let rawTargetUrl = req.query.url;

  if (!rawTargetUrl) {
    res.status(400).send('Missing "url" parameter for link redirection.');
    return;
  }

  // Security Validation & Protocol Enforcement
  let decodedUrl = decodeURIComponent(rawTargetUrl);
  if (!decodedUrl.startsWith('http://') && !decodedUrl.startsWith('https://') && !decodedUrl.startsWith('//')) {
    decodedUrl = 'https://' + decodedUrl;
  }

  const validation = security.validateDestinationUrl(decodedUrl);
  if (!validation.valid) {
    res.status(400).send(validation.error);
    return;
  }
  const targetUrl = validation.url;

  // HMAC Integrity Signature Verification
  const sigCheck = security.verifyLinkSignature(id, targetUrl, req.query.sig);
  if (!sigCheck.valid) {
    res.status(400).send(sigCheck.error);
    return;
  }

  // Optional webhook override
  const webhookUrl = req.query.webhook ? decodeURIComponent(req.query.webhook) : DEFAULT_WEBHOOK_URL;

  // 2. Extract Client Metadata
  const rawForwardedFor = req.headers['x-forwarded-for'];
  const ip = (rawForwardedFor ? rawForwardedFor.split(',')[0].trim() : null)
    || req.headers['x-real-ip']
    || req.socket?.remoteAddress
    || 'Unknown IP';

  const userAgent = req.headers['user-agent'] || 'Unknown User-Agent';
  const referer = req.headers['referer'] || req.headers['referrer'] || 'Direct / Email Client';
  const timestamp = new Date().toUTCString();

  // Vercel Free Geo-IP headers
  const city = req.headers['x-vercel-ip-city'] ? decodeURIComponent(req.headers['x-vercel-ip-city']) : '';
  const country = req.headers['x-vercel-ip-country'] || '';
  const region = req.headers['x-vercel-ip-country-region'] || req.headers['x-vercel-ip-region'] || '';
  const location = (city && country) ? `${city}, ${country}` : (country || 'Unknown Location');

  const eventData = {
    id,
    targetUrl,
    ip,
    location,
    userAgent,
    referer,
    timestamp
  };

  console.log(`[MailTracker Click] Link clicked for ID: ${id} -> ${targetUrl} from ${location}`);

  // Persist click event asynchronously
  try {
    await storage.recordClickEvent(id, targetUrl, {
      city: city || null,
      country: country || null,
      region: region || null,
      userAgent,
      ip
    });
  } catch (storageErr) {
    console.error('[MailTracker Storage] Failed to record click event:', storageErr.message);
  }

  // 3. Dispatch Webhook Notification asynchronously
  await sendWebhookNotification(webhookUrl, eventData);

  // 4. Issue 302 Found Redirect to Destination URL with stealth anti-leak headers
  res.writeHead(302, {
    Location: targetUrl,
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    Pragma: 'no-cache',
    Expires: '0',
    'Referrer-Policy': 'no-referrer',
    'Access-Control-Allow-Origin': '*'
  });
  res.end();
};
