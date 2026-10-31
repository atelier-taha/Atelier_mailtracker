# Privacy Policy & Data Disclosure

**Product:** Atelier's MailTracker — Mail Intelligence & Security Suite  
**Developer:** AtelierForge Tools (`atelierforge-tools // MAIL INTELLIGENCE`)  
**Effective Date:** October 31, 2026  
**Document Version:** 2.0.0  

---

## 1. Privacy Philosophy & Architecture Overview

Atelier's MailTracker is engineered around a **Local-First, Zero-Knowledge Privacy Architecture**. We believe that security analysis should never compromise user confidentiality. 

The extension operates across two distinct engines with isolated data boundaries:
1. **Inbound Mail Intelligence (Forensics Engine)**: Executes **100% locally** within your browser sandbox. Your email contents, message bodies, subject lines, attachments, and raw MIME headers are **never transmitted to any external server or third-party service**.
2. **Outbound Telemetry (Tracking Engine)**: Detects read receipts and link engagements for your outbound business emails using private, user-controlled serverless endpoints with zero storage of message bodies or credentials.

---

## 2. Inbound Mail Intelligence & Forensic Header Audit

### 2.1 Purely Client-Side Execution
When you click **Inspect Active Gmail Email** or paste headers into the manual analysis drawer:
- The raw RFC 5322 MIME headers are extracted directly from Gmail's authenticated reader interface (`?view=om&th=...`) through the Chrome Extension API.
- All RFC 2047 MIME decoding, transmission hop chronology analysis, SPF/DKIM verification, DMARC alignment checks, and spoof heuristic threat scoring execute **entirely within the local browser runtime**.
- **Zero Remote Exfiltration**: Neither AtelierForge, Google, nor any third party receives the parsed headers, sender addresses, recipient addresses, or email subjects.

### 2.2 Manual Header Inspection
Custom raw headers pasted into the manual inspection drawer are stored solely in transient browser memory (RAM) and are discarded immediately when the drawer is cleared or the extension popup closes.

### 2.3 Forensic Exporting
When you choose to export an audit report (SOC/SIEM JSON or Markdown), the dossier is compiled locally and copied directly to your operating system clipboard. No copy is retained or uploaded remotely.

---

## 3. Outbound Telemetry & Read Tracking Engine

### 3.1 Purpose & Scope
The outbound tracking engine enables professionals to verify message delivery, open rates, and link engagements without relying on intrusive, ad-monetized tracking services.

### 3.2 Telemetry Data Collected Upon Pixel / Link Trigger
When a recipient opens a tracked email or clicks a tracked link, the serverless endpoint (`/api/track.js` and `/api/click.js`) records:
- **Tracking Identifier**: An opaque, non-reversible pseudo-random token (e.g., `tr_mvwnh0u7`).
- **Timestamp**: Unix epoch timestamp of the open or click event.
- **Coarse Geo-Location**: Approximate city, country, and region derived from standard edge CDN runtime headers (e.g., `x-vercel-ip-country`, `x-vercel-ip-city`). **Precise GPS coordinates, device sensors, and Wi-Fi triangulation are never requested, accessed, or recorded.**
- **User-Agent Classification**: The client HTTP `User-Agent` header, used solely to categorize the reading environment (e.g., "Apple Mail", "Microsoft Outlook", "Desktop Chrome").
- **Link Clicks**: The destination URL and HMAC-SHA256 signature to authenticate the redirect and prevent tampering.

### 3.3 What We NEVER Collect or Store
- **No Email Bodies**: The tracking server never sees or stores draft content, body text, or attachments.
- **No Account Credentials**: The extension never accesses, requests, or stores your Google/Gmail password, OAuth tokens, or security keys.
- **No Contact Book Syncing**: The extension does not read, scrape, or harvest your address book or Google Contacts.

---

## 4. Data Storage, Retention & TTL Policies

### 4.1 Local Browser Storage (`chrome.storage.local` & `chrome.storage.sync`)
- **Tracked Drafts**: Stores recently tracked draft summaries (recipient email, subject line, tracking ID, timestamp, and open count) locally on your device to populate the in-popup live telemetry feed.
- **Array Capping**: The local draft log is capped at a maximum of 100 entries. Older records are automatically pruned.
- **User Settings**: Stores your preferred API endpoint, webhook token, and feature toggle flags (pixel tracking, link rewriting).

### 4.2 Edge Persistence (Upstash Redis / Vercel KV)
- If you deploy the optional serverless backend, telemetry events are stored under key `mailtracker:event:${trackingId}`.
- **14-Day Expiration Cutoff**: Client polling engines automatically ignore drafts older than 14 days. Serverless Redis keys are configured with standard Time-To-Live (TTL) expiration (14–30 days).
- **History Capping**: Individual event arrays per tracking ID are capped at a maximum of 50 open/click records to prevent unbounded storage growth.

---

## 5. Chrome Permissions & Single-Purpose Compliance

Atelier's MailTracker requests only the minimum set of permissions strictly necessary to deliver its core functions, adhering to Google's **Single-Purpose Policy**:

| Permission | Technical Need & Purpose |
| :--- | :--- |
| `storage` | Stores user configuration (API endpoint, webhook secret) and local draft tracking metadata (`tracked_drafts`). |
| `activeTab` | Interacts with the active Gmail tab upon user invocation to read compose metadata or inspect RFC headers without granting background access to all browser tabs. |
| `alarms` | Schedules a decentralized 1-minute background wake cycle to diff read receipts and trigger native alerts without maintaining persistent memory-heavy service worker connections. |
| `notifications` | Displays native operating system desktop alerts when a recipient reads your email, eliminating the need to forward notifications through third-party chat bots (Discord/Telegram). |
| `host_permissions`<br>`https://mail.google.com/*` | Required to fetch raw email headers via Gmail's authenticated `?view=om&th=...` endpoint and inject the stealth 1px spacer and wrapped links into active compose drafts. |
| `host_permissions`<br>`https://*.vercel.app/*` | Required for the extension popup and background worker to query real-time read status from the user's deployed serverless backend. |

---

## 6. Google API & Chrome Web Store User Data Policy

Atelier's MailTracker complies with the **Chrome Web Store User Data Policy**, including the **Limited Use** requirements:

1. **No Data Selling**: We do not sell, rent, monetize, or broker user personal data or email metadata to data brokers, advertisers, or third parties under any circumstances.
2. **No Advertising**: We do not use, transfer, or disclose user data for serving personalized, retargeted, or interest-based advertisements.
3. **No Human Interaction**: No human has access to or reads email headers, message content, or tracking events processed through Atelier's MailTracker.
4. **Zero Third-Party Analytics**: The extension contains zero third-party analytics trackers, telemetry SDKs (such as Google Analytics or Mixpanel), or remote ad beacons.

---

## 7. User Control, Opt-Out & Data Deletion

- **Selective Tracking**: You can toggle tracking off at any time per draft via the Compose toolbar checkbox or the extension popup controls.
- **Local Data Purge**: You can clear all locally stored draft telemetry and settings at any time by clearing the extension's storage in `chrome://extensions` or clicking **Clear** in the popup settings drawer.
- **Server Data Purge**: If using a custom Upstash/Vercel KV backend, you can flush tracking records at any time using standard Redis commands (`DEL mailtracker:event:*`) or by deleting the Upstash database instance.
- **Uninstalling**: Uninstalling the extension immediately and permanently removes all local cached headers, drafts, and configuration from your computer.

---

## 8. Security Vulnerability Reporting & Inquiries

Atelier's MailTracker is open-source and built for auditability. If you identify a potential security vulnerability or have questions regarding this privacy policy, please contact our security team:

- **Email:** `security@atelierforge.io`
- **Repository:** `https://github.com/atelierforge/atelier-mailtracker`
- **Security Policy:** All verified vulnerability reports receive priority remediation within 48 hours.
