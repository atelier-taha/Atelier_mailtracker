# Chrome Web Store Listing & Permission Justification Dossier

**Extension Name:** Atelier's MailTracker — Mail Intelligence & Security Suite  
**Package:** `atelier-mailtracker-v2.0.0.zip`  
**Publisher:** AtelierForge Tools  
**Category:** Productivity  
**Secondary Category:** Developer Tools / Security  
**Default Language:** English (United States)  

---

## 1. Store Metadata & Copy

### 1.1 Extension Title
```text
Atelier's MailTracker — Mail Intelligence & Security Suite
```

### 1.2 Short Description (Character Count: 122 / 132 max)
```text
Email header forensics, visual hop mapping, SPF/DKIM/DMARC verification, spoof detection, and stealth open/click tracking.
```

### 1.3 Detailed Description
```markdown
Atelier's MailTracker is an enterprise-grade Mail Intelligence and Security Suite designed specifically for Gmail. Combining client-side email forensics with outbound delivery telemetry, MailTracker equips security analysts, developers, sales professionals, and privacy-conscious users with complete situational awareness over their email communications.

Dual-Engine Architecture:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ ENGINE 1: INBOUND MAIL INTELLIGENCE & FORENSICS (100% Local Processing)
Audit authentic RFC 5322 MIME headers directly from the active email conversation inside Gmail with zero remote exfiltration.

• Instant Thread Inspection: Fetch and parse full headers with one click directly from Gmail's authenticated reader interface.
• Visual Transmission Hop Mapping: Chronologically invert Received headers to trace the authentic email journey from origin MTA to destination MX, identifying inter-hop latency delays (Δt) and clock skew anomalies.
• Cryptographic Authentication Verifier: Evaluates SPF, DKIM, and DMARC alignment (Strict vs. Relaxed) with specialized support for multi-part second-level domains (e.g., .co.uk, .com.au, .com.pk).
• Advanced Spoof & Phishing Heuristics: Detects Display Name email mismatches, deceptive Reply-To traps, and Cyrillic/Greek IDN homoglyphs (Punycode). Computes a deterministic 0–100 Threat Score.
• SOC/SIEM Exporting: Export full forensic audit dossiers to SIEM-ready JSON or formatted Markdown with a single click.

⚡ ENGINE 2: OUTBOUND TELEMETRY & STEALTH ENGAGEMENT TRACKING
Measure read receipts and hyperlink engagements without relying on invasive third-party ad networks.

• Stealth Tracking Beacons: Injects invisible 1px spacer pixels that trigger upon recipient open.
• Automated Link Rewriting: Rewrites outbound hyperlinks through secure, HMAC-SHA256 signed tracking redirects to measure click-throughs.
• Live Telemetry Scorecards: Monitor aggregate metrics including Total Tracked Drafts, Open Rate %, and Click Rate % in real time.
• Interactive Activity Feed: Filter recent communications by All, Opened, Clicked, or Pending. Inspect recipient read counts (✓✓ Nx), relative timestamps, and client operating environment.
• Native Desktop Notifications: Receive immediate operating system desktop alerts when your email is opened, powered by decentralized client-side polling with zero third-party webhook dependencies.

Security & Privacy Guarantees:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Zero Remote Header Exfiltration: All email header parsing, cryptographic checks, and spoof diagnostics execute 100% locally in your browser sandbox. Your email bodies and subjects never leave your machine for analysis.
• Zero Ads & Zero Tracking Networks: We do not sell user data, broker email lists, or serve advertisements.
• Manifest V3 Strict Compliance: Zero remote scripts (no external CDNs), zero inline event handlers, and strictly scoped permissions.
• Open Source & Auditable: Fully documented code with automated unit test suites covering forensic verification, HMAC link signing, and open-redirect defenses.
```

---

## 2. Chrome Web Store Single-Purpose Policy Statement

> **Single-Purpose Declaration for Reviewers:**  
> "Atelier's MailTracker provides verified email authenticity analysis and outbound delivery telemetry for Gmail communications. All features—inbound MIME header forensics, visual hop routing, domain authentication checks, and outbound read/click receipts—serve the unified single purpose of empowering users to inspect the authenticity, transmission path, and engagement status of their Gmail correspondence."

---

## 3. Chrome Permission Justification Table

Google Web Store reviewers require explicit justification for every permission and host permission declared in `manifest.json`:

| Permission | Manifest Declaration | Specific Reviewer Justification |
| :--- | :--- | :--- |
| **`storage`** | `"permissions": ["storage"]` | Required to persist user configuration (e.g., custom API endpoint, webhook secret, auto-inspect preference) and local draft tracking summaries (`tracked_drafts`) in `chrome.storage.local` to populate the popup dashboard and scorecards across browser restarts. |
| **`activeTab`** | `"permissions": ["activeTab"]` | Required to temporarily inspect the active Gmail tab upon explicit user invocation. Used to query the current email thread for authenticated RFC headers (`?view=om&th=...`) and read the recipient/subject of active compose windows without requesting permanent background access to all browser tabs. |
| **`alarms`** | `"permissions": ["alarms"]` | Required to schedule a periodic background wake cycle (1-minute cadence) via `chrome.alarms`. This performs lightweight status diffing against the user's private serverless endpoint to detect new email opens and trigger desktop alerts, adhering to Manifest V3 service worker lifecycle standards. |
| **`notifications`** | `"permissions": ["notifications"]` | Required to deliver native operating system desktop alerts when a recipient opens an email. This alerts the user in real time without requiring personal email forwarding or external third-party webhook relays (e.g., Discord or Telegram). |
| **`host_permissions`**<br>`https://mail.google.com/*` | `"host_permissions": ["https://mail.google.com/*"]` | Required because MailTracker is a Gmail productivity extension. It enables fetching raw email headers via Gmail's built-in authenticated raw view (`?view=om&th=<messageId>`) and injecting the stealth tracking pixel and compose toolbar buttons into active Gmail compose windows. |
| **`host_permissions`**<br>`https://*.vercel.app/*` | `"host_permissions": ["https://*.vercel.app/*"]` | Required to allow the extension's background worker and popup controller to communicate with the user's deployed Vercel serverless backend to sync read receipts (`/api/status`) and test endpoint connectivity. |

---

## 4. Web Store Reviewer Testing Credentials & Instructions

Provide the following instructions to the Chrome Web Store review team to facilitate rapid, friction-free verification:

```text
REVIEWER TESTING INSTRUCTIONS:

1. Installation:
   - Load the unpacked extension from the release zip (or inspect dist/atelier-mailtracker-v2.0.0.zip).
   - Click the extension icon in the Chrome toolbar to open the AT-Mailtracker dashboard.

2. Testing Inbound Forensics (Zero Setup Required):
   - Open any email conversation inside https://mail.google.com.
   - Click the extension icon and select "Inspect Active Gmail Email".
   - The extension extracts RFC headers and displays the forensic verdict, SPF/DKIM/DMARC badges, relay hops, and threat diagnostic analysis.
   - Alternatively, if no Gmail tab is open, click "Inspect Active Gmail Email" to run against the pre-loaded authentic GitHub Advisory sample, or open the manual accordion and click "Analyze".
   - Click "Copy Audit Log" or "JSON" to verify clipboard exporting.

3. Testing Outbound Telemetry:
   - Switch to the "Outbound Telemetry" tab in the popup.
   - In Gmail, click "Compose" to open a new draft.
   - Click "Sync Draft" in the popup to pull the draft recipient and subject automatically.
   - Click "Inject Tracker into Active Draft" to arm the stealth beacon.
   - Click "⚡ Test Read" to simulate an instant recipient open event and verify live scorecard / feed badge updates.
   - Test the feed filter buttons (All, Opened, Clicked, Pending).

4. Testing Configuration Modal:
   - Click the gear icon in the popup header to open Engine Configuration.
   - Verify that settings can be saved and tested.
```

---

## 5. Visual Asset Specifications

Prepare the following promotional graphics prior to submission in the Chrome Web Store Developer Dashboard:

| Asset Type | Required Dimensions | Purpose & Content |
| :--- | :--- | :--- |
| **Extension Icon** | 128 x 128 px (PNG) | High-resolution brand shield icon with cyan/indigo accent. Included in package at `icons/icon128.png`. |
| **Small Promo Tile** | 440 x 280 px (PNG/JPG) | Displayed in search results and category browse pages. Features the AT-Mailtracker logo with headline: *"Mail Intelligence & Security Suite for Gmail"*. |
| **Large Promo Tile** | 920 x 680 px (PNG/JPG) | Featured promo banner in Chrome Web Store collections. Displays the dual-engine split UI showing both Forensics and Telemetry dashboards. |
| **Marquee Banner** | 1400 x 560 px (PNG/JPG) | Hero marquee graphic for top store placement. Dark cyber aesthetic featuring the relay hop visualizer and threat scorecard. |
| **Screenshot 1** | 1280 x 800 px (PNG) | **Inbound Forensics Audit**: Showing authenticated SPF/DKIM/DMARC cards, verdict badge, and traversed relay hops. |
| **Screenshot 2** | 1280 x 800 px (PNG) | **Threat Detection**: Showing phishing detection with Cyrillic homoglyphs and display name mismatch warnings. |
| **Screenshot 3** | 1280 x 800 px (PNG) | **Outbound Telemetry Dashboard**: Showing live scorecards (Tracked, Open Rate, Click Rate) and filterable activity feed. |
| **Screenshot 4** | 1280 x 800 px (PNG) | **Active Compose Integration**: Showing Gmail Compose window with injected stealth beacon toggle and link tracker. |
| **Screenshot 5** | 1280 x 800 px (PNG) | **Native Desktop Alerts & Export**: Showing native macOS/Windows read notifications and SIEM JSON export drawer. |
