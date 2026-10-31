# 🛡️ Atelier's MailTracker — Mail Intelligence & Security Suite

> **atelierforge-tools // MAIL INTELLIGENCE**  
> Dual-Engine Enterprise Email Forensics & Invisible Tracking Suite (Manifest V3 + Vercel Serverless)

---

## 🌟 Suite Overview

**Atelier's MailTracker** combines deep **Inbound Email Forensics** with stealth **Outbound Email Tracking** inside a unified dark cyber terminal interface:

1. **Inbound Mail Intelligence Engine (`extension/lib/`)**:
   - **RFC 5322 Unfolding & MIME Decoded-Words**: Robust unfolding of multiline headers and RFC 2047 Base64 / Quoted-Printable decoding.
   - **Transmission Hop Chronology & Latency**: Inverts raw `Received:` headers so Hop 1 is the Origin MTA and the final Hop is the Destination MX. Calculates inter-hop latency ($\Delta t$), identifies IP/CIDR, rDNS hostnames, and flags clock skew or transit delays.
   - **Domain Authentication Verification**: Verifies **SPF**, **DKIM**, and **DMARC** with strict vs. relaxed alignment handling multi-part TLDs (e.g., `.co.uk`, `.com.pk`).
   - **Advanced Spoof & Phishing Detection**: Detects display-name email mismatches, brand impersonation, deceptive `Reply-To` drift traps, and Unicode homoglyphs / Punycode with deterministic `0–100` threat scoring.
   - **Forensic Dossier Exporter**: 1-click export of complete technical JSON (SOC/SIEM ready), formatted Markdown audit reports, and standalone printable HTML audit dossiers.

2. **Outbound Stealth Tracking Engine (`api/` & `extension/`)**:
   - **Stealth 1px Spacer Pixel**: Benign image attributes that bypass corporate anti-tracking engines (like Spacemail's Jellyfish).
   - **Link Click Tracking (`/api/click`)**: Captures recipient IP, location, and device via 302 redirect even when remote images are blocked by default.
   - **Zero-Leak Serverless Backend**: Strict anti-caching headers (`no-store, no-cache, must-revalidate, max-age=0`), `Referrer-Policy: no-referrer`, and Vercel Geo-IP enrichment.

3. **Gmail In-Page Integration (`extension/content.js`)**:
   - **Automated Header Extraction**: Fetches full RFC 5322 headers via Gmail's raw viewer endpoint (`?view=om&th=...`) via an authenticated MV3 background worker.
   - **Isolated Cyber Drawer**: Injected using a **Shadow DOM root** to guarantee zero style bleeding between Gmail's Material Theme and the cyber terminal UI.
   - **Outbound Compose Integration**: "Track ON" / "Track OFF" toggle right next to Gmail's Send button.

---

## 📁 Directory Structure

```text
AT-mailtracker/
├── api/
│   ├── track.js                    # Outbound 1x1 GIF tracking beacon (Zero-leak anti-caching)
│   └── click.js                    # Outbound 302 redirect link click tracker
├── extension/
│   ├── manifest.json               # Manifest V3 extension configuration
│   ├── background.js               # MV3 service worker for ?view=om header fetching
│   ├── popup.html                  # atelierforge-tools Cyber UI Dashboard
│   ├── popup.css                   # Cyber dark-mode theme matching mockup
│   ├── popup.js                    # Dual-engine popup controller
│   ├── content.js                  # Gmail DOM injector (Shadow DOM drawer + compose toggle)
│   ├── content.css                 # In-page action button styling
│   ├── lib/
│   │   ├── header-parser.js        # RFC 5322 unfolding, MIME decoder & Hop chronology
│   │   ├── auth-verifier.js        # SPF/DKIM/DMARC verifier & alignment engine
│   │   ├── spoof-detector.js       # Display name, Reply-To trap & homoglyph detector
│   │   └── forensic-exporter.js    # JSON, Markdown, and Printable HTML report generator
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
├── test/
│   ├── test-intelligence.js        # Automated test suite for Mail Intelligence engines
│   └── test-server.js              # Automated test suite for Vercel tracking endpoints
├── vercel.json                     # Vercel deployment routes & CORS headers
├── package.json                    # Project metadata & test scripts
└── README.md                       # Documentation
```

---

## 🚀 Deployment & Installation

### 1. Deploy Vercel Backend
```bash
npx vercel --prod
```
Set environment variable `WEBHOOK_URL` in Vercel to your Discord or Telegram webhook.

### 2. Install Chrome Extension
1. Open `chrome://extensions/` in Chrome or Brave.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Pin the **Atelier's MailTracker** extension.

---

## 🧪 Automated Testing

Run the unified test suite:
```bash
npm test
```
Runs both:
- `test-intelligence.js`: Validates RFC 5322 unfolding, MIME decoding, hop chronology, DMARC alignment, spoof detection, and report generation.
- `test-server.js`: Validates 1x1 GIF serving, anti-caching headers, Geo-IP, and link click redirects.
