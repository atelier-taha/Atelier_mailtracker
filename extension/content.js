/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * extension/content.js
 * 
 * Dual-Engine Gmail Content Script:
 * 1. Outbound Draft Tracking (Stealth 1px spacer pixel injection)
 * 2. Inbound Mail Intelligence (Automated raw header extraction via ?view=om&th=...,
 *    Shadow DOM cyber forensics drawer, visual hop mapping, auth & spoof check)
 */

(function () {
  'use strict';

  // Cached user settings
  let userSettings = {
    backendUrl: '',
    webhookUrl: '',
    defaultEnabled: true,
    trackLinksEnabled: true
  };

  function refreshSettings() {
    chrome.storage.sync.get(['backendUrl', 'webhookUrl', 'defaultEnabled', 'trackLinksEnabled'], (data) => {
      userSettings.backendUrl = data.backendUrl || '';
      userSettings.webhookUrl = data.webhookUrl || '';
      userSettings.defaultEnabled = typeof data.defaultEnabled !== 'undefined' ? data.defaultEnabled : true;
      userSettings.trackLinksEnabled = typeof data.trackLinksEnabled !== 'undefined' ? data.trackLinksEnabled : true;
    });
  }

  refreshSettings();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync') refreshSettings();
  });

  /* ==========================================================================
     Shadow DOM Forensics Drawer Implementation
     ========================================================================== */
  let shadowRoot = null;
  let drawerElement = null;

  function ensureShadowDrawer() {
    let host = document.getElementById('atelier-forensics-drawer-root');
    if (!host) {
      host = document.createElement('div');
      host.id = 'atelier-forensics-drawer-root';
      document.body.appendChild(host);
      shadowRoot = host.attachShadow({ mode: 'open' });

      // Injected Scoped Cyber Styles inside Shadow DOM
      const style = document.createElement('style');
      style.textContent = `
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace; }
        .drawer-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100vw;
          height: 100vh;
          background: rgba(0, 0, 0, 0.6);
          pointer-events: auto;
          display: flex;
          justify-content: flex-end;
          z-index: 1000000;
          animation: fadeIn 0.2s ease-out;
        }
        .drawer {
          width: 480px;
          height: 100vh;
          background: #070a0f;
          border-left: 1px solid #1a2333;
          display: flex;
          flex-direction: column;
          box-shadow: -10px 0 30px rgba(0, 0, 0, 0.9);
          animation: slideLeft 0.25s ease-out;
          color: #f1f5f9;
        }
        @keyframes slideLeft { from { transform: translateX(100%); } to { transform: translateX(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .titlebar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 12px 16px;
          background: #06090e;
          border-bottom: 1px solid #1a2333;
        }
        .controls { display: flex; align-items: center; gap: 6px; }
        .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; cursor: pointer; }
        .dot-red { background: #ef4444; }
        .dot-yellow { background: #f59e0b; }
        .dot-green { background: #10b981; }
        .title-text { font-size: 12px; font-weight: 700; color: #cbd5e1; margin-left: 8px; }
        .tag { font-size: 10px; color: #00e5ff; letter-spacing: 1px; }
        .body { flex: 1; overflow-y: auto; padding: 14px; font-size: 11px; }
        .trio-cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 12px; }
        .trio-card { background: #0d121d; border: 1px solid #1a2333; border-radius: 4px; padding: 8px; }
        .trio-lbl { font-size: 9px; color: #64748b; text-transform: uppercase; }
        .trio-val { font-size: 11px; font-weight: 700; color: #fff; margin-top: 2px; }
        .card { background: #0d121d; border: 1px solid #1a2333; border-radius: 4px; padding: 10px; margin-bottom: 12px; }
        .card-title { font-size: 11px; font-weight: 700; color: #00e5ff; margin-bottom: 8px; text-transform: uppercase; }
        .hop-row { display: flex; gap: 8px; padding: 6px 8px; background: #131b2a; border: 1px solid #1a2333; border-radius: 3px; margin-bottom: 6px; font-size: 10px; align-items: center; }
        .hop-badge { width: 18px; height: 18px; border-radius: 50%; background: #1e293b; color: #00e5ff; display: flex; align-items: center; justify-content: center; font-size: 9px; font-weight: 700; flex-shrink: 0; }
        .btn { padding: 6px 10px; background: #00e5ff; color: #070a0f; font-weight: 700; border: none; border-radius: 4px; cursor: pointer; font-size: 10px; }
        .btn-sec { background: #1e293b; color: #cbd5e1; border: 1px solid #2b3952; }
        .threat-item { padding: 8px; background: #1a0f12; border-left: 3px solid #ef4444; margin-bottom: 6px; border-radius: 2px; }
        .threat-item.warn { background: #191408; border-left-color: #f59e0b; }
      `;
      shadowRoot.appendChild(style);

      drawerElement = document.createElement('div');
      drawerElement.className = 'drawer-overlay';
      drawerElement.style.display = 'none';
      shadowRoot.appendChild(drawerElement);
    }
  }

  function closeForensicsDrawer() {
    if (drawerElement) {
      drawerElement.style.display = 'none';
    }
  }

  function renderForensicsInDrawer(rawHeaders, messageId) {
    ensureShadowDrawer();

    try {
      const parsedData = window.AtelierHeaderParser.parseRawEmailHeaders(rawHeaders);
      const authData = window.AtelierAuthVerifier.verifyEmailAuthentication(
        parsedData.security,
        parsedData.summary.from,
        parsedData.summary.returnPath
      );
      const spoofData = window.AtelierSpoofDetector.detectSpoofingThreats(
        parsedData.summary,
        authData
      );

      const s = parsedData.summary;
      const riskColor = spoofData.threatScore >= 50 ? '#ef4444' : spoofData.threatScore >= 20 ? '#f59e0b' : '#10b981';

      drawerElement.innerHTML = `
        <div class="drawer">
          <div class="titlebar">
            <div class="controls">
              <span class="dot dot-red" id="closeDrawerDot"></span>
              <span class="dot dot-yellow"></span>
              <span class="dot dot-green"></span>
              <span class="title-text">atelierforge-tools // FORENSICS</span>
            </div>
            <span class="tag">ACTIVE INSPECTION</span>
          </div>
          <div class="body">
            <!-- 3 Top Cards -->
            <div class="trio-cards">
              <div class="trio-card">
                <div class="trio-lbl">AUTH CHECK</div>
                <div class="trio-val" style="color:${authData.dmarc.computedPass ? '#00ff9d' : '#ef4444'};">
                  ${authData.dmarc.computedPass ? 'DMARC PASS' : 'AUTH FAIL'}
                </div>
              </div>
              <div class="trio-card">
                <div class="trio-lbl">HOP ANALYSIS</div>
                <div class="trio-val" style="color:#00e5ff;">${parsedData.hops.length} Hops</div>
              </div>
              <div class="trio-card">
                <div class="trio-lbl">SPOOF CHECK</div>
                <div class="trio-val" style="color:${riskColor};">${spoofData.riskLevel}</div>
              </div>
            </div>

            <!-- Envelope Info -->
            <div class="card">
              <div class="card-title">1. Envelope & Identity</div>
              <div style="line-height:1.5;">
                <div><span style="color:#64748b;">Subject:</span> <strong>${s.subject}</strong></div>
                <div><span style="color:#64748b;">From:</span> <span style="color:#38bdf8;">${s.from.raw}</span></div>
                <div><span style="color:#64748b;">Return-Path:</span> <span>${s.returnPath.raw || 'None'}</span></div>
                <div><span style="color:#64748b;">Reply-To:</span> <span>${s.replyTo.raw || 'None'}</span></div>
                <div><span style="color:#64748b;">Date:</span> <span>${s.date}</span></div>
              </div>
            </div>

            <!-- Threat Breakdown -->
            <div class="card">
              <div class="card-title" style="color:${riskColor};">2. Threat & Spoof Status (${spoofData.threatScore}/100)</div>
              ${spoofData.findings.length === 0 ? '<div style="color:#00ff9d;">✓ No deceptive reply-to traps or spoofing indicators.</div>' : ''}
              ${spoofData.findings.map(f => `
                <div class="threat-item ${f.severity === 'LOW' ? 'warn' : ''}">
                  <div style="font-weight:700; color:${f.severity === 'LOW' ? '#fbbf24' : '#f87171'};">[${f.severity}] ${f.title}</div>
                  <div style="color:#cbd5e1; font-size:10px; margin-top:2px;">${f.description}</div>
                </div>
              `).join('')}
            </div>

            <!-- Authentication Breakdown -->
            <div class="card">
              <div class="card-title">3. Authentication Alignment</div>
              <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:6px;">
                <div style="background:#131b2a; padding:6px; border-radius:3px;">
                  <div style="font-size:9px; color:#64748b;">SPF</div>
                  <div style="font-weight:700; color:${authData.spf.pass ? '#00ff9d' : '#ef4444'};">${authData.spf.status.toUpperCase()}</div>
                  <div style="font-size:8px; color:#94a3b8;">${authData.spf.aligned ? 'Aligned' : 'Unaligned'}</div>
                </div>
                <div style="background:#131b2a; padding:6px; border-radius:3px;">
                  <div style="font-size:9px; color:#64748b;">DKIM</div>
                  <div style="font-weight:700; color:${authData.dkim.pass ? '#00ff9d' : '#ef4444'};">${authData.dkim.status.toUpperCase()}</div>
                  <div style="font-size:8px; color:#94a3b8;">${authData.dkim.aligned ? 'Aligned' : 'Unaligned'}</div>
                </div>
                <div style="background:#131b2a; padding:6px; border-radius:3px;">
                  <div style="font-size:9px; color:#64748b;">DMARC</div>
                  <div style="font-weight:700; color:${authData.dmarc.computedPass ? '#00ff9d' : '#ef4444'};">${authData.dmarc.computedPass ? 'PASS' : 'FAIL'}</div>
                  <div style="font-size:8px; color:#94a3b8;">${authData.dmarc.disposition}</div>
                </div>
              </div>
            </div>

            <!-- Hop Path -->
            <div class="card">
              <div class="card-title">4. Transmission Hop Path (${parsedData.hops.length} Hops)</div>
              ${parsedData.hops.map(h => `
                <div class="hop-row">
                  <div class="hop-badge">${h.isOrigin ? 'ORG' : h.hopNumber}</div>
                  <div style="flex:1; min-width:0;">
                    <div style="font-weight:700; color:#fff; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${h.fromMta || 'Unknown'}</div>
                    <div style="color:#64748b; font-size:9px;">by ${h.byMta || 'Destination'} ${h.ip ? `• [${h.ip}]` : ''}</div>
                  </div>
                  <div style="text-align:right;">
                    <div style="color:#00e5ff; font-size:9px;">${h.isOrigin ? 'Origin' : `${h.deltaTimeSeconds}s`}</div>
                    ${h.clockSkewAnomaly ? '<div style="color:#f59e0b; font-size:8px;">Clock Skew</div>' : ''}
                    ${h.delayAnomaly ? '<div style="color:#f59e0b; font-size:8px;">Delay</div>' : ''}
                  </div>
                </div>
              `).join('')}
            </div>

            <!-- Export Buttons -->
            <div style="display:flex; gap:6px;">
              <button type="button" id="copyMdBtn" class="btn" style="flex:1;">Copy Markdown</button>
              <button type="button" id="closeDrawerBtn" class="btn btn-sec">Close</button>
            </div>
          </div>
        </div>
      `;

      drawerElement.style.display = 'flex';

      shadowRoot.getElementById('closeDrawerDot').addEventListener('click', closeForensicsDrawer);
      shadowRoot.getElementById('closeDrawerBtn').addEventListener('click', closeForensicsDrawer);
      shadowRoot.getElementById('copyMdBtn').addEventListener('click', async () => {
        const md = window.AtelierForensicExporter.exportAsMarkdown(parsedData, authData, spoofData);
        await navigator.clipboard.writeText(md);
        alert('✓ Forensic Markdown report copied to clipboard!');
      });
    } catch (err) {
      console.error(err);
      renderFallbackDrawer(`Parsing Error: ${err.message}`, messageId);
    }
  }

  /**
   * Resolves the active Gmail account index from the current URL path partition.
   * e.g., /mail/u/2/#inbox -> "2", defaulting to "0".
   */
  function getGmailAccountIndex() {
    const match = window.location.pathname.match(/\/mail\/u\/(\d+)\//);
    return match ? match[1] : '0';
  }

  /**
   * Resolves the exact individual email message ID from a target DOM node in threaded conversations.
   * Traverses up from the element checking data-legacy-message-id, data-message-id, and inner fallbacks.
   */
  function resolveMessageIdFromElement(triggerElement) {
    if (!triggerElement) return null;

    // Traverse up to find closest message container
    const container = triggerElement.closest('div[data-legacy-message-id], div[data-message-id], div.adn, .adn.ads');
    if (!container) return null;

    // 1. Check data-legacy-message-id first (clean hex format)
    const legacyId = container.getAttribute('data-legacy-message-id');
    if (legacyId && legacyId.trim()) {
      return legacyId.trim();
    }

    // 2. Check data-message-id second (strip #msg-f: / #msg-a: prefixes if present)
    const rawId = container.getAttribute('data-message-id');
    if (rawId && rawId.trim()) {
      const cleanId = rawId.trim().replace(/^#?msg-[a-zA-Z0-9]+:/, '');
      if (cleanId) return cleanId;
    }

    // 3. Fallback: query inner elements containing [data-legacy-message-id]
    const innerLegacy = container.querySelector('[data-legacy-message-id]');
    if (innerLegacy) {
      const innerLegacyId = innerLegacy.getAttribute('data-legacy-message-id');
      if (innerLegacyId && innerLegacyId.trim()) {
        return innerLegacyId.trim();
      }
    }

    // Secondary fallback: query inner elements containing [data-message-id]
    const innerMsg = container.querySelector('[data-message-id]');
    if (innerMsg) {
      const innerMsgId = innerMsg.getAttribute('data-message-id');
      if (innerMsgId && innerMsgId.trim()) {
        const cleanInner = innerMsgId.trim().replace(/^#?msg-[a-zA-Z0-9]+:/, '');
        if (cleanInner) return cleanInner;
      }
    }

    return null;
  }

  function renderUnresolvedMessageErrorDrawer() {
    ensureShadowDrawer();

    drawerElement.innerHTML = `
      <div class="drawer">
        <div class="titlebar">
          <div class="controls">
            <span class="dot dot-red" id="closeErrorDot"></span>
            <span class="title-text">atelierforge-tools // FORENSICS</span>
          </div>
          <span class="tag" style="color:#ef4444;">RESOLUTION ERROR</span>
        </div>
        <div class="body">
          <div class="card" style="border-color:#ef4444;">
            <div class="card-title" style="color:#f87171;">⚠️ Message ID Resolution Failed</div>
            <div style="color:#cbd5e1; font-size:11px; line-height:1.6; margin-bottom:10px;">
              Unable to resolve a valid message ID for this email item in the conversation thread.
              Please ensure the specific message is expanded, or paste RFC 5322 headers manually below:
            </div>
          </div>

          <div class="card">
            <div class="card-title">Manual RFC 5322 Header Analysis</div>
            <textarea id="manualHeaderBox" style="width:100%; height:160px; background:#080c14; border:1px solid #1a2333; color:#cbd5e1; font-size:10px; padding:8px; border-radius:4px;" placeholder="Paste RFC 5322 headers here (from Gmail: Show Original)..."></textarea>
            <div style="display:flex; gap:6px; margin-top:8px;">
              <button type="button" id="manualAnalyzeBtn" class="btn" style="flex:1;">Execute Analysis</button>
              <button type="button" id="errorCloseBtn" class="btn btn-sec">Cancel</button>
            </div>
          </div>
        </div>
      </div>
    `;

    drawerElement.style.display = 'flex';

    shadowRoot.getElementById('closeErrorDot').addEventListener('click', closeForensicsDrawer);
    shadowRoot.getElementById('errorCloseBtn').addEventListener('click', closeForensicsDrawer);
    shadowRoot.getElementById('manualAnalyzeBtn').addEventListener('click', () => {
      const text = shadowRoot.getElementById('manualHeaderBox').value.trim();
      if (text) {
        renderForensicsInDrawer(text, null);
      }
    });
  }

  function renderFallbackDrawer(errorMsg, messageId) {
    ensureShadowDrawer();

    const accountIndex = getGmailAccountIndex();
    const rawUrl = messageId ? `https://mail.google.com/mail/u/${accountIndex}/?view=om&th=${encodeURIComponent(messageId)}` : '';

    drawerElement.innerHTML = `
      <div class="drawer">
        <div class="titlebar">
          <div class="controls">
            <span class="dot dot-red" id="closeFallbackDot"></span>
            <span class="title-text">atelierforge-tools // FORENSICS</span>
          </div>
          <span class="tag">MANUAL INPUT</span>
        </div>
        <div class="body">
          <div class="card" style="border-color:#f59e0b;">
            <div class="card-title" style="color:#fbbf24;">⚡ Header Fetch Notice</div>
            <div style="color:#cbd5e1; font-size:11px; margin-bottom:10px;">
              Automated extraction encountered session boundaries. You can view or copy raw headers directly from Gmail:
            </div>
            ${rawUrl ? `<a href="${rawUrl}" target="_blank" class="btn" style="display:inline-block; text-decoration:none; margin-bottom:12px;">🔗 Open Original Headers in New Tab</a>` : ''}
          </div>

          <div class="card">
            <div class="card-title">Paste RFC 5322 Headers</div>
            <textarea id="manualHeaderBox" style="width:100%; height:160px; background:#080c14; border:1px solid #1a2333; color:#cbd5e1; font-size:10px; padding:8px; border-radius:4px;" placeholder="Paste headers here..."></textarea>
            <div style="display:flex; gap:6px; margin-top:8px;">
              <button type="button" id="manualAnalyzeBtn" class="btn" style="flex:1;">Execute Analysis</button>
              <button type="button" id="fallbackCloseBtn" class="btn btn-sec">Cancel</button>
            </div>
          </div>
        </div>
      </div>
    `;

    drawerElement.style.display = 'flex';

    shadowRoot.getElementById('closeFallbackDot').addEventListener('click', closeForensicsDrawer);
    shadowRoot.getElementById('fallbackCloseBtn').addEventListener('click', closeForensicsDrawer);
    shadowRoot.getElementById('manualAnalyzeBtn').addEventListener('click', () => {
      const text = shadowRoot.getElementById('manualHeaderBox').value.trim();
      if (text) {
        renderForensicsInDrawer(text, messageId);
      }
    });
  }

  /**
   * Triggers automated raw header analysis for a specific Gmail email
   */
  function analyzeEmailHeaders(messageId) {
    if (!messageId) {
      console.warn('[AT-MailTracker] Unable to resolve message ID for target node');
      renderUnresolvedMessageErrorDrawer();
      return;
    }

    ensureShadowDrawer();
    const accountIndex = getGmailAccountIndex();

    drawerElement.innerHTML = `
      <div class="drawer">
        <div class="titlebar">
          <div class="controls"><span class="dot dot-red" id="loadingCloseDot"></span></div>
          <span class="tag">FETCHING HEADERS</span>
        </div>
        <div class="body" style="display:flex; align-items:center; justify-content:center; flex-direction:column; gap:12px; height:80%;">
          <div style="color:#00e5ff; font-weight:700;">⚡ Fetching RFC 5322 headers from Gmail...</div>
          <div style="color:#64748b; font-size:10px;">Querying endpoint /u/${accountIndex}/?view=om&th=${messageId}</div>
        </div>
      </div>
    `;
    drawerElement.style.display = 'flex';
    shadowRoot.getElementById('loadingCloseDot').addEventListener('click', closeForensicsDrawer);

    // Call background service worker across session boundaries
    chrome.runtime.sendMessage(
      { action: 'FETCH_RAW_HEADERS', messageId, accountIndex },
      (response) => {
        if (response && response.success && response.rawHeaders) {
          renderForensicsInDrawer(response.rawHeaders, messageId);
        } else {
          renderFallbackDrawer(response ? response.error : 'Session boundary challenge', messageId);
        }
      }
    );
  }

  /* ==========================================================================
     Inbound Gmail Action Button Injection
     ========================================================================== */
  function injectInboundForensicsButton(emailContainer) {
    if (emailContainer.querySelector('.atelier-intel-btn')) return;

    // Locate the email action bar / header bar
    const actionBar = emailContainer.querySelector('.gH')
      || emailContainer.querySelector('.gK')
      || emailContainer.querySelector('.adn.ads')
      || emailContainer.querySelector('[role="heading"]')?.parentElement;

    if (!actionBar) return;

    const intelBtn = document.createElement('button');
    intelBtn.type = 'button';
    intelBtn.className = 'atelier-intel-btn';
    intelBtn.title = "Atelier's MailTracker: Analyze RFC 5322 headers, visual hops, and spoofing indicators";
    intelBtn.innerHTML = `
      <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
      </svg>
      <span>🛡️ Forensics</span>
    `;

    intelBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();

      // Resolve exact message ID dynamically from closest container in thread
      const resolvedId = resolveMessageIdFromElement(intelBtn)
        || resolveMessageIdFromElement(emailContainer)
        || emailContainer.getAttribute('data-legacy-message-id')
        || (emailContainer.getAttribute('data-message-id') ? emailContainer.getAttribute('data-message-id').replace(/^#?msg-[a-zA-Z0-9]+:/, '') : null);

      if (!resolvedId) {
        console.warn('[AT-MailTracker] Unable to resolve message ID for target node', intelBtn);
        renderUnresolvedMessageErrorDrawer();
        return;
      }

      analyzeEmailHeaders(resolvedId);
    });

    actionBar.appendChild(intelBtn);
  }

  /* ==========================================================================
     Outbound Compose Window Integration (Stealth 1px Spacer Pixel)
     ========================================================================== */
  function generateTrackingId() {
    return `tr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 8)}`;
  }

  function showGmailToast(message, type = 'info') {
    const existing = document.querySelector('.mailtracker-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `mailtracker-toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
      if (toast && toast.parentNode) {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
      }
    }, 4000);
  }

  function recordTrackedEmail(trackingId, subject, recipient) {
    const draftSubject = (subject && subject.trim()) ? subject.trim() : '(No Subject)';
    const draftRecipient = (recipient && recipient.trim()) ? recipient.trim() : 'Recipient';
    const now = Date.now();

    chrome.storage.local.get(['tracked_drafts', 'recentTrackedEmails'], (data) => {
      const drafts = data.tracked_drafts || [];
      const newDraft = {
        trackingId: trackingId,
        id: trackingId,
        recipient: draftRecipient,
        subject: draftSubject,
        timestamp: now,
        openCount: 0,
        clickCount: 0,
        lastNotifiedOpenCount: 0,
        lastLocation: {
          city: null,
          country: null
        }
      };

      drafts.unshift(newDraft);
      const cappedDrafts = drafts.slice(0, 100);

      // Maintain legacy list for backward compatibility
      const legacyList = data.recentTrackedEmails || [];
      legacyList.unshift({
        id: trackingId,
        trackingId: trackingId,
        subject: draftSubject,
        recipient: draftRecipient,
        timestamp: new Date(now).toISOString()
      });
      const cappedLegacy = legacyList.slice(0, 100);

      chrome.storage.local.set({
        tracked_drafts: cappedDrafts,
        recentTrackedEmails: cappedLegacy
      });
    });
  }

  function findMessageBody(composeContainer) {
    return composeContainer.querySelector('div[role="textbox"][contenteditable="true"]')
      || composeContainer.querySelector('div[contenteditable="true"][aria-label*="Message Body"]')
      || composeContainer.querySelector('div[g_editable="true"]')
      || composeContainer.querySelector('div[role="textbox"]');
  }

  function findSubject(composeContainer) {
    const subjectInput = composeContainer.querySelector('input[name="subjectbox"]')
      || composeContainer.querySelector('input[name="subject"]')
      || composeContainer.querySelector('input[placeholder="Subject"]')
      || composeContainer.querySelector('input[aria-label*="Subject"]');
    return (subjectInput && subjectInput.value.trim()) ? subjectInput.value.trim() : '(No Subject)';
  }

  function findRecipients(composeContainer) {
    const recipients = new Set();

    // 1. Check span/div email attributes and data hovercards
    const emailElements = composeContainer.querySelectorAll('span[email], div[email], [data-hovercard-id], [peoplekit-id]');
    emailElements.forEach((el) => {
      const email = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || el.getAttribute('peoplekit-id');
      if (email && email.includes('@')) {
        recipients.add(email.trim());
      } else if (el.textContent && el.textContent.includes('@')) {
        const match = el.textContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match) recipients.add(match[0].trim());
      }
    });

    // 2. Check input elements
    if (recipients.size === 0) {
      const inputs = composeContainer.querySelectorAll('input[name="to"], textarea[name="to"], input[aria-label*="To"], input[aria-label*="Recipients"]');
      inputs.forEach((inp) => {
        if (inp.value && inp.value.includes('@')) {
          recipients.add(inp.value.trim());
        }
      });
    }

    // 3. Check modern recipient chips
    if (recipients.size === 0) {
      const chips = composeContainer.querySelectorAll('.vR .vN, [role="option"]');
      chips.forEach((chip) => {
        const text = chip.textContent || '';
        const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match) {
          recipients.add(match[0].trim());
        } else if (text.trim()) {
          recipients.add(text.trim());
        }
      });
    }

    return Array.from(recipients).join(', ') || 'Recipient';
  }

  function wrapOutboundLinks(composeContainer, trackingId) {
    if (!userSettings.backendUrl || !trackingId) return 0;

    const bodyElement = findMessageBody(composeContainer);
    if (!bodyElement) return 0;

    const clickEndpoint = userSettings.backendUrl.replace(/\/api\/track\/?$/, '/api/click');
    const links = bodyElement.querySelectorAll('a[href]');
    let rewrittenCount = 0;

    links.forEach((link) => {
      const originalHref = link.getAttribute('href') || '';
      const trimmedHref = originalHref.trim();

      // Exclusions:
      // 1. Empty or local jump anchors (#...)
      if (!trimmedHref || trimmedHref.startsWith('#')) return;

      // 2. Protocols like mailto:, tel:, sms:
      if (/^(mailto|tel|sms):/i.test(trimmedHref)) return;

      // 3. Already wrapped links
      if (trimmedHref.includes('/api/click') || link.dataset.mailtrackerWrapped === 'true') return;

      // 4. Insecure / script pseudo-protocols
      if (/^(javascript|data|vbscript|file):/i.test(trimmedHref)) return;

      // Construct wrapped URL
      const delimiter = clickEndpoint.includes('?') ? '&' : '?';
      const wrappedUrl = `${clickEndpoint}${delimiter}id=${encodeURIComponent(trackingId)}&url=${encodeURIComponent(trimmedHref)}`;

      link.setAttribute('href', wrappedUrl);
      link.dataset.mailtrackerWrapped = 'true';
      rewrittenCount++;
    });

    return rewrittenCount;
  }

  function injectTrackingPixel(composeContainer, trackingId) {
    if (!userSettings.backendUrl) {
      showGmailToast('⚠️ MailTracker: Please set your Vercel Backend URL in the extension popup.', 'warning');
      return;
    }

    const bodyElement = findMessageBody(composeContainer);
    if (!bodyElement) return;

    if (bodyElement.querySelector('img[data-mailtracker-pixel]')) return;

    let url = userSettings.backendUrl;
    const delimiter = url.includes('?') ? '&' : '?';
    url += `${delimiter}id=${encodeURIComponent(trackingId)}`;

    if (userSettings.webhookUrl) {
      url += `&webhook=${encodeURIComponent(userSettings.webhookUrl)}`;
    }

    // Stealth spacer pixel format (survives Spacemail Jellyfish and corporate spam filters)
    const pixelImg = document.createElement('img');
    pixelImg.src = url;
    pixelImg.setAttribute('data-mailtracker-pixel', trackingId);
    pixelImg.setAttribute('width', '1');
    pixelImg.setAttribute('height', '1');
    pixelImg.setAttribute('border', '0');
    pixelImg.setAttribute('alt', '');
    pixelImg.style.cssText = 'outline:none;text-decoration:none;-ms-interpolation-mode:bicubic;vertical-align:baseline;display:inline-block;border:none;margin:0;padding:0;width:1px;height:1px;';

    bodyElement.appendChild(pixelImg);
  }

  function updateButtonUI(button, isEnabled) {
    if (isEnabled) {
      button.className = 'mailtracker-btn active';
      button.title = 'Open tracking is ON for this email. Click to disable.';
      button.innerHTML = `
        <svg class="mailtracker-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
        <span class="mailtracker-badge">Track ON</span>
      `;
    } else {
      button.className = 'mailtracker-btn inactive';
      button.title = 'Open tracking is OFF for this email. Click to enable.';
      button.innerHTML = `
        <svg class="mailtracker-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
          <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
        <span class="mailtracker-badge">Track OFF</span>
      `;
    }
  }

  function updateLinksButtonUI(button, isEnabled) {
    if (isEnabled) {
      button.className = 'mailtracker-btn mailtracker-links-btn active';
      button.title = 'Link tracking is ON for this email. Click to disable.';
      button.innerHTML = `
        <svg class="mailtracker-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
        </svg>
        <span class="mailtracker-badge">Links ON</span>
      `;
    } else {
      button.className = 'mailtracker-btn mailtracker-links-btn inactive';
      button.title = 'Link tracking is OFF for this email. Click to enable.';
      button.innerHTML = `
        <svg class="mailtracker-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
          <line x1="2" y1="2" x2="22" y2="22"></line>
        </svg>
        <span class="mailtracker-badge">Links OFF</span>
      `;
    }
  }

  function attachSendListeners(composeContainer, sendBtn) {
    if (composeContainer.dataset.mailTrackerListenersAttached) return;
    composeContainer.dataset.mailTrackerListenersAttached = 'true';

    const handleSendAction = () => {
      const isPixelEnabled = composeContainer.dataset.mailTrackerEnabled === 'true';
      const isLinksEnabled = composeContainer.dataset.mailTrackerLinksEnabled === 'true';

      if (!isPixelEnabled && !isLinksEnabled) return;

      const trackingId = generateTrackingId();
      const subject = findSubject(composeContainer);
      const recipient = findRecipients(composeContainer);

      let linksCount = 0;
      if (isLinksEnabled) {
        linksCount = wrapOutboundLinks(composeContainer, trackingId);
      }

      if (isPixelEnabled) {
        injectTrackingPixel(composeContainer, trackingId);
      }

      recordTrackedEmail(trackingId, subject, recipient);

      const statusBadges = [];
      if (isPixelEnabled) statusBadges.push('Pixel attached');
      if (isLinksEnabled && linksCount > 0) statusBadges.push(`${linksCount} link(s) tracked`);
      showGmailToast(`✓ MailTracker: ${statusBadges.join(' • ') || 'Tracking active'} (${trackingId})`, 'success');
    };

    sendBtn.addEventListener('click', handleSendAction, true);
    composeContainer.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        handleSendAction();
      }
    }, true);
  }

  function setupComposeWindow(composeContainer) {
    if (composeContainer.querySelector('.mailtracker-btn')) return;

    const sendBtn = composeContainer.querySelector('div[role="button"][data-tooltip*="Send"]')
      || composeContainer.querySelector('div[role="button"][aria-label*="Send"]')
      || composeContainer.querySelector('.T-I.J-J5-Ji.aoO.v7.T-I-atl.L3')
      || composeContainer.querySelector('.T-I.J-J5-Ji.aoO');

    if (!sendBtn) return;

    const sendParent = sendBtn.closest('td') || sendBtn.closest('.btC') || sendBtn.parentElement;
    if (!sendParent) return;

    // 1. Pixel Tracking Button
    const trackerBtn = document.createElement('div');
    trackerBtn.setAttribute('role', 'button');
    trackerBtn.setAttribute('tabindex', '0');

    let isTrackingActive = userSettings.defaultEnabled;
    composeContainer.dataset.mailTrackerEnabled = isTrackingActive ? 'true' : 'false';
    updateButtonUI(trackerBtn, isTrackingActive);

    trackerBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      isTrackingActive = !isTrackingActive;
      composeContainer.dataset.mailTrackerEnabled = isTrackingActive ? 'true' : 'false';
      updateButtonUI(trackerBtn, isTrackingActive);
    });

    // 2. Link Tracking Button
    const linksBtn = document.createElement('div');
    linksBtn.setAttribute('role', 'button');
    linksBtn.setAttribute('tabindex', '0');

    let isLinksActive = userSettings.trackLinksEnabled;
    composeContainer.dataset.mailTrackerLinksEnabled = isLinksActive ? 'true' : 'false';
    updateLinksButtonUI(linksBtn, isLinksActive);

    linksBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      isLinksActive = !isLinksActive;
      composeContainer.dataset.mailTrackerLinksEnabled = isLinksActive ? 'true' : 'false';
      updateLinksButtonUI(linksBtn, isLinksActive);
    });

    if (sendBtn.nextSibling) {
      sendBtn.parentNode.insertBefore(trackerBtn, sendBtn.nextSibling);
      sendBtn.parentNode.insertBefore(linksBtn, trackerBtn.nextSibling);
    } else {
      sendParent.appendChild(trackerBtn);
      sendParent.appendChild(linksBtn);
    }

    attachSendListeners(composeContainer, sendBtn);
  }

  /* ==========================================================================
     DOM Mutation Scanning Loop
     ========================================================================== */
  function scanGmailDom() {
    // 1. Scan for Compose Windows (Outbound)
    const composeContainers = document.querySelectorAll(
      'div[role="dialog"], div.M9, div.AD, div.ip.iS, .aoI, .nH.Hd'
    );
    composeContainers.forEach((container) => {
      if (container.querySelector('div[role="textbox"]') || container.querySelector('[data-tooltip*="Send"]')) {
        setupComposeWindow(container);
      }
    });

    // 2. Scan for Opened Emails in Reading View (Inbound Forensics)
    const emailContainers = document.querySelectorAll(
      '.adn.ads, .gE.iv.gt, div[data-message-id], div[data-legacy-message-id]'
    );
    emailContainers.forEach((emailContainer) => {
      injectInboundForensicsButton(emailContainer);
    });
  }

  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) {
      scanGmailDom();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanGmailDom);
  } else {
    scanGmailDom();
  }

  /* ==========================================================================
     Extension Message Listener for Popup Interaction
     ========================================================================== */
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'FETCH_RAW_HEADERS' || request.action === 'FETCH_ACTIVE_EMAIL_HEADERS') {
      const emailContainers = document.querySelectorAll(
        '.adn.ads, .gE.iv.gt, div[data-message-id], div[data-legacy-message-id]'
      );
      let targetMessageId = null;

      for (const container of emailContainers) {
        const resolvedId = resolveMessageIdFromElement(container);
        if (resolvedId) {
          targetMessageId = resolvedId;
          break;
        }
      }

      if (!targetMessageId) {
        sendResponse({ success: false, error: 'No active email found open in Gmail view.' });
        return true;
      }

      const accountIndex = getGmailAccountIndex();
      chrome.runtime.sendMessage(
        { action: 'FETCH_RAW_HEADERS', messageId: targetMessageId, accountIndex },
        (res) => {
          sendResponse(res);
        }
      );
      return true;
    }

    if (request.type === 'QUERY_COMPOSE_METADATA') {
      const composeContainers = document.querySelectorAll(
        'div[role="dialog"], div.M9, div.AD, div.ip.iS, .aoI, .nH.Hd'
      );
      let to = '';
      let subject = '';
      for (const container of composeContainers) {
        if (container.querySelector('div[role="textbox"]') || container.querySelector('[data-tooltip*="Send"]')) {
          to = findRecipients(container);
          subject = findSubject(container);
          break;
        }
      }
      sendResponse({ success: true, to, subject });
      return true;
    }

    if (request.type === 'INJECT_TRACKER_TO_COMPOSE') {
      const composeContainers = document.querySelectorAll(
        'div[role="dialog"], div.M9, div.AD, div.ip.iS, .aoI, .nH.Hd'
      );
      let injected = false;
      const trkId = request.trackingId || generateTrackingId();
      for (const container of composeContainers) {
        if (container.querySelector('div[role="textbox"]') || container.querySelector('[data-tooltip*="Send"]')) {
          if (request.pixel !== false) {
            injectTrackingPixel(container, trkId);
          }
          if (request.links !== false) {
            wrapOutboundLinks(container, trkId);
          }
          const s = findSubject(container);
          const r = findRecipients(container);
          recordTrackedEmail(trkId, s, r);
          injected = true;
          break;
        }
      }
      sendResponse({ success: injected, trackingId: trkId });
      return true;
    }
  });

  console.log("[Atelier's MailTracker] Suite initialized on Gmail (Inbound Intelligence + Outbound Beacon).");
})();
