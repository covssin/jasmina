/* static/js/app.js */

(() => {
  const configEl = document.getElementById("app-config");
  const config = configEl ? JSON.parse(configEl.textContent) : {};

  const currentLang = config.lang || "pl";
  const defaultTtl = Number(config.ttl_seconds) || 1800;
  const T = config.translations || {};

  let currentToken = null;
  let pollInterval = null;
  let timerInterval = null;
  let remainingSeconds = defaultTtl;
  let lastReportData = null;

  const btnGenerate = document.getElementById("btn-generate");
  const btnNewSession = document.getElementById("btn-new-session");
  const btnCopyAddress = document.getElementById("btn-copy-address");
  const sessionBox = document.getElementById("session-box");
  const addressEl = document.getElementById("audit-address");
  const timerEl = document.getElementById("countdown-timer");
  const statusMsgEl = document.getElementById("status-message");
  const waitingHintEl = document.getElementById("waiting-hint");
  const reportWrapper = document.getElementById("report-wrapper");
  const recsContainer = document.getElementById("recommendations-list");

  function formatTime(sec) {
    const m = String(Math.floor(sec / 60)).padStart(2, "0");
    const s = String(sec % 60).padStart(2, "0");
    return `${m}:${s}`;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function copyText(text, btn) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = T.btn_copied;
      setTimeout(() => {
        btn.textContent = orig;
      }, 1600);
    });
  }

  function switchLanguage(lang) {
    if (lang === currentLang) return;
    const url = new URL(window.location.href);
    url.searchParams.set("lang", lang);
    window.location.href = url.toString();
  }

  function startTimers() {
    clearInterval(timerInterval);
    clearInterval(pollInterval);

    timerInterval = setInterval(() => {
      if (remainingSeconds > 0) {
        remainingSeconds -= 1;
        timerEl.textContent = formatTime(remainingSeconds);
      } else {
        clearInterval(timerInterval);
        clearInterval(pollInterval);
        statusMsgEl.textContent = T.status_expired;
        waitingHintEl.hidden = true;
      }
    }, 1000);

    pollInterval = setInterval(pollStatus, 3000);
  }

  async function startNewAudit() {
    clearInterval(pollInterval);
    clearInterval(timerInterval);
    reportWrapper.hidden = true;
    lastReportData = null;

    const res = await fetch("/api/session", { method: "POST" });
    if (!res.ok) return;
    const data = await res.json();

    currentToken = data.token;
    remainingSeconds = defaultTtl;
    sessionStorage.setItem("jasmina_token", currentToken);

    addressEl.textContent = data.address;
    timerEl.textContent = formatTime(remainingSeconds);
    statusMsgEl.innerHTML = `<span class="spinner-dot"></span><span>${escapeHtml(T.status_waiting)}</span>`;
    waitingHintEl.hidden = false;
    sessionBox.hidden = false;
    btnGenerate.hidden = true;

    startTimers();
  }

  async function pollStatus() {
    if (!currentToken) return;
    try {
      const res = await fetch(`/api/status/${encodeURIComponent(currentToken)}?lang=${encodeURIComponent(currentLang)}`);
      if (!res.ok) return;
      const data = await res.json();

      if (typeof data.remaining_seconds === "number") {
        remainingSeconds = data.remaining_seconds;
        timerEl.textContent = formatTime(remainingSeconds);
      }

      if (data.status === "completed" && data.report) {
        clearInterval(pollInterval);
        statusMsgEl.innerHTML = `<strong style="color: var(--pass);">✓ ${escapeHtml(T.status_done)}</strong>`;
        waitingHintEl.hidden = true;
        lastReportData = data.report;
        renderReport(data.report);
      } else if (data.status === "expired") {
        clearInterval(pollInterval);
        clearInterval(timerInterval);
        statusMsgEl.textContent = T.status_expired;
        waitingHintEl.hidden = true;
      }
    } catch (err) {
      console.error("Polling error:", err);
    }
  }

  function localizeField(field) {
    if (!field) return "";
    if (typeof field === "object") {
      return field[currentLang] || field.pl || "";
    }
    return String(field);
  }

  function renderReport(report) {
    reportWrapper.hidden = false;

    const score = report.score ?? "—";
    document.getElementById("score-badge").textContent = `${T.score_label} ${score}`;

    const meta = report.meta || {};
    document.getElementById("meta-grid").innerHTML = `
      <div class="meta-item"><span>${escapeHtml(T.sender_label)}</span><strong>${escapeHtml(meta.from || "—")}</strong></div>
      <div class="meta-item"><span>${escapeHtml(T.envelope_label)}</span><strong>${escapeHtml(meta.mail_from || "—")}</strong></div>
      <div class="meta-item"><span>${escapeHtml(T.ip_label)}</span><strong>${escapeHtml(meta.client_ip || "—")}</strong></div>
      <div class="meta-item"><span>${escapeHtml(T.tls_label)}</span><strong>${escapeHtml(meta.tls || "—")}</strong></div>
    `;

    const checks = report.checks || [];
    document.getElementById("checks-grid").innerHTML = checks.map((c) => {
      const st = (c.status || "warn").toLowerCase();
      const pillClass = st === "pass" ? "pill-pass" : (st === "fail" ? "pill-fail" : "pill-warn");
      const pillText = st === "pass" ? T.check_pass : (st === "fail" ? T.check_fail : T.check_warn);
      const msg = localizeField(c.message);

      return `
        <div class="check-card">
          <div class="check-head">
            <span class="check-name">${escapeHtml(c.name || "")}</span>
            <span class="pill ${pillClass}">${escapeHtml(pillText)}</span>
          </div>
          <p class="check-desc">${escapeHtml(msg)}</p>
        </div>
      `;
    }).join("");

    const recs = report.recommendations || [];
    if (!recs.length) {
      recsContainer.innerHTML = `<p style="color: var(--pass); margin: 0;">✓ ${escapeHtml(T.no_missing_records)}</p>`;
    } else {
      recsContainer.innerHTML = recs.map((r, idx) => {
        const title = localizeField(r.title);
        const desc = localizeField(r.description);
        const critClass = r.severity === "critical" ? "critical" : "";
        const dnsBlock = r.suggested_dns
          ? `
            <div class="rec-dns">
              <code>${escapeHtml(r.suggested_dns)}</code>
              <button type="button" class="btn-secondary" data-copy-dns-idx="${idx}">${escapeHtml(T.btn_copy)}</button>
            </div>
          `
          : "";

        return `
          <div class="rec-item ${critClass}">
            <div class="rec-header"><strong>${escapeHtml(title)}</strong></div>
            <div class="rec-desc">${escapeHtml(desc)}</div>
            ${dnsBlock}
          </div>
        `;
      }).join("");
    }

    document.getElementById("raw-headers").textContent = report.raw_headers || "—";
    document.getElementById("raw-json").textContent = JSON.stringify(report, null, 2);
  }

  async function restoreSession() {
    const savedToken = sessionStorage.getItem("jasmina_token");
    if (!savedToken) return;

    try {
      const res = await fetch(`/api/status/${encodeURIComponent(savedToken)}?lang=${encodeURIComponent(currentLang)}`);
      if (!res.ok) {
        sessionStorage.removeItem("jasmina_token");
        return;
      }

      const data = await res.json();
      if (data.status === "expired") {
        sessionStorage.removeItem("jasmina_token");
        return;
      }

      currentToken = data.token;
      addressEl.textContent = data.address;
      remainingSeconds = data.remaining_seconds ?? 0;
      timerEl.textContent = formatTime(remainingSeconds);
      sessionBox.hidden = false;
      btnGenerate.hidden = true;

      if (data.status === "completed" && data.report) {
        statusMsgEl.innerHTML = `<strong style="color: var(--pass);">✓ ${escapeHtml(T.status_done)}</strong>`;
        waitingHintEl.hidden = true;
        lastReportData = data.report;
        renderReport(data.report);
      } else {
        startTimers();
      }
    } catch (err) {
      console.error("Restore session error:", err);
    }
  }

  // Event listeners
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchLanguage(btn.dataset.lang));
  });

  btnGenerate.addEventListener("click", startNewAudit);
  btnNewSession.addEventListener("click", startNewAudit);
  btnCopyAddress.addEventListener("click", () => copyText(addressEl.textContent, btnCopyAddress));

  recsContainer.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-copy-dns-idx]");
    if (!btn || !lastReportData?.recommendations) return;
    const idx = Number(btn.dataset.copyDnsIdx);
    const dns = lastReportData.recommendations[idx]?.suggested_dns;
    if (dns) copyText(dns, btn);
  });

  window.addEventListener("DOMContentLoaded", restoreSession);
})();