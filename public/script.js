/* ═══════════════════════════════════════════════════
   PHISHGUARD — Frontend Script
   URL Analyzer, History, Dashboard, Animations
═══════════════════════════════════════════════════ */

"use strict";

// ── CONFIG ──────────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:3000/api";
const USE_BACKEND = false; // Set to true when backend is running

// ── STATE ────────────────────────────────────────────────────────────────────
let scanHistory = JSON.parse(localStorage.getItem("phishguard_history") || "[]");
let currentFilter = "all";

// ── DOM REFS ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const urlInput    = $("urlInput");
const analyzeBtn  = $("analyzeBtn");
const resetBtn    = $("resetBtn");
const clearBtn    = $("clearBtn");
const scanBar     = $("scanBar");
const resultCard  = $("resultCard");
const historyBody = $("historyBody");
const historySearch = $("historySearch");
const toast       = $("toast");
const themeToggle = $("themeToggle");

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  spawnParticles();
  animateHeroCounters();
  renderHistory();
  updateDashboard();
  setupEventListeners();
  animateNavOnScroll();
});

// ── EVENT LISTENERS ──────────────────────────────────────────────────────────
function setupEventListeners() {
  analyzeBtn.addEventListener("click", handleAnalyze);
  resetBtn.addEventListener("click", handleReset);
  clearBtn.addEventListener("click", () => { urlInput.value = ""; urlInput.focus(); });
  urlInput.addEventListener("keydown", e => { if (e.key === "Enter") handleAnalyze(); });

  $("copyBtn").addEventListener("click", copyResult);
  $("downloadBtn").addEventListener("click", downloadReport);
  $("clearHistoryBtn").addEventListener("click", clearHistory);

  historySearch.addEventListener("input", () => renderHistory());

  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      renderHistory();
    });
  });

  themeToggle.addEventListener("click", toggleTheme);
}

// ── ANALYZE ──────────────────────────────────────────────────────────────────
async function handleAnalyze() {
  const url = urlInput.value.trim();
  if (!url) { showToast("Please enter a URL to analyze", "error"); urlInput.focus(); return; }
  if (!isValidURL(url)) { showToast("Please enter a valid URL format", "error"); return; }

  setLoading(true);
  scanBar.style.display = "block";
  resultCard.style.display = "none";

  try {
    let result;
    if (USE_BACKEND) {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      if (!res.ok) throw new Error("Backend error");
      result = await res.json();
    } else {
      result = await localAnalyze(url);
    }

    await runScanAnimation(result);
    displayResult(result);
    addToHistory(result);
    updateDashboard();
    showToast("Analysis complete!", "success");
  } catch (err) {
    console.error(err);
    showToast("Analysis failed. Using local engine.", "error");
    const result = await localAnalyze(url);
    await runScanAnimation(result);
    displayResult(result);
    addToHistory(result);
    updateDashboard();
  } finally {
    setLoading(false);
  }
}

function handleReset() {
  urlInput.value = "";
  scanBar.style.display = "none";
  resultCard.style.display = "none";
  urlInput.focus();
}

// ── LOCAL ANALYSIS ENGINE ─────────────────────────────────────────────────────
async function localAnalyze(url) {
  await delay(200); // simulate async

  const indicators = {};
  let riskScore = 0;
  const reasons = [];

  const lower = url.toLowerCase();
  const normalizedUrl = lower.startsWith("http") ? lower : "http://" + lower;
  let hostname = "";
  try {
    hostname = new URL(normalizedUrl).hostname;
  } catch { hostname = url; }

  // 1. SSL Check
  indicators.ssl = !lower.startsWith("https://");
  if (indicators.ssl) { riskScore += 20; reasons.push("No HTTPS/SSL encryption detected"); }

  // 2. IP Address URL
  indicators.ipAddress = /^https?:\/\/\d{1,3}(\.\d{1,3}){3}([:\/]|$)/.test(lower) || /^\d{1,3}(\.\d{1,3}){3}/.test(hostname);
  if (indicators.ipAddress) { riskScore += 35; reasons.push("IP address used instead of domain name"); }

  // 3. Suspicious Keywords
  const suspiciousKeywords = ["login", "verify", "secure", "account", "update", "confirm", "bank", "paypal", "password", "credential", "signin", "wallet", "alert", "suspend", "unlock", "billing", "invoice"];
  const foundKeywords = suspiciousKeywords.filter(k => lower.includes(k));
  indicators.keywords = foundKeywords.length > 0;
  if (indicators.keywords) { riskScore += Math.min(foundKeywords.length * 8, 30); reasons.push(`Suspicious keywords: ${foundKeywords.slice(0,3).join(", ")}`); }

  // 4. Shortened URL
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "short.link", "rb.gy", "cutt.ly"];
  indicators.shortened = shorteners.some(s => hostname.includes(s));
  if (indicators.shortened) { riskScore += 25; reasons.push("URL shortener service detected — masks true destination"); }

  // 5. Excessive subdomains / fake domain pattern
  const parts = hostname.split(".");
  const hasManySubdomains = parts.length > 4;
  const fakePatterns = ["paypal-", "amazon-", "google-", "apple-", "microsoft-", "netflix-", "bankof", "-secure", "-login", "-verify", "account-"];
  const hasFakePattern = fakePatterns.some(p => lower.includes(p)) || (parts.length > 3 && ["paypal","amazon","google","apple"].some(b => lower.includes(b)));
  indicators.fakeDomain = hasManySubdomains || hasFakePattern;
  if (indicators.fakeDomain) { riskScore += 30; reasons.push("Suspicious domain pattern resembling a legitimate brand"); }

  // 6. URL Length
  indicators.longUrl = url.length > 100;
  if (indicators.longUrl) { riskScore += 15; reasons.push(`Excessive URL length (${url.length} chars) — common obfuscation technique`); }

  // 7. Special characters & encoding
  const specialChars = (url.match(/[@%~]/g) || []).length;
  indicators.specialChars = specialChars > 1;
  if (indicators.specialChars) { riskScore += 10; reasons.push("Unusual special characters in URL structure"); }

  // 8. Multiple hyphens or numbers
  const hyphenCount = (hostname.match(/-/g) || []).length;
  indicators.hyphens = hyphenCount > 3;
  if (indicators.hyphens) { riskScore += 10; reasons.push("Multiple hyphens in domain — common phishing pattern"); }

  riskScore = Math.min(riskScore, 100);

  // Determine threat level
  let status, threatLevel, icon;
  if (riskScore <= 15) { status = "Safe"; threatLevel = "Safe"; icon = "✅"; }
  else if (riskScore <= 35) { status = "Low Risk"; threatLevel = "Low Risk"; icon = "🟡"; }
  else if (riskScore <= 55) { status = "Suspicious"; threatLevel = "Medium Risk"; icon = "⚠️"; }
  else if (riskScore <= 75) { status = "Malicious"; threatLevel = "High Risk"; icon = "🚨"; }
  else { status = "Malicious"; threatLevel = "Critical Risk"; icon = "💀"; }

  const reason = reasons.length > 0
    ? reasons.join(". ") + "."
    : "No significant threats detected. URL appears safe based on structural analysis.";

  return { url, status, riskScore, threatLevel, reason, indicators, icon, timestamp: new Date().toISOString() };
}

// ── SCAN ANIMATION ────────────────────────────────────────────────────────────
async function runScanAnimation(result) {
  const fill   = $("scanFill");
  const pct    = $("scanPct");
  const text   = $("scanText");
  const steps  = document.querySelectorAll(".scan-steps .step");

  const phases = [
    { label: "DNS Lookup & domain resolution...", pct: 15 },
    { label: "Regex pattern validation...", pct: 35 },
    { label: "Suspicious keyword detection...", pct: 55 },
    { label: "SSL certificate validation...", pct: 75 },
    { label: "AI risk scoring...", pct: 100 }
  ];

  steps.forEach(s => s.classList.remove("active","done"));

  for (let i = 0; i < phases.length; i++) {
    const phase = phases[i];
    text.textContent = phase.label;
    fill.style.width = phase.pct + "%";
    pct.textContent = phase.pct + "%";
    if (steps[i]) { steps[i].classList.add("active"); }
    if (i > 0 && steps[i-1]) { steps[i-1].classList.remove("active"); steps[i-1].classList.add("done"); }
    await delay(480);
  }
  await delay(300);
}

// ── DISPLAY RESULT ────────────────────────────────────────────────────────────
function displayResult(data) {
  resultCard.style.display = "block";

  // Remove previous state classes
  resultCard.className = "result-card";
  const classMap = { "Safe": "safe", "Low Risk": "low", "Suspicious": "suspicious", "Malicious": "malicious" };
  const levelClassMap = { "Safe": "safe", "Low Risk": "low", "Medium Risk": "medium", "High Risk": "high", "Critical Risk": "critical" };

  const cardClass = ["Safe","Low Risk"].includes(data.status) ? "safe" : (data.status === "Suspicious" ? "suspicious" : "malicious");
  resultCard.classList.add(cardClass);

  $("resultIcon").textContent = data.icon || "🔍";
  $("resultStatus").textContent = data.status;
  $("resultUrl").textContent = data.url;
  $("reasonText").textContent = data.reason;

  // Risk score animation
  let current = 0;
  const target = data.riskScore;
  const scoreEl = $("riskScoreNum");
  const fill    = $("riskFill");
  const timer = setInterval(() => {
    current = Math.min(current + 2, target);
    scoreEl.textContent = current;
    fill.style.width = current + "%";
    if (current >= target) clearInterval(timer);
  }, 20);

  // Risk fill class
  fill.className = "risk-fill";
  if (target <= 15) fill.classList.add("safe");
  else if (target <= 35) fill.classList.add("low");
  else if (target <= 55) fill.classList.add("medium");
  else if (target <= 75) fill.classList.add("high");
  else fill.classList.add("critical");

  // Threat badge
  const badge = $("threatBadge");
  badge.className = "threat-level-badge";
  const levelClass = levelClassMap[data.threatLevel] || "safe";
  badge.classList.add(levelClass);
  $("threatIcon").textContent = data.icon || "●";
  $("threatLevelText").textContent = data.threatLevel;

  // Indicators grid
  const grid = $("indicatorsGrid");
  const indDefs = [
    { key: "keywords",    label: "Suspicious Keywords" },
    { key: "ipAddress",   label: "IP Address URL" },
    { key: "shortened",   label: "Shortened Link" },
    { key: "fakeDomain",  label: "Fake Domain Pattern" },
    { key: "ssl",         label: "No SSL / HTTP" },
    { key: "longUrl",     label: "Excessive URL Length" },
    { key: "specialChars",label: "Special Characters" },
    { key: "hyphens",     label: "Suspicious Hyphens" }
  ];
  grid.innerHTML = indDefs.map(d => {
    const detected = data.indicators && data.indicators[d.key];
    return `<div class="indicator-item ${detected ? "detected" : "clear"}">
      <span class="ind-dot"></span>
      <span>${d.label}</span>
      <span style="margin-left:auto;font-size:0.75rem;font-family:var(--font-mono);">${detected ? "DETECTED" : "CLEAR"}</span>
    </div>`;
  }).join("");

  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── HISTORY ───────────────────────────────────────────────────────────────────
function addToHistory(result) {
  scanHistory.unshift(result);
  if (scanHistory.length > 100) scanHistory.pop();
  localStorage.setItem("phishguard_history", JSON.stringify(scanHistory));
  renderHistory();
}

function renderHistory() {
  const query = historySearch.value.trim().toLowerCase();
  const filtered = scanHistory.filter(item => {
    const matchFilter = currentFilter === "all" ||
      (currentFilter === "safe" && ["Safe","Low Risk"].includes(item.status)) ||
      (currentFilter === "suspicious" && item.status === "Suspicious") ||
      (currentFilter === "malicious" && item.status === "Malicious");
    const matchSearch = !query || item.url.toLowerCase().includes(query);
    return matchFilter && matchSearch;
  });

  if (filtered.length === 0) {
    historyBody.innerHTML = `<div class="empty-state"><div class="empty-icon">📡</div><p>${query ? "No results found." : "No scans yet. Analyze a URL to begin."}</p></div>`;
    return;
  }

  const statusClass = s => {
    if (["Safe","Low Risk"].includes(s)) return "safe";
    if (s === "Suspicious") return "suspicious";
    return "malicious";
  };

  historyBody.innerHTML = filtered.map((item, i) => `
    <div class="table-row" onclick="reScan('${escapeAttr(item.url)}')">
      <span class="row-url" title="${escapeHtml(item.url)}">${escapeHtml(truncate(item.url, 55))}</span>
      <span class="row-status ${statusClass(item.status)}">${escapeHtml(item.status)}</span>
      <span class="row-score" style="color:${riskColor(item.riskScore)}">${item.riskScore}/100</span>
      <span class="row-threat">${escapeHtml(item.threatLevel)}</span>
      <span class="row-time">${formatTime(item.timestamp)}</span>
    </div>
  `).join("");
}

function reScan(url) {
  urlInput.value = url;
  document.getElementById("analyzer").scrollIntoView({ behavior: "smooth" });
}

function clearHistory() {
  if (!confirm("Clear all scan history?")) return;
  scanHistory = [];
  localStorage.removeItem("phishguard_history");
  renderHistory();
  updateDashboard();
  showToast("History cleared", "success");
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function updateDashboard() {
  const safe       = scanHistory.filter(i => ["Safe","Low Risk"].includes(i.status)).length;
  const suspicious = scanHistory.filter(i => i.status === "Suspicious").length;
  const malicious  = scanHistory.filter(i => i.status === "Malicious").length;
  const total      = scanHistory.length;

  $("statSafe").textContent       = safe;
  $("statSuspicious").textContent = suspicious;
  $("statMalicious").textContent  = malicious;
  $("statTotal").textContent      = total;

  const p = n => total > 0 ? Math.round((n / total) * 100) : 0;
  $("barSafe").style.width       = p(safe) + "%";
  $("barSuspicious").style.width = p(suspicious) + "%";
  $("barMalicious").style.width  = p(malicious) + "%";

  // Indicator counts
  const counts = { keywords:0, ipAddress:0, shortened:0, fakeDomain:0, ssl:0, longUrl:0 };
  scanHistory.forEach(i => {
    if (i.indicators) Object.keys(counts).forEach(k => { if (i.indicators[k]) counts[k]++; });
  });
  $("li-keywords").textContent = counts.keywords;
  $("li-ip").textContent       = counts.ipAddress;
  $("li-short").textContent    = counts.shortened;
  $("li-fake").textContent     = counts.fakeDomain;
  $("li-ssl").textContent      = counts.ssl;
  $("li-length").textContent   = counts.longUrl;

  // Donut chart
  updateDonut(safe, suspicious, malicious, total);
}

function updateDonut(safe, suspicious, malicious, total) {
  const circumference = 283;
  const safeRatio       = total > 0 ? safe / total : 0;
  const suspiciousRatio = total > 0 ? suspicious / total : 0;
  const maliciousRatio  = total > 0 ? malicious / total : 0;

  const safeDash = safeRatio * circumference;
  const suspDash = suspiciousRatio * circumference;
  const malDash  = maliciousRatio * circumference;

  const safeEl = $("donutSafe");
  const suspEl = $("donutSuspicious");
  const malEl  = $("donutMalicious");

  // Stacked: safe starts at top, suspicious after safe, malicious after suspicious
  safeEl.setAttribute("stroke-dasharray", `${safeDash} ${circumference - safeDash}`);
  safeEl.setAttribute("stroke-dashoffset", circumference);
  safeEl.style.transition = "stroke-dasharray 1s ease";

  const suspOffset = circumference - safeDash;
  suspEl.setAttribute("stroke-dasharray", `${suspDash} ${circumference - suspDash}`);
  suspEl.setAttribute("stroke-dashoffset", suspOffset);
  suspEl.style.transition = "stroke-dasharray 1s ease, stroke-dashoffset 1s ease";

  const malOffset = circumference - safeDash - suspDash;
  malEl.setAttribute("stroke-dasharray", `${malDash} ${circumference - malDash}`);
  malEl.setAttribute("stroke-dashoffset", malOffset);
  malEl.style.transition = "stroke-dasharray 1s ease, stroke-dashoffset 1s ease";

  $("donutLabel").textContent = total;
}

// ── COPY & DOWNLOAD ───────────────────────────────────────────────────────────
function copyResult() {
  const url    = $("resultUrl").textContent;
  const status = $("resultStatus").textContent;
  const score  = $("riskScoreNum").textContent;
  const threat = $("threatLevelText").textContent;
  const reason = $("reasonText").textContent;

  const text = `PhishGuard Scan Report\n${"─".repeat(40)}\nURL: ${url}\nStatus: ${status}\nRisk Score: ${score}/100\nThreat Level: ${threat}\nAnalysis: ${reason}\nScanned: ${new Date().toLocaleString()}`;
  navigator.clipboard.writeText(text).then(() => showToast("Report copied!", "success")).catch(() => showToast("Copy failed", "error"));
}

function downloadReport() {
  const url    = $("resultUrl").textContent;
  const status = $("resultStatus").textContent;
  const score  = $("riskScoreNum").textContent;
  const threat = $("threatLevelText").textContent;
  const reason = $("reasonText").textContent;
  const time   = new Date().toLocaleString();

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PhishGuard Report</title>
<style>
  body{font-family:monospace;background:#050b12;color:#e2f0ff;padding:40px;max-width:700px;margin:0 auto;}
  h1{color:#00f5ff;letter-spacing:3px;margin-bottom:4px;}
  .sub{color:rgba(226,240,255,0.4);font-size:0.8rem;margin-bottom:32px;}
  .row{display:flex;gap:16px;border-bottom:1px solid rgba(0,245,255,0.1);padding:12px 0;}
  .label{color:#00f5ff;min-width:140px;font-size:0.85rem;}
  .value{color:#e2f0ff;font-size:0.95rem;word-break:break-all;}
  .badge{display:inline-block;padding:4px 14px;border-radius:100px;font-size:0.8rem;margin-top:8px;}
  .safe{background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.4);}
  .medium{background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.4);}
  .malicious,.high,.critical{background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.4);}
  .footer{margin-top:40px;color:rgba(226,240,255,0.3);font-size:0.75rem;text-align:center;}
</style></head>
<body>
  <h1>PHISHGUARD</h1>
  <div class="sub">AI Phishing URL Detection Report • ${time}</div>
  <div class="row"><span class="label">URL Analyzed</span><span class="value">${escapeHtml(url)}</span></div>
  <div class="row"><span class="label">Detection Status</span><span class="value">${escapeHtml(status)}</span></div>
  <div class="row"><span class="label">Risk Score</span><span class="value">${escapeHtml(score)} / 100</span></div>
  <div class="row"><span class="label">Threat Level</span><span class="value"><span class="badge">${escapeHtml(threat)}</span></span></div>
  <div class="row"><span class="label">Analysis</span><span class="value">${escapeHtml(reason)}</span></div>
  <div class="footer">Generated by PhishGuard — AI Threat Intelligence Platform</div>
</body></html>`;

  const blob = new Blob([html], { type: "text/html" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `phishguard-report-${Date.now()}.html`;
  a.click();
  showToast("Report downloaded!", "success");
}

// ── THEME TOGGLE ──────────────────────────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const isLight = html.dataset.theme === "light";
  html.dataset.theme = isLight ? "dark" : "light";
  themeToggle.querySelector(".toggle-icon").textContent = isLight ? "☀" : "🌙";
  localStorage.setItem("phishguard_theme", html.dataset.theme);
}

// ── PARTICLES ─────────────────────────────────────────────────────────────────
function spawnParticles() {
  const container = $("particles");
  const colors = ["#00f5ff","#7c3aed","#10b981","#ef4444"];
  for (let i = 0; i < 30; i++) {
    const p = document.createElement("div");
    p.className = "particle";
    const size = Math.random() * 3 + 1;
    p.style.cssText = `
      width:${size}px; height:${size}px;
      left:${Math.random()*100}%;
      background:${colors[Math.floor(Math.random()*colors.length)]};
      animation-duration:${8 + Math.random()*12}s;
      animation-delay:${Math.random()*10}s;
      box-shadow: 0 0 ${size*2}px currentColor;
    `;
    container.appendChild(p);
  }
}

// ── HERO COUNTER ANIMATION ────────────────────────────────────────────────────
function animateHeroCounters() {
  document.querySelectorAll(".hstat-num[data-count]").forEach(el => {
    const target = parseInt(el.dataset.count);
    const duration = 2000;
    const start = performance.now();
    function step(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.floor(eased * target).toLocaleString();
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });
}

// ── NAVBAR SCROLL ─────────────────────────────────────────────────────────────
function animateNavOnScroll() {
  const nav = $("navbar");
  window.addEventListener("scroll", () => {
    nav.style.boxShadow = window.scrollY > 20
      ? "0 4px 40px rgba(0,0,0,0.5)"
      : "none";
  }, { passive: true });
}

// ── LOADING STATE ─────────────────────────────────────────────────────────────
function setLoading(loading) {
  const btnText    = analyzeBtn.querySelector(".btn-text");
  const btnSpinner = analyzeBtn.querySelector(".btn-spinner");
  analyzeBtn.disabled = loading;
  btnText.style.display    = loading ? "none" : "inline";
  btnSpinner.style.display = loading ? "inline-flex" : "none";
}

// ── TOAST ─────────────────────────────────────────────────────────────────────
function showToast(msg, type = "") {
  toast.textContent = msg;
  toast.className = `toast ${type} show`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toast.classList.remove("show"), 3000);
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function isValidURL(url) {
  try {
    const u = url.startsWith("http") ? url : "http://" + url;
    new URL(u);
    return true;
  } catch { return false; }
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function truncate(str, n) { return str.length > n ? str.slice(0, n) + "…" : str; }

function escapeHtml(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function escapeAttr(str) {
  return String(str).replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function riskColor(score) {
  if (score <= 15) return "var(--green)";
  if (score <= 35) return "#84cc16";
  if (score <= 55) return "var(--orange)";
  if (score <= 75) return "#f97316";
  return "var(--red)";
}

function formatTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
  } catch { return "—"; }
}

// ── RESTORE THEME ─────────────────────────────────────────────────────────────
const savedTheme = localStorage.getItem("phishguard_theme");
if (savedTheme) {
  document.documentElement.dataset.theme = savedTheme;
  themeToggle && (themeToggle.querySelector(".toggle-icon").textContent = savedTheme === "light" ? "🌙" : "☀");
}
