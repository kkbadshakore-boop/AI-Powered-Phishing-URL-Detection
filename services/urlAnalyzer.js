/**
 * PhishGuard — URL Analyzer Service
 * Multi-layer threat detection engine
 */

"use strict";

// ── CONSTANTS ─────────────────────────────────────────────────────────────────
const SUSPICIOUS_KEYWORDS = [
  "login","verify","secure","account","update","confirm","bank",
  "paypal","password","credential","signin","wallet","alert",
  "suspend","unlock","billing","invoice","click","free","prize",
  "urgent","limited","expire","security","validate","authorize",
];

const URL_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
  "buff.ly","short.link","rb.gy","cutt.ly","tiny.cc","adf.ly",
  "bc.vc","u.to","x.co","shorturl.at","soo.gd",
]);

const TRUSTED_DOMAINS = new Set([
  "google.com","microsoft.com","apple.com","github.com","amazon.com",
  "facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com",
  "wikipedia.org","stackoverflow.com","anthropic.com","openai.com",
]);

const FAKE_BRAND_PATTERNS = [
  /paypal[\-_\.]/i, /[\-_\.]paypal/i,
  /amazon[\-_\.]/i, /[\-_\.]amazon/i,
  /google[\-_\.]/i, /[\-_\.]google/i,
  /apple[\-_\.]/i,  /[\-_\.]apple/i,
  /microsoft[\-_\.]/i, /[\-_\.]microsoft/i,
  /netflix[\-_\.]/i, /[\-_\.]netflix/i,
  /bankof/i, /[\-_\.]secure[\-_\.]/i, /[\-_\.]login[\-_\.]/i,
];

// ── VALIDATE ──────────────────────────────────────────────────────────────────
function validateUrl(url) {
  try {
    const normalized = url.startsWith("http") ? url : "http://" + url;
    const parsed = new URL(normalized);
    return parsed.hostname.includes(".") || /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname);
  } catch {
    return false;
  }
}

// ── MAIN ANALYZER ─────────────────────────────────────────────────────────────
async function analyzeUrl(url) {
  const lower  = url.toLowerCase();
  const normalized = lower.startsWith("http") ? lower : "http://" + lower;

  let parsed, hostname, pathname;
  try {
    const u = new URL(normalized);
    hostname = u.hostname;
    pathname = u.pathname + u.search;
  } catch {
    hostname = url;
    pathname = "";
  }

  const indicators = {};
  let riskScore = 0;
  const reasons = [];

  // ── 1. SSL / HTTPS ──────────────────────────────────────────────────────
  indicators.ssl = !lower.startsWith("https://");
  if (indicators.ssl) {
    riskScore += 20;
    reasons.push("No HTTPS/SSL encryption — data transmitted in plaintext");
  }

  // ── 2. IP Address ────────────────────────────────────────────────────────
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  indicators.ipAddress = ipRegex.test(hostname);
  if (indicators.ipAddress) {
    riskScore += 35;
    reasons.push("IP address used as domain — common phishing technique to avoid domain tracking");
  }

  // ── 3. Trusted Domain Whitelist ──────────────────────────────────────────
  const baseDomain = getBaseDomain(hostname);
  const isTrusted  = TRUSTED_DOMAINS.has(baseDomain);
  if (isTrusted && riskScore < 20) {
    return buildResult(url, 5, reasons, indicators, isTrusted);
  }

  // ── 4. Suspicious Keywords ───────────────────────────────────────────────
  const fullUrl = lower;
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => fullUrl.includes(k));
  indicators.keywords = foundKeywords.length > 0;
  if (indicators.keywords) {
    const kScore = Math.min(foundKeywords.length * 8, 28);
    riskScore += kScore;
    reasons.push(`Suspicious keywords detected: ${foundKeywords.slice(0,4).join(", ")}`);
  }

  // ── 5. URL Shortener ─────────────────────────────────────────────────────
  indicators.shortened = URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(baseDomain);
  if (indicators.shortened) {
    riskScore += 25;
    reasons.push("URL shortener detected — obscures the true destination URL");
  }

  // ── 6. Fake Brand Pattern ────────────────────────────────────────────────
  const hasFakePattern = FAKE_BRAND_PATTERNS.some(p => p.test(hostname));
  const tooManySubdomains = hostname.split(".").length > 4;
  indicators.fakeDomain = hasFakePattern || tooManySubdomains;
  if (indicators.fakeDomain) {
    riskScore += 30;
    reasons.push("Domain pattern mimics a legitimate brand — highly suspicious");
  }

  // ── 7. URL Length ────────────────────────────────────────────────────────
  indicators.longUrl = url.length > 100;
  if (indicators.longUrl) {
    const lengthPenalty = Math.min(Math.floor((url.length - 100) / 20) * 5, 20);
    riskScore += 10 + lengthPenalty;
    reasons.push(`URL is unusually long (${url.length} chars) — obfuscation technique`);
  }

  // ── 8. Special Characters ────────────────────────────────────────────────
  const specialMatches = (url.match(/[@%~\{\}|\\^<>]/g) || []);
  indicators.specialChars = specialMatches.length > 1;
  if (indicators.specialChars) {
    riskScore += 10;
    reasons.push("Unusual special characters detected in URL structure");
  }

  // ── 9. Hyphens in Domain ─────────────────────────────────────────────────
  const hyphenCount = (hostname.match(/-/g) || []).length;
  indicators.hyphens = hyphenCount >= 3;
  if (indicators.hyphens) {
    riskScore += 10;
    reasons.push("Multiple hyphens in domain name — common phishing domain pattern");
  }

  // ── 10. Hex / Base64 Encoded Path ────────────────────────────────────────
  const hasEncoded = /%[0-9a-f]{2}/i.test(pathname) && pathname.split("%").length > 3;
  indicators.encoded = hasEncoded;
  if (hasEncoded) {
    riskScore += 12;
    reasons.push("URL encoding detected in path — may be hiding malicious content");
  }

  // ── 11. Numeric Domains ───────────────────────────────────────────────────
  const numericDomainMatch = hostname.match(/^[\d\-]+\./);
  indicators.numericDomain = !!numericDomainMatch;
  if (indicators.numericDomain) {
    riskScore += 15;
    reasons.push("Numeric domain pattern — unusual for legitimate websites");
  }

  riskScore = Math.min(Math.max(riskScore, 0), 100);
  return buildResult(url, riskScore, reasons, indicators, isTrusted);
}

// ── BUILD RESULT ──────────────────────────────────────────────────────────────
function buildResult(url, riskScore, reasons, indicators, isTrusted) {
  let status, threatLevel, icon;

  if (isTrusted && riskScore < 20) {
    status = "Safe"; threatLevel = "Safe"; icon = "✅";
  } else if (riskScore <= 15) {
    status = "Safe"; threatLevel = "Safe"; icon = "✅";
  } else if (riskScore <= 35) {
    status = "Low Risk"; threatLevel = "Low Risk"; icon = "🟡";
  } else if (riskScore <= 55) {
    status = "Suspicious"; threatLevel = "Medium Risk"; icon = "⚠️";
  } else if (riskScore <= 75) {
    status = "Malicious"; threatLevel = "High Risk"; icon = "🚨";
  } else {
    status = "Malicious"; threatLevel = "Critical Risk"; icon = "💀";
  }

  const reason = reasons.length > 0
    ? reasons.join(". ") + "."
    : "No significant threats detected. URL appears safe based on structural and pattern analysis.";

  return { url, status, riskScore, threatLevel, reason, indicators, icon };
}

// ── HELPER ────────────────────────────────────────────────────────────────────
function getBaseDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 2) return parts.slice(-2).join(".");
  return hostname;
}

module.exports = { analyzeUrl, validateUrl };
