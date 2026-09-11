// === CONFIG & API BASE ===
function resolveApiBase() {
  // When deployed on Vercel, Flask and the frontend share the same origin.
  if (window.location.protocol.startsWith("http")) {
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      return "http://127.0.0.1:5000";
    }

    return window.location.origin;
  }

  return "http://127.0.0.1:5000";
}

let API_BASE = resolveApiBase();

// Universal API fetch helper with automatic port 5000 fallback (handles VS Code Live Server, IIS, etc.)
async function apiFetch(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, options);
    // If a static server (e.g. VS Code Live Server port 5500) returns 405 or 404, fallback to port 5000
    if ((res.status === 405 || res.status === 404) && API_BASE !== "http://127.0.0.1:5000") {
      console.warn(`[Web-Vul] API ${url} returned ${res.status}. Rerouting to Flask backend at http://127.0.0.1:5000...`);
      API_BASE = "http://127.0.0.1:5000";
      return await fetch(`${API_BASE}${endpoint}`, options);
    }
    return res;
  } catch (err) {
    if (API_BASE !== "http://127.0.0.1:5000") {
      console.warn(`[Web-Vul] Request to ${url} failed. Retrying on http://127.0.0.1:5000...`);
      API_BASE = "http://127.0.0.1:5000";
      return await fetch(`${API_BASE}${endpoint}`, options);
    }
    throw err;
  }
}

// === DOM ELEMENTS ===
const scanButton = document.getElementById("scan-button");
const scanButtonText = document.getElementById("scan-button-text");
const scanButtonSpinner = document.getElementById("scan-button-spinner");
const urlInput = document.getElementById("url-input");
const errorMessage = document.getElementById("error-message");

const placeholder = document.getElementById("placeholder");
const resultsWrapper = document.getElementById("results-wrapper");

const scanUrlLabel = document.getElementById("scan-url-label");
const scanTimeLabel = document.getElementById("scan-time-label");

const summaryTotal = document.getElementById("summary-total");
const summaryHigh = document.getElementById("summary-high");
const summaryMedium = document.getElementById("summary-medium");
const summaryLow = document.getElementById("summary-low");

const vulnerabilitiesContainer = document.getElementById(
  "vulnerabilities-container"
);
const aiAnalysisBox = document.getElementById("ai-analysis");

// Tabs
const vulnTab = document.getElementById("vuln-tab");
const aiTab = document.getElementById("ai-tab");
const vulnColumn = document.getElementById("vuln-column");
const aiColumn = document.getElementById("ai-column");
const vulnCountBadge = document.getElementById("vuln-count-badge");

// Security Score Elements
const scoreValue = document.getElementById("score-value");
const scoreGrade = document.getElementById("score-grade");
const scoreStatusText = document.getElementById("score-status-text");
const scoreCircle = document.getElementById("score-circle");

// Export button
const exportBtn = document.getElementById("export-pdf-btn");

// Filter & Search state
let currentFilter = "all";
let currentSearch = "";

// Recent Scans
const STORAGE_KEY = "web_vul_scan_history";
const recentScansWrapper = document.getElementById("recent-scans-wrapper");
const recentScansSelect = document.getElementById("recent-scans-select");
const clearHistoryBtn = document.getElementById("clear-history-btn");
const vulnSearchInput = document.getElementById("vuln-search-input");

// store last scan for PDF export
let lastScanData = null;

// === HELPERS ===

// Convert backend UTC scan_time to IST label for UI + PDF
function convertUTCtoIST(utcString) {
  if (!utcString) return "";

  try {
    let utcDate = new Date(utcString);

    if (isNaN(utcDate.getTime())) {
      // try appending UTC
      utcDate = new Date(utcString + " UTC");
    }

    if (isNaN(utcDate.getTime())) {
      return utcString;
    }

    return utcDate.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch (err) {
    console.error("Time conversion failed:", err);
    return utcString;
  }
}

function setLoading(isLoading) {
  if (isLoading) {
    scanButton.disabled = true;
    scanButtonText.textContent = "Scanning...";
    scanButtonSpinner.classList.remove("hidden");
  } else {
    scanButton.disabled = false;
    scanButtonText.textContent = "Scan Website";
    scanButtonSpinner.classList.add("hidden");
  }
}

function showError(message) {
  if (!message) {
    errorMessage.classList.add("hidden");
    errorMessage.textContent = "";
    return;
  }
  errorMessage.textContent = message;
  errorMessage.classList.remove("hidden");
}

function getSeverityClass(risk) {
  const key = (risk || "").toLowerCase();
  if (key === "high") return "severity-high";
  if (key === "medium") return "severity-medium";
  if (key === "low") return "severity-low";
  return "";
}

// Calculate Security Health Score (0-100) and Letter Grade
function calculateSecurityScore(details) {
  let score = 100;
  if (Array.isArray(details)) {
    details.forEach((v) => {
      const risk = (v.risk || "").toLowerCase();
      if (risk === "high") score -= 25;
      else if (risk === "medium") score -= 10;
      else if (risk === "low") score -= 5;
    });
  }
  score = Math.max(0, Math.min(100, score));

  let grade = "A+";
  let gradeClass = "grade-a";
  let statusText = "Excellent Security Posture";
  let circleClass = "score-secure";

  if (score >= 90) {
    grade = "A+";
    gradeClass = "grade-a";
    statusText = "Excellent Posture - Low Risk";
    circleClass = "score-secure";
  } else if (score >= 80) {
    grade = "A";
    gradeClass = "grade-a";
    statusText = "Strong Posture - Minor Flaws";
    circleClass = "score-secure";
  } else if (score >= 65) {
    grade = "B";
    gradeClass = "grade-b";
    statusText = "Moderate Risk - Action Needed";
    circleClass = "score-low-risk";
  } else if (score >= 50) {
    grade = "C";
    gradeClass = "grade-c";
    statusText = "Elevated Risk - Hardening Required";
    circleClass = "score-med-risk";
  } else if (score >= 30) {
    grade = "D";
    gradeClass = "grade-d";
    statusText = "High Risk - Vulnerable";
    circleClass = "score-high-risk";
  } else {
    grade = "F";
    gradeClass = "grade-f";
    statusText = "Critical Risk - Immediate Action";
    circleClass = "score-high-risk";
  }

  return { score, grade, gradeClass, statusText, circleClass };
}

// Enrich vulnerabilities with OWASP 2021 categories, CWE IDs, and Code Remediation Snippets
function getEnrichedMetadata(vuln) {
  const type = (vuln.type || "").toLowerCase();
  const desc = (vuln.description || "").toLowerCase();

  // 1. SQL Injection
  if (type.includes("sql") || desc.includes("sql")) {
    return {
      owasp: "OWASP A03:2021 - Injection",
      cwe: "CWE-89: SQL Injection",
      snippetLang: "SQL / Parameterized Query",
      snippet: `// VULNERABLE:\n// query = "SELECT * FROM users WHERE user = '" + input + "'";\n\n// SECURE (Parameterized Query):\nconst stmt = db.prepare("SELECT * FROM users WHERE user = ?");\nconst result = stmt.all(input);`
    };
  }

  // 2. Cross-Site Scripting (XSS)
  if (type.includes("xss") || desc.includes("cross-site scripting")) {
    return {
      owasp: "OWASP A03:2021 - Injection",
      cwe: "CWE-79: Cross-Site Scripting (XSS)",
      snippetLang: "HTML Sanitization & Context Encoding",
      snippet: `// VULNERABLE: element.innerHTML = userInput;\n\n// SECURE (Text node or DOMPurify):\nelement.textContent = userInput;\n// Or with sanitizer:\nelement.innerHTML = DOMPurify.sanitize(userInput);`
    };
  }

  // 3. Security Headers
  if (desc.includes("content-security-policy") || desc.includes("csp") || type.includes("csp")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-1021: Improper UI Restriction",
      snippetLang: "Nginx / Express Configuration",
      snippet: `# Nginx:\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;\n\n# Express (Helmet):\napp.use(helmet.contentSecurityPolicy());`
    };
  }

  if (desc.includes("strict-transport-security") || desc.includes("hsts") || type.includes("hsts")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-319: Cleartext Sensitive Data Transmission",
      snippetLang: "Nginx / Apache Configuration",
      snippet: `# Nginx:\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n\n# Apache:\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`
    };
  }

  if (desc.includes("x-frame-options") || type.includes("x-frame-options") || desc.includes("clickjacking")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-1021: Clickjacking Defense",
      snippetLang: "Nginx / Express Configuration",
      snippet: `# Nginx:\nadd_header X-Frame-Options "DENY" always;\n\n# Express:\napp.use((req, res, next) => {\n  res.setHeader("X-Frame-Options", "DENY");\n  next();\n});`
    };
  }

  if (desc.includes("x-content-type-options") || type.includes("x-content-type-options") || desc.includes("mime")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-693: Protection Mechanism Failure",
      snippetLang: "Nginx / Express Configuration",
      snippet: `# Nginx:\nadd_header X-Content-Type-Options "nosniff" always;\n\n# Express:\napp.use((req, res, next) => {\n  res.setHeader("X-Content-Type-Options", "nosniff");\n  next();\n});`
    };
  }

  // 4. Cookie Security Flags
  if (type.includes("cookie") || desc.includes("cookie")) {
    if (type.includes("httponly") || desc.includes("httponly")) {
      return {
        owasp: "OWASP A07:2021 - Identification Failures",
        cwe: "CWE-1004: Sensitive Cookie Without HttpOnly",
        snippetLang: "Express / Node Session",
        snippet: `// Express Session:\napp.use(session({\n  secret: "secure-key",\n  cookie: { httpOnly: true, secure: true, sameSite: "lax" }\n}));`
      };
    }
    if (type.includes("secure") || desc.includes("secure")) {
      return {
        owasp: "OWASP A05:2021 - Security Misconfiguration",
        cwe: "CWE-614: Sensitive Cookie in HTTPS Without Secure Flag",
        snippetLang: "Set-Cookie Header",
        snippet: `// Set Secure flag on all cookies:\nres.setHeader("Set-Cookie", "session_id=...; Secure; HttpOnly; SameSite=Lax");`
      };
    }
    return {
      owasp: "OWASP A01:2021 - Broken Access Control",
      cwe: "CWE-1275: Cookie With Insecure SameSite",
      snippetLang: "SameSite Cookie Directive",
      snippet: `// Configure SameSite to mitigate CSRF:\nSet-Cookie: token=xyz; SameSite=Lax; Secure; HttpOnly`
    };
  }

  // 5. Sensitive File / Directory Exposure
  if (type.includes(".env") || desc.includes(".env") || type.includes(".git") || desc.includes(".git")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-538: File and Directory Information Exposure",
      snippetLang: "Nginx / Apache Access Block",
      snippet: `# Nginx (Block hidden dotfiles):\nlocation ~ /\\.(env|git|htaccess) {\n    deny all;\n    return 404;\n}\n\n# Apache (.htaccess):\n<FilesMatch "^\\.(env|git)">\n    Order allow,deny\n    Deny from all\n</FilesMatch>`
    };
  }

  if (type.includes("robots.txt") || desc.includes("robots.txt")) {
    return {
      owasp: "OWASP A01:2021 - Broken Access Control",
      cwe: "CWE-200: Information Exposure via robots.txt",
      snippetLang: "Authorization & ACLs",
      snippet: `// Protect administrative paths with server-side authentication:\napp.use("/admin", authenticateUser, requireAdminRole);`
    };
  }

  // 6. Information Disclosure & Banners
  if (type.includes("information disclosure") || type.includes("server banner") || type.includes("x-powered-by")) {
    return {
      owasp: "OWASP A05:2021 - Security Misconfiguration",
      cwe: "CWE-200: Server Banner Information Exposure",
      snippetLang: "Nginx / Apache / Express Hardening",
      snippet: `# Nginx: Hide version\nserver_tokens off;\n\n# Apache: Minimal banner\nServerTokens Prod\nServerSignature Off\n\n# Express:\napp.disable("x-powered-by");`
    };
  }

  // 7. CORS Misconfiguration
  if (type.includes("cors") || desc.includes("cors") || desc.includes("origin")) {
    return {
      owasp: "OWASP A01:2021 - Broken Access Control",
      cwe: "CWE-942: Permissive Cross-Domain Policy",
      snippetLang: "Express / Flask CORS Whitelist",
      snippet: `// Express CORS (Strict Whitelist):\nconst whitelist = ["https://yourdomain.com"];\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || whitelist.includes(origin)) callback(null, true);\n    else callback(new Error("Blocked by CORS"));\n  },\n  credentials: true\n}));`
    };
  }

  return {
    owasp: "OWASP A05:2021 - Security Misconfiguration",
    cwe: "CWE-693: Defense in Depth",
    snippetLang: "Security Hardening",
    snippet: `# Enforce security best practices and validate server configuration.`
  };
}

function updateSummary(details, totalVulns, highRiskCount, scanUrl, scanTime) {
  const vulnList = Array.isArray(details) ? details : [];
  const count = typeof totalVulns === "number" ? totalVulns : vulnList.length;

  summaryTotal.textContent = count;

  let high = 0;
  let medium = 0;
  let low = 0;

  vulnList.forEach((v) => {
    const risk = (v.risk || "").toLowerCase();
    if (risk === "high") high++;
    else if (risk === "medium") medium++;
    else if (risk === "low") low++;
  });

  if (typeof highRiskCount === "number") {
    high = highRiskCount;
  }

  summaryHigh.textContent = high;
  summaryMedium.textContent = medium;
  summaryLow.textContent = low;

  // Update Security Score & Grade
  const scoreData = calculateSecurityScore(vulnList);
  if (scoreValue) scoreValue.textContent = scoreData.score;
  if (scoreGrade) {
    scoreGrade.textContent = scoreData.grade;
    scoreGrade.className = `score-grade-badge ${scoreData.gradeClass}`;
  }
  if (scoreStatusText) scoreStatusText.textContent = scoreData.statusText;
  if (scoreCircle) scoreCircle.className = `score-circle ${scoreData.circleClass}`;

  // Update Tab Count Badge
  if (vulnCountBadge) vulnCountBadge.textContent = count;

  scanUrlLabel.textContent = scanUrl ? `Target: ${scanUrl}` : "";

  if (scanTime) {
    const istLabel = convertUTCtoIST(scanTime);
    scanTimeLabel.textContent = `Scan time (IST): ${istLabel}`;
  } else {
    scanTimeLabel.textContent = "";
  }
}

function renderVulnerabilities(details) {
  vulnerabilitiesContainer.innerHTML = "";

  const vulnList = Array.isArray(details) ? details : [];

  // Update Toolbar Count Badges
  const fAll = document.getElementById("filter-count-all");
  const fHigh = document.getElementById("filter-count-high");
  const fMed = document.getElementById("filter-count-medium");
  const fLow = document.getElementById("filter-count-low");

  if (fAll) fAll.textContent = vulnList.length;
  if (fHigh) fHigh.textContent = vulnList.filter(v => (v.risk || "").toLowerCase() === "high").length;
  if (fMed) fMed.textContent = vulnList.filter(v => (v.risk || "").toLowerCase() === "medium").length;
  if (fLow) fLow.textContent = vulnList.filter(v => (v.risk || "").toLowerCase() === "low").length;

  if (vulnList.length === 0) {
    const empty = document.createElement("div");
    empty.className = "vuln-card";
    empty.innerHTML = `
      <div class="vuln-header">
        <div class="vuln-title" style="color:#22c55e;">✅ No Vulnerabilities Detected</div>
        <span class="severity-pill severity-low">Secure</span>
      </div>
      <div class="vuln-body" style="color:var(--text-soft); font-size:13px;">
        The automated security checks did not find any issues with the target URL.
      </div>
    `;
    vulnerabilitiesContainer.appendChild(empty);
    return;
  }

  // Filter by Severity and Live Search Query
  const filtered = vulnList.filter((vuln) => {
    const r = (vuln.risk || "").toLowerCase();
    if (currentFilter !== "all" && r !== currentFilter) {
      return false;
    }
    if (currentSearch.trim()) {
      const q = currentSearch.toLowerCase();
      const typeMatch = (vuln.type || "").toLowerCase().includes(q);
      const descMatch = (vuln.description || "").toLowerCase().includes(q);
      const recoMatch = (vuln.recommendation || "").toLowerCase().includes(q);
      if (!typeMatch && !descMatch && !recoMatch) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    const noMatch = document.createElement("div");
    noMatch.className = "vuln-card";
    noMatch.innerHTML = `
      <div class="vuln-header">
        <div class="vuln-title" style="color:#94a3b8;">🔍 No matching issues</div>
      </div>
      <div class="vuln-body" style="color:var(--text-soft); font-size:13px;">
        No findings match filter <strong>${currentFilter.toUpperCase()}</strong> with search "<strong>${currentSearch}</strong>".
      </div>
    `;
    vulnerabilitiesContainer.appendChild(noMatch);
    return;
  }

  filtered.forEach((vuln) => {
    const type = vuln.type || "Unknown";
    const desc = vuln.description || "";
    const risk = vuln.risk || "Unknown";
    const recommendation = vuln.recommendation || "";
    const meta = getEnrichedMetadata(vuln);

    const card = document.createElement("div");
    card.className = "vuln-card";

    // Card Header
    const header = document.createElement("div");
    header.className = "vuln-header";

    const title = document.createElement("div");
    title.className = "vuln-title";
    title.textContent = `${type}: ${desc}`;

    const sev = document.createElement("span");
    sev.className = `severity-pill ${getSeverityClass(risk)}`;
    sev.textContent = risk;

    header.appendChild(title);
    header.appendChild(sev);
    card.appendChild(header);

    // OWASP & CWE Tags
    const tagsWrapper = document.createElement("div");
    tagsWrapper.className = "vuln-tags";

    const owaspTag = document.createElement("span");
    owaspTag.className = "tag-pill owasp-tag";
    owaspTag.textContent = `🛡️ ${meta.owasp}`;

    const cweTag = document.createElement("span");
    cweTag.className = "tag-pill cwe-tag";
    cweTag.textContent = `🔍 ${meta.cwe}`;

    tagsWrapper.appendChild(owaspTag);
    tagsWrapper.appendChild(cweTag);
    card.appendChild(tagsWrapper);

    // Card Body
    const body = document.createElement("div");
    body.className = "vuln-body";

    const recBox = document.createElement("div");
    recBox.className = "vuln-reco";

    const recTitle = document.createElement("div");
    recTitle.className = "vuln-reco-title";
    recTitle.textContent = "Recommended Fix:";

    const recText = document.createElement("div");
    recText.textContent = recommendation;

    recBox.appendChild(recTitle);
    recBox.appendChild(recText);
    body.appendChild(recBox);

    // Actionable Code Snippet Box
    if (meta.snippet) {
      const snippetBox = document.createElement("div");
      snippetBox.className = "code-snippet-box";

      const snippetHeader = document.createElement("div");
      snippetHeader.className = "code-snippet-header";

      const langSpan = document.createElement("span");
      langSpan.className = "code-snippet-lang";
      langSpan.textContent = `💻 ${meta.snippetLang}`;

      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-snippet-btn";
      copyBtn.textContent = "📋 Copy Fix";
      copyBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(meta.snippet).then(() => {
          copyBtn.textContent = "✓ Copied!";
          setTimeout(() => {
            copyBtn.textContent = "📋 Copy Fix";
          }, 1500);
        });
      });

      snippetHeader.appendChild(langSpan);
      snippetHeader.appendChild(copyBtn);

      const pre = document.createElement("pre");
      pre.className = "code-snippet-pre";
      const code = document.createElement("code");
      code.textContent = meta.snippet;
      pre.appendChild(code);

      snippetBox.appendChild(snippetHeader);
      snippetBox.appendChild(pre);
      body.appendChild(snippetBox);
    }

    card.appendChild(body);
    vulnerabilitiesContainer.appendChild(card);
  });
}

function renderAiAnalysis(aiText) {
  aiAnalysisBox.innerHTML = "";

  if (!aiText) {
    aiAnalysisBox.textContent = "No AI analysis provided.";
    return;
  }

  // Check if AI is unavailable or failed
  if (aiText.startsWith("AI analysis unavailable:") || aiText.startsWith("AI analysis failed:")) {
    const notice = document.createElement("div");
    notice.className = "info-box";
    notice.style.borderColor = "rgba(234, 179, 8, 0.45)";
    notice.style.background = "rgba(30, 41, 59, 0.85)";
    notice.innerHTML = `
      <div class="info-icon" style="font-size:24px;">⚠️</div>
      <div>
        <div class="info-title" style="color:#fcd34d; margin-bottom:6px;">AI Security Auditor Notice</div>
        <p class="info-text" style="color:#e2e8f0; margin-bottom:8px;">${aiText}</p>
        <div style="font-size:12px; color:#94a3b8; background:rgba(15,23,42,0.6); padding:8px 12px; border-radius:6px; border:1px solid rgba(148,163,184,0.2);">
          💡 <strong>How to configure:</strong> Add your valid Google Gemini API key to <code>backend/.env</code>:<br>
          <code style="color:#38bdf8;">GEMINI_API_KEY=your_key_here</code><br>
          Get a free API key at <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener" style="color:#38bdf8; text-decoration:underline;">Google AI Studio</a>.
        </div>
      </div>
    `;
    aiAnalysisBox.appendChild(notice);
    return;
  }

  // Check if output contains our structured format: "### Vulnerability"
  if (aiText.includes("### Vulnerability") || aiText.includes("###")) {
    const container = document.createElement("div");
    container.className = "ai-report-container";

    // Split by sections starting with "### "
    const sections = aiText.split(/(?=###\s+)/);

    sections.forEach((sec) => {
      const trimmed = sec.trim();
      if (!trimmed) return;

      const card = document.createElement("div");
      card.className = "ai-report-card";

      // Extract title: e.g. "### Vulnerability 1: Content Security Policy (CSP)"
      const titleMatch = trimmed.match(/###\s*(?:Vulnerability\s*\d*:\s*)?([^\n\r]+)/i);
      const title = titleMatch ? titleMatch[1].trim() : "Security Finding";

      // Extract Risk: "🔸 RISK: High"
      const riskMatch = trimmed.match(/🔸?\s*RISK:\s*([^\n\r]+)/i);
      const risk = riskMatch ? riskMatch[1].trim() : "Notice";

      // Apply border color class
      const riskLower = risk.toLowerCase();
      if (riskLower.includes("high")) card.classList.add("ai-risk-high");
      else if (riskLower.includes("med")) card.classList.add("ai-risk-medium");
      else card.classList.add("ai-risk-low");

      // Header row with Title and Risk badge
      const header = document.createElement("div");
      header.className = "ai-vuln-header";

      const titleEl = document.createElement("div");
      titleEl.className = "ai-vuln-title";
      titleEl.textContent = title;

      const riskBadge = document.createElement("span");
      riskBadge.className = `severity-pill ${getSeverityClass(riskLower)}`;
      riskBadge.textContent = risk;

      header.appendChild(titleEl);
      header.appendChild(riskBadge);
      card.appendChild(header);

      // Extract Summary: "🔸 SUMMARY: ..."
      const summaryMatch = trimmed.match(/🔸?\s*SUMMARY:\s*([\s\S]*?)(?=🔸?\s*RECOMMENDATIONS:|$)/i);
      if (summaryMatch && summaryMatch[1].trim()) {
        const sumLabel = document.createElement("div");
        sumLabel.className = "ai-section-label";
        sumLabel.textContent = "Audit Summary";
        card.appendChild(sumLabel);

        const sumText = document.createElement("div");
        sumText.className = "ai-summary-text";
        sumText.textContent = summaryMatch[1].trim();
        card.appendChild(sumText);
      }

      // Extract Recommendations: "🔸 RECOMMENDATIONS: ..."
      const recoMatch = trimmed.match(/🔸?\s*RECOMMENDATIONS:\s*([\s\S]*?)$/i);
      if (recoMatch && recoMatch[1].trim()) {
        const recoLabel = document.createElement("div");
        recoLabel.className = "ai-section-label";
        recoLabel.textContent = "Remediation Steps";
        card.appendChild(recoLabel);

        const ul = document.createElement("ul");
        ul.className = "ai-bullet-list";

        const lines = recoMatch[1].split("\n");
        lines.forEach((l) => {
          const cleanLine = l.replace(/^[-*•\s]+/, "").trim();
          if (cleanLine) {
            const li = document.createElement("li");
            li.textContent = cleanLine;
            ul.appendChild(li);
          }
        });

        card.appendChild(ul);
      }

      container.appendChild(card);
    });

    aiAnalysisBox.appendChild(container);
  } else {
    // Plain text fallback formatted with clean paragraphs
    const pre = document.createElement("div");
    pre.style.whiteSpace = "pre-wrap";
    pre.style.fontSize = "13px";
    pre.style.lineHeight = "1.6";
    pre.style.color = "#cbd5e1";
    pre.textContent = aiText;
    aiAnalysisBox.appendChild(pre);
  }
}

function showTab(tab) {
  if (!vulnColumn || !aiColumn || !vulnTab || !aiTab) return;

  if (tab === "vuln") {
    vulnColumn.classList.remove("hidden");
    aiColumn.classList.add("hidden");

    vulnTab.classList.add("tab-active");
    vulnTab.classList.remove("tab-inactive");

    aiTab.classList.add("tab-inactive");
    aiTab.classList.remove("tab-active");
  } else {
    aiColumn.classList.remove("hidden");
    vulnColumn.classList.add("hidden");

    aiTab.classList.add("tab-active");
    aiTab.classList.remove("tab-inactive");

    vulnTab.classList.add("tab-inactive");
    vulnTab.classList.remove("tab-active");
  }
}

// === EXECUTIVE PDF EXPORT ===
function handleExportPdf() {
  if (!lastScanData) return;

  if (!window.jspdf || !window.jspdf.jsPDF) {
    alert("PDF library not loaded.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "pt", format: "a4" });

  const margin = 40;
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const contentWidth = pageWidth - 2 * margin;

  const targetUrl = lastScanData.scan_url || "Unknown Target";
  const scanTimeIST = lastScanData.scan_time
    ? convertUTCtoIST(lastScanData.scan_time)
    : "Unknown Time";

  const details = Array.isArray(lastScanData.details) ? lastScanData.details : [];
  const scoreInfo = calculateSecurityScore(details);

  let high = 0;
  let medium = 0;
  let low = 0;
  details.forEach((v) => {
    const risk = (v.risk || "").toLowerCase();
    if (risk === "high") high++;
    else if (risk === "medium") medium++;
    else if (risk === "low") low++;
  });

  let y = 0;

  // Helper to ensure enough space on page or add page
  function ensureSpace(neededHeight) {
    if (y + neededHeight > pageHeight - 50) {
      doc.addPage();
      y = 50;
      return true;
    }
    return false;
  }

  // --- PAGE 1: HEADER BANNER ---
  doc.setFillColor(15, 23, 42); // Dark Slate/Navy
  doc.rect(0, 0, pageWidth, 74, "F");

  // Cyan Accent Strip
  doc.setFillColor(14, 165, 233);
  doc.rect(0, 71, pageWidth, 3, "F");

  // Title & Subtitle
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text("CYBERSECURITY ASSESSMENT REPORT", margin, 34);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text("Executive Security Audit, OWASP Classification & Remediation Roadmap", margin, 52);

  // Date on right
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  const dateStr = `Generated: ${scanTimeIST}`;
  const dateW = doc.getTextWidth(dateStr);
  doc.text(dateStr, pageWidth - margin - dateW, 34);

  y = 92;

  // --- TARGET PROFILE BOX ---
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.8);
  doc.roundedRect(margin, y, contentWidth, 54, 4, 4, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105);
  doc.text("TARGET URL:", margin + 12, y + 18);
  doc.text("ASSESSMENT SCOPE:", margin + 12, y + 36);

  doc.setFont("helvetica", "normal");
  doc.setTextColor(15, 23, 42);
  const truncatedUrl = targetUrl.length > 55 ? targetUrl.substring(0, 52) + "..." : targetUrl;
  doc.text(truncatedUrl, margin + 85, y + 18);
  doc.text("Automated Security Headers, Injection & Reflection Analysis", margin + 125, y + 36);

  doc.setFont("helvetica", "bold");
  doc.setTextColor(71, 85, 105);
  doc.text("SCAN ENGINE:", margin + 350, y + 18);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(15, 23, 42);
  doc.text("AI Web Auditor v2.0", margin + 420, y + 18);

  y += 66;

  // --- SECTION 1: EXECUTIVE SUMMARY & SCORECARD ---
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text("1. Executive Summary & Security Posture", margin, y);
  y += 12;

  // Scorecard Container (Two Columns: Score Gauge on left, Metrics Grid on right)
  const scoreCardY = y;
  const scoreCardH = 70;
  const colLeftW = 190;
  const colRightW = contentWidth - colLeftW - 12;

  // Left Box: Security Health Score
  let scoreBgColor = [236, 253, 245]; // green
  let scoreBorderColor = [52, 211, 153];
  let scoreTextColor = [5, 150, 105];

  if (scoreInfo.score < 50) {
    scoreBgColor = [254, 242, 242]; // red
    scoreBorderColor = [248, 113, 113];
    scoreTextColor = [220, 38, 38];
  } else if (scoreInfo.score < 75) {
    scoreBgColor = [255, 247, 237]; // orange
    scoreBorderColor = [251, 146, 60];
    scoreTextColor = [234, 88, 12];
  }

  doc.setFillColor(scoreBgColor[0], scoreBgColor[1], scoreBgColor[2]);
  doc.setDrawColor(scoreBorderColor[0], scoreBorderColor[1], scoreBorderColor[2]);
  doc.roundedRect(margin, scoreCardY, colLeftW, scoreCardH, 4, 4, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text("SECURITY POSTURE SCORE", margin + 12, scoreCardY + 18);

  doc.setFontSize(22);
  doc.setTextColor(scoreTextColor[0], scoreTextColor[1], scoreTextColor[2]);
  doc.text(`${scoreInfo.score}`, margin + 12, scoreCardY + 44);

  doc.setFontSize(11);
  doc.setTextColor(100, 116, 139);
  doc.text("/ 100", margin + 58, scoreCardY + 44);

  doc.setFontSize(10);
  doc.setFont("helvetica", "bold");
  doc.text(`Grade: ${scoreInfo.grade}`, margin + 96, scoreCardY + 44);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text(scoreInfo.statusText, margin + 12, scoreCardY + 60);

  // Right Box: Metrics Table
  const rightX = margin + colLeftW + 12;
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(rightX, scoreCardY, colRightW, scoreCardH, 4, 4, "FD");

  const cellW = colRightW / 4;
  const metrics = [
    { label: "Total Issues", val: details.length, color: [30, 41, 59] },
    { label: "High Risk", val: high, color: [220, 38, 38] },
    { label: "Medium Risk", val: medium, color: [234, 88, 12] },
    { label: "Low Risk", val: low, color: [202, 138, 4] },
  ];

  metrics.forEach((m, idx) => {
    const cx = rightX + idx * cellW;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(m.label, cx + 8, scoreCardY + 22);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(m.color[0], m.color[1], m.color[2]);
    doc.text(String(m.val), cx + 8, scoreCardY + 50);

    if (idx < 3) {
      doc.setDrawColor(226, 232, 240);
      doc.line(cx + cellW, scoreCardY + 10, cx + cellW, scoreCardY + scoreCardH - 10);
    }
  });

  y = scoreCardY + scoreCardH + 18;

  // --- SECTION 2: OWASP TOP 10 & CWE MATRIX ---
  ensureSpace(90);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text("2. OWASP Top 10 & Industry Taxonomy Mapping", margin, y);
  y += 12;

  // Table Headers
  const tableX = margin;
  const rowH = 20;
  const colW1 = 28;  // #
  const colW2 = 140; // Finding
  const colW3 = 60;  // Severity
  const colW4 = 175; // OWASP Category
  const colW5 = contentWidth - (colW1 + colW2 + colW3 + colW4); // CWE

  doc.setFillColor(30, 41, 59);
  doc.rect(tableX, y, contentWidth, rowH, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text("#", tableX + 8, y + 13);
  doc.text("VULNERABILITY", tableX + colW1 + 8, y + 13);
  doc.text("SEVERITY", tableX + colW1 + colW2 + 8, y + 13);
  doc.text("OWASP 2021 CATEGORY", tableX + colW1 + colW2 + colW3 + 8, y + 13);
  doc.text("CWE ID", tableX + colW1 + colW2 + colW3 + colW4 + 8, y + 13);
  y += rowH;

  if (details.length === 0) {
    doc.setFillColor(255, 255, 255);
    doc.rect(tableX, y, contentWidth, 22, "F");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(34, 197, 94);
    doc.text("No vulnerabilities detected. All baseline checks passed.", tableX + 12, y + 15);
    y += 22;
  } else {
    details.forEach((v, idx) => {
      ensureSpace(24);
      const meta = getEnrichedMetadata(v);
      const isEven = idx % 2 === 0;

      doc.setFillColor(isEven ? 248 : 255, isEven ? 250 : 255, isEven ? 252 : 255);
      doc.setDrawColor(226, 232, 240);
      doc.rect(tableX, y, contentWidth, rowH, "FD");

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(String(idx + 1), tableX + 8, y + 13);

      // Title (truncate if needed)
      doc.setFont("helvetica", "bold");
      doc.setTextColor(15, 23, 42);
      const name = (v.type || "Finding").length > 24 ? (v.type || "Finding").substring(0, 22) + "..." : (v.type || "Finding");
      doc.text(name, tableX + colW1 + 8, y + 13);

      // Severity with color
      const risk = (v.risk || "").toLowerCase();
      if (risk === "high") doc.setTextColor(220, 38, 38);
      else if (risk === "medium") doc.setTextColor(234, 88, 12);
      else doc.setTextColor(202, 138, 4);
      doc.text(v.risk || "Unknown", tableX + colW1 + colW2 + 8, y + 13);

      // OWASP & CWE
      doc.setFont("helvetica", "normal");
      doc.setTextColor(71, 85, 105);
      doc.text(meta.owasp, tableX + colW1 + colW2 + colW3 + 8, y + 13);
      doc.text(meta.cwe, tableX + colW1 + colW2 + colW3 + colW4 + 8, y + 13);

      y += rowH;
    });
  }

  y += 18;

  // --- SECTION 3: DETAILED TECHNICAL FINDINGS & REMEDIATION ---
  ensureSpace(80);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text("3. Technical Findings & Remediation Guidance", margin, y);
  y += 14;

  details.forEach((v, idx) => {
    ensureSpace(90);
    const meta = getEnrichedMetadata(v);
    const risk = (v.risk || "Low").toUpperCase();

    // Finding Card Header
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.6);
    doc.roundedRect(margin, y, contentWidth, 24, 3, 3, "FD");

    // Title
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`Issue #${idx + 1}: ${v.type || "Vulnerability"}`, margin + 10, y + 16);

    // Severity Badge on Right
    let badgeBg = [202, 138, 4];
    if (risk === "HIGH") badgeBg = [220, 38, 38];
    else if (risk === "MEDIUM") badgeBg = [234, 88, 12];

    doc.setFillColor(badgeBg[0], badgeBg[1], badgeBg[2]);
    const badgeW = 52;
    doc.roundedRect(pageWidth - margin - badgeW - 8, y + 4, badgeW, 16, 2, 2, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(255, 255, 255);
    const badgeTextW = doc.getTextWidth(risk);
    doc.text(risk, pageWidth - margin - badgeW - 8 + (badgeW - badgeTextW) / 2, y + 15);

    y += 30;

    // Description
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    doc.text("Description:", margin + 8, y);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(30, 41, 59);

    const descLines = doc.splitTextToSize(v.description || "No description provided.", contentWidth - 80);
    doc.text(descLines, margin + 75, y);
    y += descLines.length * 12 + 4;

    // Recommendation
    ensureSpace(40);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    doc.text("Remediation:", margin + 8, y);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(15, 23, 42);

    const recLines = doc.splitTextToSize(v.recommendation || "Follow secure coding practices.", contentWidth - 80);
    doc.text(recLines, margin + 75, y);
    y += recLines.length * 12 + 6;

    // Code Patch Snippet Box (if available)
    if (meta.snippet) {
      ensureSpace(45);
      doc.setFillColor(15, 23, 42); // dark background
      doc.setDrawColor(51, 65, 85);
      const snippetLines = doc.splitTextToSize(meta.snippet, contentWidth - 30);
      const snippetH = Math.min(snippetLines.length * 10 + 16, 70);

      doc.roundedRect(margin + 8, y, contentWidth - 16, snippetH, 3, 3, "FD");

      doc.setFont("courier", "normal");
      doc.setFontSize(7);
      doc.setTextColor(56, 189, 248); // light cyan code
      doc.text(snippetLines.slice(0, 6), margin + 16, y + 13);
      y += snippetH + 8;
    }

    y += 10;
  });

  // --- SECTION 4: AI STRATEGIC ASSESSMENT ---
  if (lastScanData.ai_analysis) {
    ensureSpace(90);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(15, 23, 42);
    doc.text("4. Strategic AI Auditor Recommendations", margin, y);
    y += 14;

    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.6);

    const aiRaw = String(lastScanData.ai_analysis);
    const cleanAiText = aiRaw.replace(/###/g, "").replace(/🔸/g, "•").trim();
    const aiLines = doc.splitTextToSize(cleanAiText, contentWidth - 24);

    const boxH = aiLines.length * 12 + 18;
    // Print lines with page wrap
    doc.roundedRect(margin, y, contentWidth, boxH, 4, 4, "FD");

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(30, 41, 59);

    let currentY = y + 14;
    aiLines.forEach((line) => {
      if (currentY > pageHeight - 50) {
        doc.addPage();
        currentY = 50;
      }
      doc.text(line, margin + 12, currentY);
      currentY += 12;
    });

    y = currentY + 14;
  }

  // --- RUNNING HEADERS & FOOTERS ON ALL PAGES ---
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);

    // Running Header (Pages > 1)
    if (i > 1) {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text("CONFIDENTIAL • WEB SECURITY ASSESSMENT REPORT", margin, 24);
      doc.text(truncatedUrl, pageWidth - margin - doc.getTextWidth(truncatedUrl), 24);

      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.5);
      doc.line(margin, 28, pageWidth - margin, 28);
    }

    // Running Footer (All Pages)
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 26, pageWidth - margin, pageHeight - 26);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text("AI-Powered Web Vulnerability Scanner • For authorized use only", margin, pageHeight - 14);

    const pageLabel = `Page ${i} of ${totalPages}`;
    doc.text(pageLabel, pageWidth - margin - doc.getTextWidth(pageLabel), pageHeight - 14);
  }

  // Generate filename with sanitized target name
  const cleanDomain = targetUrl.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9.-]/g, "_");
  const fileName = `Security-Audit-${cleanDomain}.pdf`;
  doc.save(fileName);
}

// === SCAN HANDLER ===
async function handleScan() {
  const url = urlInput.value.trim();
  showError("");

  if (!url) {
    showError("Please enter a URL to scan.");
    return;
  }

  setLoading(true);

  try {
    const response = await apiFetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `Scan failed with status ${response.status}`);
    }

    const data = await response.json();

    placeholder.classList.add("hidden");
    resultsWrapper.classList.remove("hidden");

    updateSummary(
      data.details || [],
      data.total_vulnerabilities_found,
      data.high_risk_vulnerabilities,
      data.scan_url,
      data.scan_time
    );

    const summaryContainer = document.getElementById("scan-summary-container");
    if (summaryContainer) {
      summaryContainer.classList.remove("hidden");
    }

    renderVulnerabilities(data.details || []);
    renderAiAnalysis(data.ai_analysis || "");

    lastScanData = data;
    saveScanToHistory(data);

    if (exportBtn) {
      exportBtn.classList.remove("hidden");
    }

    showTab("vuln");
  } catch (err) {
    console.error(err);
    showError(err.message || "Something went wrong while scanning.");
  } finally {
    setLoading(false);
  }
}

// === SCAN HISTORY (LOCALSTORAGE) ===
function saveScanToHistory(scanData) {
  if (!scanData || !scanData.scan_url) return;
  try {
    let history = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    // Remove duplicates of same URL to place at top
    history = history.filter((h) => h.url !== scanData.scan_url);
    history.unshift({
      id: Date.now(),
      url: scanData.scan_url,
      time: scanData.scan_time,
      data: scanData,
    });
    // Keep last 5
    history = history.slice(0, 5);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    updateHistoryDropdown();
  } catch (e) {
    console.error("Error saving scan to history:", e);
  }
}

function updateHistoryDropdown() {
  if (!recentScansWrapper || !recentScansSelect) return;
  try {
    const history = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    if (history.length === 0) {
      recentScansWrapper.classList.add("hidden");
      return;
    }
    recentScansWrapper.classList.remove("hidden");
    recentScansSelect.innerHTML = '<option value="">Choose previous scan...</option>';
    history.forEach((item, idx) => {
      const opt = document.createElement("option");
      opt.value = idx;
      const cleanUrl = item.url.replace(/^https?:\/\//, "");
      const shortUrl = cleanUrl.length > 28 ? cleanUrl.substring(0, 25) + "..." : cleanUrl;
      const ist = convertUTCtoIST(item.time) || item.time || "";
      opt.textContent = `${shortUrl} (${ist})`;
      recentScansSelect.appendChild(opt);
    });
  } catch (e) {
    console.error("Error reading scan history:", e);
  }
}

function loadHistoryItem(index) {
  try {
    const history = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    const item = history[index];
    if (!item || !item.data) return;

    urlInput.value = item.url;
    lastScanData = item.data;

    placeholder.classList.add("hidden");
    resultsWrapper.classList.remove("hidden");

    updateSummary(
      lastScanData.details || [],
      lastScanData.total_vulnerabilities_found,
      lastScanData.high_risk_vulnerabilities,
      lastScanData.scan_url,
      lastScanData.scan_time
    );

    const summaryContainer = document.getElementById("scan-summary-container");
    if (summaryContainer) {
      summaryContainer.classList.remove("hidden");
    }

    renderVulnerabilities(lastScanData.details || []);
    renderAiAnalysis(lastScanData.ai_analysis || "");

    if (exportBtn) {
      exportBtn.classList.remove("hidden");
    }

    showTab("vuln");
  } catch (e) {
    console.error("Error loading history item:", e);
  }
}

function clearHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    updateHistoryDropdown();
  } catch (e) {
    console.error("Error clearing history:", e);
  }
}

// === EVENTS ===
scanButton.addEventListener("click", handleScan);

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    handleScan();
  }
});

if (vulnTab && aiTab) {
  vulnTab.addEventListener("click", () => showTab("vuln"));
  aiTab.addEventListener("click", () => showTab("ai"));
}

if (exportBtn) {
  exportBtn.addEventListener("click", handleExportPdf);
}

// Filter Pills
document.querySelectorAll(".filter-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    document.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("filter-active"));
    pill.classList.add("filter-active");
    currentFilter = pill.getAttribute("data-filter") || "all";
    if (lastScanData) {
      renderVulnerabilities(lastScanData.details || []);
    }
  });
});

// Live Search Input
if (vulnSearchInput) {
  vulnSearchInput.addEventListener("input", (e) => {
    currentSearch = e.target.value;
    if (lastScanData) {
      renderVulnerabilities(lastScanData.details || []);
    }
  });
}

// Recent Scans
if (recentScansSelect) {
  recentScansSelect.addEventListener("change", (e) => {
    const val = e.target.value;
    if (val !== "") {
      loadHistoryItem(parseInt(val, 10));
    }
  });
}

if (clearHistoryBtn) {
  clearHistoryBtn.addEventListener("click", () => {
    clearHistory();
  });
}

// Initialize Scan History on page load
updateHistoryDropdown();

// =========================================================
// === BARCODE & QR CODE INSPECTOR MODULE ===
// =========================================================

// --- Mode Switcher (Website Scanner vs. Barcode Inspector) ---
const modeWebBtn = document.getElementById("mode-web-btn");
const modeBarcodeBtn = document.getElementById("mode-barcode-btn");
const viewWebScanner = document.getElementById("view-web-scanner");
const viewBarcodeInspector = document.getElementById("view-barcode-inspector");

function switchAppMode(mode) {
  if (mode === "web") {
    modeWebBtn.classList.add("mode-active");
    modeBarcodeBtn.classList.remove("mode-active");
    viewWebScanner.classList.remove("hidden");
    viewBarcodeInspector.classList.add("hidden");
  } else {
    modeBarcodeBtn.classList.add("mode-active");
    modeWebBtn.classList.remove("mode-active");
    viewBarcodeInspector.classList.remove("hidden");
    viewWebScanner.classList.add("hidden");
  }
}

if (modeWebBtn && modeBarcodeBtn) {
  modeWebBtn.addEventListener("click", () => switchAppMode("web"));
  modeBarcodeBtn.addEventListener("click", () => switchAppMode("barcode"));
}

// --- Barcode Input Tabs ---
const bcTabUpload = document.getElementById("bc-tab-upload");
const bcTabCamera = document.getElementById("bc-tab-camera");
const bcTabPaste = document.getElementById("bc-tab-paste");

const bcPanelUpload = document.getElementById("bc-panel-upload");
const bcPanelCamera = document.getElementById("bc-panel-camera");
const bcPanelPaste = document.getElementById("bc-panel-paste");

function switchBcInputTab(tab) {
  [bcTabUpload, bcTabCamera, bcTabPaste].forEach((b) => b && b.classList.remove("bc-tab-active"));
  [bcPanelUpload, bcPanelCamera, bcPanelPaste].forEach((p) => p && p.classList.add("hidden"));

  if (tab === "upload") {
    bcTabUpload.classList.add("bc-tab-active");
    bcPanelUpload.classList.remove("hidden");
    if (window.stopCameraScanner) window.stopCameraScanner();
  } else if (tab === "camera") {
    bcTabCamera.classList.add("bc-tab-active");
    bcPanelCamera.classList.remove("hidden");
  } else if (tab === "paste") {
    bcTabPaste.classList.add("bc-tab-active");
    bcPanelPaste.classList.remove("hidden");
    if (window.stopCameraScanner) window.stopCameraScanner();
  }
}

if (bcTabUpload && bcTabCamera && bcTabPaste) {
  bcTabUpload.addEventListener("click", () => switchBcInputTab("upload"));
  bcTabCamera.addEventListener("click", () => switchBcInputTab("camera"));
  bcTabPaste.addEventListener("click", () => switchBcInputTab("paste"));
}

// --- Barcode Results Elements ---
const bcPlaceholder = document.getElementById("bc-placeholder");
const bcResultsWrapper = document.getElementById("bc-results-wrapper");
const bcCategoryIcon = document.getElementById("bc-category-icon");
const bcCategoryName = document.getElementById("bc-category-name");
const bcSubtype = document.getElementById("bc-subtype");
const bcFormatBadge = document.getElementById("bc-format-badge");
const bcSafetyBadge = document.getElementById("bc-safety-badge");
const bcExpiryBanner = document.getElementById("bc-expiry-banner");
const bcExpiryIcon = document.getElementById("bc-expiry-icon");
const bcExpiryText = document.getElementById("bc-expiry-text");
const bcDetailsContainer = document.getElementById("bc-details-container");
const bcRawContent = document.getElementById("bc-raw-content");
const bcCopyRawBtn = document.getElementById("bc-copy-raw-btn");
const bcAiAnalysisBox = document.getElementById("bc-ai-analysis-box");
const bcExportPdfBtn = document.getElementById("bc-export-pdf-btn");

// Product Card Elements
const bcProductCard = document.getElementById("bc-product-card");
const bcProductImg = document.getElementById("bc-product-img");
const bcProductBrand = document.getElementById("bc-product-brand");
const bcProductTitle = document.getElementById("bc-product-title");
const bcProductMeta = document.getElementById("bc-product-meta");
const bcErrorMessage = document.getElementById("bc-error-message");

// Stores last barcode inspection result for PDF export
let lastBarcodeData = null;

function showBcError(msg) {
  const el = bcErrorMessage || document.getElementById("bc-error-message");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "";
  } else {
    el.classList.remove("hidden");
    el.innerHTML = typeof msg === "string" ? msg : String(msg);
  }
}

// --- Copy Decoded Content ---
if (bcCopyRawBtn) {
  bcCopyRawBtn.addEventListener("click", () => {
    if (bcRawContent && bcRawContent.textContent) {
      navigator.clipboard.writeText(bcRawContent.textContent).then(() => {
        bcCopyRawBtn.textContent = "✓ Copied!";
        setTimeout(() => {
          bcCopyRawBtn.textContent = "📋 Copy";
        }, 1500);
      });
    }
  });
}

// --- Inspect Barcode Payload (Backend Integration) ---
async function inspectBarcodePayload(content, format = "QR_CODE") {
  showBcError("");
  if (!content || !content.trim()) {
    showBcError("No barcode or QR content detected.");
    return;
  }

  if (bcPlaceholder) bcPlaceholder.classList.add("hidden");
  if (bcResultsWrapper) bcResultsWrapper.classList.remove("hidden");

  // Immediate lively loading feedback in the right inspection card
  if (bcCategoryIcon) bcCategoryIcon.textContent = "⚡";
  if (bcCategoryName) bcCategoryName.textContent = "Analyzing Payload...";
  if (bcSubtype) bcSubtype.textContent = "Querying GS1 product registry & AI Threat Auditor...";
  if (bcFormatBadge) bcFormatBadge.textContent = format || "INSPECTING";
  if (bcSafetyBadge) {
    bcSafetyBadge.textContent = "Auditing...";
    bcSafetyBadge.className = "severity-pill severity-medium";
  }
  if (bcRawContent) bcRawContent.textContent = content;
  if (bcAiAnalysisBox) {
    bcAiAnalysisBox.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;padding:12px;color:#38bdf8;">
        <span class="spinner-lg"></span>
        <div>
          <div style="font-weight:600;font-size:14px;color:#f1f5f9;">AI Threat Auditor &amp; Product Registry in Progress...</div>
          <div style="font-size:12px;color:#94a3b8;margin-top:2px;">Cross-referencing barcode prefix, safety patterns, and Gemini AI analysis.</div>
        </div>
      </div>
    `;
  }

  try {
    const res = await apiFetch("/analyze-barcode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: content.trim(), format }),
    });

    if (bcResultsWrapper) {
      bcResultsWrapper.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(errText || `Inspection failed with status ${res.status}`);
    }

    const data = await res.json();
    renderBarcodeResults(data);
  } catch (err) {
    console.error("Barcode inspection error:", err);
    showBcError(err.message || "Failed to inspect barcode with backend API.");
  }
}

// --- Render Barcode Results ---
function renderBarcodeResults(data) {
  if (!data) return;

  // Persist for PDF export
  lastBarcodeData = data;
  if (bcExportPdfBtn) bcExportPdfBtn.classList.remove("hidden");

  // 1. Category & Icon
  if (bcCategoryIcon) bcCategoryIcon.textContent = data.category_icon || "🏷️";
  if (bcCategoryName) bcCategoryName.textContent = data.category || "General Data";
  if (bcSubtype) bcSubtype.textContent = data.sub_type || "";

  // 2. Format Badge
  if (bcFormatBadge) bcFormatBadge.textContent = data.format || "QR_CODE";

  // 3. Safety Badge
  if (bcSafetyBadge) {
    const safety = (data.safety_level || "Safe").toLowerCase();
    bcSafetyBadge.textContent = data.safety_level || "Safe";
    if (safety === "safe") {
      bcSafetyBadge.className = "severity-pill severity-low";
    } else if (safety === "caution") {
      bcSafetyBadge.className = "severity-pill severity-medium";
    } else {
      bcSafetyBadge.className = "severity-pill severity-high";
    }
  }

  // 4. Expiry Banner
  if (bcExpiryBanner && bcExpiryText) {
    bcExpiryBanner.className = "bc-expiry-banner";
    const status = data.expiry_status || "";
    if (status.includes("EXPIRED")) {
      bcExpiryBanner.classList.add("expired");
      if (bcExpiryIcon) bcExpiryIcon.textContent = "⚠️";
    } else if (status.includes("ACTIVE")) {
      bcExpiryBanner.classList.add("active");
      if (bcExpiryIcon) bcExpiryIcon.textContent = "✅";
    } else {
      if (bcExpiryIcon) bcExpiryIcon.textContent = "⏰";
    }
    bcExpiryText.textContent = `${status}: ${data.expiry_details || ""}`;
  }

  // 4b. Product Showcase Card (for retail / consumer barcodes)
  if (bcProductCard) {
    const prod = data.product_info;
    if (prod && prod.found) {
      bcProductCard.classList.remove("hidden");
      if (bcProductTitle) bcProductTitle.textContent = prod.product_name || "Identified Product";
      if (bcProductBrand) bcProductBrand.textContent = prod.brand || "Retail Brand";

      if (bcProductImg) {
        if (prod.image_url) {
          bcProductImg.src = prod.image_url;
          bcProductImg.classList.remove("hidden");
        } else {
          bcProductImg.classList.add("hidden");
        }
      }

      if (bcProductMeta) {
        const catClean = prod.category ? prod.category.split(">").pop().trim() : "";
        bcProductMeta.innerHTML = `
          <span>🌍 Origin: <strong>${prod.origin_country || "International"}</strong></span>
          ${catClean ? `<span>📦 Category: <strong>${catClean}</strong></span>` : ""}
          ${prod.quantity ? `<span>⚖️ Size: <strong>${prod.quantity}</strong></span>` : ""}
        `;
      }
    } else {
      bcProductCard.classList.add("hidden");
    }
  }

  // 5. Detailed Attributes Grid
  if (bcDetailsContainer) {
    bcDetailsContainer.innerHTML = "";
    const details = data.details || {};
    const keys = Object.keys(details);

    if (keys.length === 0) {
      const item = document.createElement("div");
      item.className = "bc-detail-item";
      item.innerHTML = `
        <div class="bc-detail-key">Payload Type</div>
        <div class="bc-detail-val">${data.category || "Plain Text"}</div>
      `;
      bcDetailsContainer.appendChild(item);
    } else {
      keys.forEach((k) => {
        const item = document.createElement("div");
        item.className = "bc-detail-item";
        item.innerHTML = `
          <div class="bc-detail-key">${k}</div>
          <div class="bc-detail-val">${details[k]}</div>
        `;
        bcDetailsContainer.appendChild(item);
      });
    }

    // Add warnings if present
    if (Array.isArray(data.warnings) && data.warnings.length > 0) {
      data.warnings.forEach((w) => {
        const item = document.createElement("div");
        item.className = "bc-detail-item";
        item.style.borderColor = "#ef4444";
        item.innerHTML = `
          <div class="bc-detail-key" style="color:#f87171;">⚠️ Security Notice</div>
          <div class="bc-detail-val" style="color:#fca5a5;">${w}</div>
        `;
        bcDetailsContainer.appendChild(item);
      });
    }
  }

  // 6. Raw Content
  if (bcRawContent) {
    bcRawContent.textContent = data.raw_content || "";
  }

  // 7. AI Security Audit Box
  if (bcAiAnalysisBox) {
    const aiText = data.ai_analysis || "";
    if (aiText.startsWith("AI analysis unavailable:") || aiText.startsWith("AI analysis failed:")) {
      bcAiAnalysisBox.innerHTML = `
        <div class="info-box" style="border-color: rgba(234, 179, 8, 0.45); background: rgba(30, 41, 59, 0.85);">
          <div class="info-icon" style="font-size:24px;">⚠️</div>
          <div>
            <div class="info-title" style="color:#fcd34d; margin-bottom:6px;">AI Threat Intelligence Notice</div>
            <p class="info-text" style="color:#e2e8f0; margin-bottom:8px;">${aiText}</p>
            <div style="font-size:12px; color:#94a3b8; background:rgba(15,23,42,0.6); padding:8px 12px; border-radius:6px; border:1px solid rgba(148,163,184,0.2);">
              💡 <strong>How to configure:</strong> Add your valid Google Gemini API key to <code>backend/.env</code>:<br>
              <code style="color:#38bdf8;">GEMINI_API_KEY=your_key_here</code><br>
              Get a free API key at <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener" style="color:#38bdf8; text-decoration:underline;">Google AI Studio</a>.
            </div>
          </div>
        </div>
      `;
    } else if (aiText.includes("###")) {
      renderAiAnalysisContent(aiText, bcAiAnalysisBox);
    } else {
      bcAiAnalysisBox.textContent = aiText || "No AI analysis returned.";
    }
  }
}

// Helper to format AI breakdown into styled cards
function renderAiAnalysisContent(aiText, container) {
  container.innerHTML = "";
  const sections = aiText.split(/(?=###\s+)/);
  const cont = document.createElement("div");
  cont.className = "ai-report-container";

  sections.forEach((sec) => {
    const trimmed = sec.trim();
    if (!trimmed) return;

    const card = document.createElement("div");
    card.className = "ai-report-card";

    const titleMatch = trimmed.match(/###\s*([^\n\r]+)/);
    const title = titleMatch ? titleMatch[1].trim() : "Audit Finding";

    const titleEl = document.createElement("div");
    titleEl.className = "ai-vuln-title";
    titleEl.textContent = title;
    card.appendChild(titleEl);

    const bodyText = trimmed.replace(/###\s*[^\n\r]+/, "").trim();
    const lines = bodyText.split("\n");

    lines.forEach((l) => {
      const cl = l.trim();
      if (!cl) return;
      if (cl.startsWith("🔸") || cl.startsWith("-") || cl.startsWith("*")) {
        const p = document.createElement("div");
        p.className = "ai-summary-text";
        p.style.marginTop = "4px";
        p.textContent = cl;
        card.appendChild(p);
      } else {
        const p = document.createElement("div");
        p.className = "ai-summary-text";
        p.textContent = cl;
        card.appendChild(p);
      }
    });

    cont.appendChild(card);
  });

  container.appendChild(cont);
}

// --- Image File Upload & Decoding (html5-qrcode) ---
const dropZone = document.getElementById("drop-zone");
const barcodeFileInput = document.getElementById("barcode-file-input");
const filePreviewWrapper = document.getElementById("file-preview-wrapper");
const filePreviewImg = document.getElementById("file-preview-img");
const fileClearBtn = document.getElementById("file-clear-btn");

let html5QrCodeDetector = null;   // for file scanning only
let cameraDetector = null;         // dedicated camera instance

function getQrDetector() {
  if (!html5QrCodeDetector && window.Html5Qrcode) {
    html5QrCodeDetector = new Html5Qrcode("qr-reader-file-helper");
  }
  return html5QrCodeDetector;
}

if (dropZone && barcodeFileInput) {
  dropZone.addEventListener("click", () => barcodeFileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleImageBarcodeFile(e.dataTransfer.files[0]);
    }
  });

  barcodeFileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleImageBarcodeFile(e.target.files[0]);
    }
  });
}

// Canvas-based QR decoder using jsQR (handles central logos like Google Pay / PhonePe / UPI)
function decodeCanvasWithJsQR(imgElement) {
  try {
    if (!window.jsQR) return null;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const w = imgElement.naturalWidth || imgElement.width;
    const h = imgElement.naturalHeight || imgElement.height;

    // Pass 1: Native size
    canvas.width = w;
    canvas.height = h;
    ctx.drawImage(imgElement, 0, 0);

    let imgData = ctx.getImageData(0, 0, w, h);
    let code = jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: "attemptBoth",
    });
    if (code && code.data) return code.data;

    // Pass 2: Downscaled if high resolution
    if (w > 800 || h > 800) {
      const scale = Math.min(800 / w, 800 / h);
      const sW = Math.round(w * scale);
      const sH = Math.round(h * scale);
      canvas.width = sW;
      canvas.height = sH;
      ctx.drawImage(imgElement, 0, 0, sW, sH);

      imgData = ctx.getImageData(0, 0, sW, sH);
      code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: "attemptBoth",
      });
      if (code && code.data) return code.data;
    }

    // Pass 3: Grayscale / High-contrast thresholding (for dark borders/frames)
    const d = imgData.data;
    for (let i = 0; i < d.length; i += 4) {
      const gray = d[i] * 0.299 + d[i + 1] * 0.587 + d[i + 2] * 0.114;
      const v = gray > 120 ? 255 : 0;
      d[i] = v;
      d[i + 1] = v;
      d[i + 2] = v;
    }
    ctx.putImageData(imgData, 0, 0);
    code = jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: "attemptBoth",
    });
    if (code && code.data) return code.data;

    return null;
  } catch (e) {
    console.warn("jsQR error:", e);
    return null;
  }
}

async function handleImageBarcodeFile(file) {
  showBcError("");
  if (!file.type.startsWith("image/")) {
    showBcError("Please select a valid image file (PNG, JPG, WEBP).");
    return;
  }

  // Show preview in UI
  const reader = new FileReader();
  reader.onload = (e) => {
    const dataUrl = e.target.result;
    if (filePreviewImg) filePreviewImg.src = dataUrl;
    if (filePreviewWrapper) filePreviewWrapper.classList.remove("hidden");
    if (dropZone) dropZone.classList.add("hidden");

    const img = new Image();
    img.onload = async () => {
      // Pass 1: Browser Native BarcodeDetector (instant hardware ML acceleration on Chrome/Edge/Android)
      if ("BarcodeDetector" in window) {
        try {
          const supported = await BarcodeDetector.getSupportedFormats();
          const bd = new BarcodeDetector({ formats: supported });
          const barcodes = await bd.detect(img);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            inspectBarcodePayload(barcodes[0].rawValue, barcodes[0].format?.toUpperCase() || "BARCODE");
            return;
          }
        } catch (nativeErr) {
          console.warn("Native BarcodeDetector pass:", nativeErr);
        }
      }

      // Pass 2: High-contrast canvas jsQR (handles central logos like GPay / PhonePe / UPI)
      const jsQrResult = decodeCanvasWithJsQR(img);
      if (jsQrResult) {
        inspectBarcodePayload(jsQrResult, "QR_CODE");
        return;
      }

      // Pass 3: Powerful Backend AI Optical Scanner (zxing-cpp + Gemini Vision)
      // Handles blurry, low-resolution, tilted photos or unaligned retail barcodes
      sendImageToBackendAiDecoder(file);
    };
    img.src = dataUrl;
  };
  reader.readAsDataURL(file);
}

// Send image to backend for C++ and Gemini Vision optical barcode decoding
async function sendImageToBackendAiDecoder(fileOrBlob) {
  showBcError("");
  if (bcPlaceholder) bcPlaceholder.classList.add("hidden");
  if (bcResultsWrapper) bcResultsWrapper.classList.remove("hidden");

  if (bcCategoryName) bcCategoryName.textContent = "AI Optical Scanner...";
  if (bcSubtype) bcSubtype.textContent = "Decoding barcode via C++ and Gemini Vision...";
  if (bcRawContent) bcRawContent.textContent = "Analyzing image pixels...";
  if (bcAiAnalysisBox) bcAiAnalysisBox.textContent = "Detecting code structure, reading numbers, and fetching product identity...";

  try {
    const formData = new FormData();
    formData.append("file", fileOrBlob, "barcode.png");

    const res = await apiFetch("/decode-barcode-image", {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Inspection failed with status ${res.status}`);
    }

    const data = await res.json();
    renderBarcodeResults(data);
  } catch (err) {
    console.error("AI Decoder Error:", err);
    showBcError(err.message || "Failed to decode barcode from image.");
  }
}

if (fileClearBtn) {
  fileClearBtn.addEventListener("click", () => {
    if (barcodeFileInput) barcodeFileInput.value = "";
    if (filePreviewWrapper) filePreviewWrapper.classList.add("hidden");
    if (dropZone) dropZone.classList.remove("hidden");
    showBcError("");
  });
}

// --- Dual-Engine Live Camera Scanner (Html5Qrcode + Pure Native getUserMedia Fallback) ---
const cameraStartBtn = document.getElementById("camera-start-btn");
const cameraStartText = document.getElementById("camera-start-btn-text");
const cameraStartSpinner = document.getElementById("camera-start-btn-spinner");
const cameraSnapBtn = document.getElementById("camera-snap-btn");
const cameraStopBtn = document.getElementById("camera-stop-btn");
const cameraStatusBanner = document.getElementById("camera-status-banner");

let isCameraRunning = false;
let activeCameraStream = null;
let cameraFrameTimer = null;

window.startCameraScanner = async function () {
  showBcError("");
  const readerEl = document.getElementById("qr-reader");
  if (!readerEl) return;

  await window.stopCameraScanner();

  // High-tech HUD Reticle Loading Screen in Viewfinder
  readerEl.innerHTML = `
    <div class="camera-hud-viewfinder">
      <div class="hud-reticle">
        <span class="hud-corner tl"></span>
        <span class="hud-corner tr"></span>
        <span class="hud-corner bl"></span>
        <span class="hud-corner br"></span>
        <div class="hud-pulse-radar"></div>
      </div>
      <div style="font-weight: 700; font-size: 15px; color: #38bdf8;">Connecting Camera Stream...</div>
      <div style="font-size: 12px; color: #94a3b8; margin-top: 6px;">Please tap "Allow" if your browser prompts for webcam access</div>
    </div>
  `;

  if (cameraStartBtn) {
    cameraStartBtn.disabled = true;
    cameraStartBtn.classList.add("is-loading");
  }
  if (cameraStartText) cameraStartText.textContent = "Connecting Camera...";
  if (cameraStartSpinner) cameraStartSpinner.classList.remove("hidden");

  if (cameraStatusBanner) {
    cameraStatusBanner.className = "pulsing-status";
    cameraStatusBanner.classList.remove("hidden");
    cameraStatusBanner.innerHTML = `
      <span class="spinner-lg"></span>
      <div>
        <div style="font-weight: 700; color: #ffffff;">Requesting Camera Stream...</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 2px;">Establishing video hardware connection. Look for permission prompt in address bar.</div>
      </div>
    `;
  }

  let started = false;

  // 1. Primary Engine: Pure HTML5 getUserMedia Video Stream with Laser Scanline HUD
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error(window.location.protocol === "file:"
        ? "Webcam blocked by browser on file:/// URLs. Please open http://localhost:5000 in your browser."
        : "Webcam API not supported or permissions blocked in this browser.");
    }

    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { ideal: 1280 },
        height: { ideal: 720 },
      },
    });
    activeCameraStream = stream;

    readerEl.innerHTML = "";

    // Container with laser sweep line
    const container = document.createElement("div");
    container.className = "camera-viewfinder-container";

    const laser = document.createElement("div");
    laser.className = "laser-scan-line";
    container.appendChild(laser);

    const video = document.createElement("video");
    video.id = "bc-native-live-video";
    video.autoplay = true;
    video.playsInline = true;
    video.muted = true;
    video.style.width = "100%";
    video.style.height = "260px";
    video.style.objectFit = "cover";
    video.srcObject = stream;
    container.appendChild(video);
    readerEl.appendChild(container);

    await video.play();
    started = true;

    if (cameraStatusBanner) {
      cameraStatusBanner.className = "pulsing-status status-success";
      cameraStatusBanner.innerHTML = `
        <span style="font-size: 18px;">🟢</span>
        <div>
          <div style="font-weight: 700; color: #34d399;">Live Camera Scanner Active!</div>
          <div style="font-size: 12px; color: #a7f3d0; margin-top: 1px;">Center any barcode/QR code in the viewfinder or click <strong>Snap &amp; AI Inspect</strong>.</div>
        </div>
      `;
    }

    // Real-time canvas scanning loop (scans frames every 250ms)
    let nativeDetector = null;
    if ("BarcodeDetector" in window) {
      try {
        const formats = await BarcodeDetector.getSupportedFormats().catch(() => []);
        nativeDetector = new BarcodeDetector({ formats: formats.length > 0 ? formats : ["qr_code", "ean_13", "upc_a", "code_128"] });
      } catch (_) {}
    }

    cameraFrameTimer = setInterval(async () => {
      const v = document.querySelector("#qr-reader video");
      if (!v || v.readyState < 2 || !v.videoWidth) return;
      try {
        if (nativeDetector) {
          const detected = await nativeDetector.detect(v);
          if (detected && detected.length > 0 && detected[0].rawValue) {
            clearInterval(cameraFrameTimer);
            window.stopCameraScanner();
            inspectBarcodePayload(detected[0].rawValue, detected[0].format?.toUpperCase() || "BARCODE");
            return;
          }
        }
        if (window.jsQR) {
          const canvas = document.createElement("canvas");
          canvas.width = Math.min(v.videoWidth, 640);
          canvas.height = Math.min(v.videoHeight, 480);
          const ctx = canvas.getContext("2d");
          ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
          const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const qr = jsQR(imgData.data, imgData.width, imgData.height);
          if (qr && qr.data) {
            clearInterval(cameraFrameTimer);
            window.stopCameraScanner();
            inspectBarcodePayload(qr.data, "QR_CODE");
            return;
          }
        }
      } catch (_) {}
    }, 250);

  } catch (nativeErr) {
    console.warn("Native getUserMedia error, attempting Html5Qrcode fallback:", nativeErr);

    // 2. Secondary Engine: Html5Qrcode Fallback
    if (window.Html5Qrcode) {
      try {
        readerEl.innerHTML = "";
        cameraDetector = new Html5Qrcode("qr-reader", { verbose: false });
        const scanConfig = {
          fps: 15,
          qrbox: (w, h) => ({
            width: Math.min(Math.floor(w * 0.85), 320),
            height: Math.min(Math.floor(h * 0.6), 200),
          }),
        };
        const onSuccess = (decodedText, decodedResult) => {
          const fmt = decodedResult?.result?.format?.formatName || "QR_CODE";
          window.stopCameraScanner();
          inspectBarcodePayload(decodedText, fmt);
        };

        const devices = await Html5Qrcode.getCameras().catch(() => []);
        const cameraId = devices && devices.length > 0 ? devices[0].id : { facingMode: "user" };
        await cameraDetector.start(cameraId, scanConfig, onSuccess, () => {});
        started = true;
        if (cameraStatusBanner) {
          cameraStatusBanner.className = "pulsing-status status-success";
          cameraStatusBanner.innerHTML = `
            <span style="font-size: 18px;">🟢</span>
            <div>
              <div style="font-weight: 700; color: #34d399;">Camera Scanner Active</div>
              <div style="font-size: 12px; color: #a7f3d0; margin-top: 1px;">Align code inside the viewfinder.</div>
            </div>
          `;
        }
      } catch (h5Err) {
        console.error("All camera engines failed:", h5Err);
      }
    }
  }

  if (started) {
    isCameraRunning = true;
    if (cameraStartBtn) cameraStartBtn.classList.add("hidden");
    if (cameraSnapBtn) cameraSnapBtn.classList.remove("hidden");
    if (cameraStopBtn) cameraStopBtn.classList.remove("hidden");
  } else {
    if (readerEl) readerEl.innerHTML = "";
    const isFileUrl = window.location.protocol === "file:";
    const errorMsg = isFileUrl
      ? "⚠️ Browsers block camera access on <code>file:///</code> URLs. Please open <strong><a href='http://localhost:5000' style='color:#38bdf8;text-decoration:underline;'>http://localhost:5000</a></strong> in your browser!"
      : "⚠️ Could not open camera. Please check camera permissions in your browser settings (look for lock icon in address bar).";

    if (cameraStatusBanner) {
      cameraStatusBanner.className = "pulsing-status status-error";
      cameraStatusBanner.classList.remove("hidden");
      cameraStatusBanner.innerHTML = `
        <span style="font-size: 18px;">⚠️</span>
        <div>
          <div style="font-weight: 700; color: #f87171;">Camera Access Blocked</div>
          <div style="font-size: 12px; color: #fca5a5; margin-top: 2px;">${errorMsg}</div>
        </div>
      `;
    }
    showBcError(errorMsg);
  }

  if (cameraStartBtn) {
    cameraStartBtn.disabled = false;
    cameraStartBtn.classList.remove("is-loading");
    if (cameraStartText) cameraStartText.textContent = "Start Camera Scanner";
    if (cameraStartSpinner) cameraStartSpinner.classList.add("hidden");
  }
};

window.snapCameraFrame = function () {
  const video = document.querySelector("#qr-reader video");
  if (!video || !video.videoWidth) {
    showBcError("Camera video feed is not ready yet. Please wait a moment and try again.");
    return;
  }

  if (cameraSnapBtn) {
    cameraSnapBtn.disabled = true;
    cameraSnapBtn.textContent = "📸 Inspecting Snapshot...";
  }

  const canvas = document.createElement("canvas");
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

  canvas.toBlob((blob) => {
    if (blob) {
      window.stopCameraScanner();
      sendImageToBackendAiDecoder(blob);
    }
    if (cameraSnapBtn) {
      cameraSnapBtn.disabled = false;
      cameraSnapBtn.textContent = "📸 Snap & AI Inspect";
    }
  }, "image/png");
};

window.stopCameraScanner = async function () {
  if (cameraFrameTimer) {
    clearInterval(cameraFrameTimer);
    cameraFrameTimer = null;
  }

  if (activeCameraStream) {
    activeCameraStream.getTracks().forEach((track) => track.stop());
    activeCameraStream = null;
  }

  if (cameraDetector) {
    try {
      await cameraDetector.stop().catch(() => {});
    } catch (_) {}
    try {
      cameraDetector.clear();
    } catch (_) {}
    cameraDetector = null;
  }

  const readerEl = document.getElementById("qr-reader");
  if (readerEl) readerEl.innerHTML = "";

  isCameraRunning = false;
  if (cameraStartBtn) {
    cameraStartBtn.classList.remove("hidden");
    cameraStartBtn.disabled = false;
    cameraStartBtn.classList.remove("is-loading");
  }
  if (cameraStartText) cameraStartText.textContent = "Start Camera Scanner";
  if (cameraStartSpinner) cameraStartSpinner.classList.add("hidden");
  if (cameraSnapBtn) cameraSnapBtn.classList.add("hidden");
  if (cameraStopBtn) cameraStopBtn.classList.add("hidden");
  if (cameraStatusBanner) cameraStatusBanner.classList.add("hidden");
};

// Wire up event listeners
if (cameraStartBtn) {
  cameraStartBtn.addEventListener("click", window.startCameraScanner);
}
if (cameraSnapBtn) {
  cameraSnapBtn.addEventListener("click", window.snapCameraFrame);
}
if (cameraStopBtn) {
  cameraStopBtn.addEventListener("click", window.stopCameraScanner);
}

// --- Paste Raw Payload Text Mode ---
const barcodeRawText = document.getElementById("barcode-raw-text");
const inspectTextBtn = document.getElementById("inspect-text-btn");
const inspectTextBtnText = document.getElementById("inspect-text-btn-text");
const inspectTextBtnSpinner = document.getElementById("inspect-text-btn-spinner");
const pasteStatusBanner = document.getElementById("paste-status-banner");

window.runTextInspection = async function () {
  const rawInput = barcodeRawText ? barcodeRawText.value.trim() : "";
  if (!rawInput) {
    showBcError("Please paste or enter barcode numbers, URL, or payload text to inspect.");
    if (barcodeRawText) barcodeRawText.focus();
    return;
  }

  showBcError("");

  // Normalize spaces/hyphens for numeric barcodes e.g. "3 337875 597371" -> "3337875597371"
  const stripped = rawInput.replace(/[\s\-]+/g, "");
  const payloadToSend = (/^\d{8,14}$/.test(stripped)) ? stripped : rawInput;

  // Immediate lively button & banner processing state
  if (inspectTextBtn) {
    inspectTextBtn.disabled = true;
    inspectTextBtn.classList.add("is-loading");
  }
  if (inspectTextBtnText) inspectTextBtnText.textContent = "Analyzing Payload...";
  if (inspectTextBtnSpinner) inspectTextBtnSpinner.classList.remove("hidden");

  if (pasteStatusBanner) {
    pasteStatusBanner.className = "pulsing-status";
    pasteStatusBanner.classList.remove("hidden");
    pasteStatusBanner.innerHTML = `
      <span class="spinner-lg"></span>
      <div>
        <div style="font-weight: 700; color: #ffffff;">Analyzing Barcode &amp; AI Security...</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 2px;">Querying global GS1 product databases &amp; AI quishing threat auditor...</div>
      </div>
    `;
  }

  try {
    await inspectBarcodePayload(payloadToSend, "RAW_PAYLOAD");
    if (pasteStatusBanner) {
      pasteStatusBanner.className = "pulsing-status status-success";
      pasteStatusBanner.innerHTML = `
        <span style="font-size: 18px;">✅</span>
        <div>
          <div style="font-weight: 700; color: #34d399;">Inspection Complete!</div>
          <div style="font-size: 12px; color: #a7f3d0; margin-top: 1px;">Product identification and threat report displayed on the right.</div>
        </div>
      `;
      setTimeout(() => {
        if (pasteStatusBanner && pasteStatusBanner.classList.contains("status-success")) {
          pasteStatusBanner.classList.add("hidden");
        }
      }, 4000);
    }
  } catch (err) {
    if (pasteStatusBanner) {
      pasteStatusBanner.className = "pulsing-status status-error";
      pasteStatusBanner.innerHTML = `
        <span style="font-size: 18px;">❌</span>
        <div>
          <div style="font-weight: 700; color: #f87171;">Inspection Failed</div>
          <div style="font-size: 12px; color: #fca5a5; margin-top: 1px;">${err.message || "Failed to inspect barcode"}</div>
        </div>
      `;
    }
  } finally {
    if (inspectTextBtn) {
      inspectTextBtn.disabled = false;
      inspectTextBtn.classList.remove("is-loading");
    }
    if (inspectTextBtnText) inspectTextBtnText.textContent = "Inspect Payload";
    if (inspectTextBtnSpinner) inspectTextBtnSpinner.classList.add("hidden");
  }
};

if (inspectTextBtn) {
  inspectTextBtn.addEventListener("click", window.runTextInspection);
}

if (barcodeRawText) {
  barcodeRawText.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      window.runTextInspection();
    }
  });
}

// =========================================================
// === BARCODE PDF REPORT EXPORT ===
// =========================================================

function handleExportBarcodePdf() {
  if (!lastBarcodeData) {
    alert("No barcode inspection data to export. Please inspect a barcode first.");
    return;
  }

  if (!window.jspdf || !window.jspdf.jsPDF) {
    alert("PDF library not loaded yet. Please wait and try again.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "pt", format: "a4" });

  const margin = 40;
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const contentWidth = pageWidth - 2 * margin;

  const data = lastBarcodeData;
  const now = new Date();
  const dateStr = now.toLocaleDateString("en-IN", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
  const timeStr = now.toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit",
  });

  let y = 0;
  let pageNumber = 1;

  // --- Helper: Page Break ---
  function ensureSpace(neededHeight) {
    if (y + neededHeight > pageHeight - 50) {
      addFooter();
      doc.addPage();
      pageNumber++;
      y = 50;
      return true;
    }
    return false;
  }

  // --- Helper: Footer ---
  function addFooter() {
    doc.setFillColor(15, 23, 42);
    doc.rect(0, pageHeight - 30, pageWidth, 30, "F");
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text("Barcode & QR Inspector Report | Web-Vul Security Suite", margin, pageHeight - 12);
    doc.text("Page " + pageNumber, pageWidth - margin - 35, pageHeight - 12);
  }

  // --- Helper: Section Heading ---
  function drawSectionHeading(title) {
    ensureSpace(40);
    doc.setFillColor(30, 41, 59);
    doc.roundedRect(margin, y, contentWidth, 26, 4, 4, "F");
    doc.setFontSize(11);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(226, 232, 240);
    doc.text(title, margin + 10, y + 17);
    y += 34;
  }

  // --- Helper: Wrapped text block ---
  function drawWrappedText(text, fontSize, color, maxWidth, lineHeight) {
    doc.setFontSize(fontSize);
    doc.setTextColor(color[0], color[1], color[2]);
    doc.setFont("helvetica", "normal");
    const lines = doc.splitTextToSize(text || "", maxWidth || contentWidth);
    lines.forEach((line) => {
      ensureSpace(lineHeight + 4);
      doc.text(line, margin + 8, y);
      y += lineHeight;
    });
  }

  // =====================================================
  // PAGE 1: HEADER BANNER
  // =====================================================
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 80, "F");

  // Accent strip
  doc.setFillColor(99, 102, 241);
  doc.rect(0, 80, pageWidth, 4, "F");

  // Title
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(255, 255, 255);
  doc.text("Barcode & QR Code Inspection Report", margin, 35);

  // Subtitle
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(148, 163, 184);
  doc.text("Web-Vul Security Suite | Generated: " + dateStr + " at " + timeStr, margin, 55);

  // Confidential tag
  doc.setFillColor(239, 68, 68);
  doc.roundedRect(pageWidth - margin - 100, 20, 100, 22, 4, 4, "F");
  doc.setFontSize(9);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(255, 255, 255);
  doc.text("CONFIDENTIAL", pageWidth - margin - 85, 35);

  y = 100;

  // =====================================================
  // OVERVIEW SCORECARD
  // =====================================================
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 100, 6, 6, "F");

  const cardInnerY = y + 16;
  const col1 = margin + 16;
  const col2 = margin + contentWidth / 3;
  const col3 = margin + (contentWidth * 2) / 3;

  // Column 1: Category
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.text("CATEGORY", col1, cardInnerY);

  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(226, 232, 240);
  const catText = (data.category || "General Data");
  doc.text(catText, col1, cardInnerY + 20);

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(148, 163, 184);
  doc.text(data.sub_type || "", col1, cardInnerY + 36);

  // Column 2: Format & Safety
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text("FORMAT", col2, cardInnerY);

  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(226, 232, 240);
  doc.text(data.format || "QR_CODE", col2, cardInnerY + 20);

  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text("SAFETY LEVEL", col2, cardInnerY + 44);

  const safetyText = data.safety_level || "Safe";
  const safetyColor = safetyText.toLowerCase() === "safe"
    ? [34, 197, 94]
    : safetyText.toLowerCase() === "caution"
    ? [234, 179, 8]
    : [239, 68, 68];
  doc.setFillColor(safetyColor[0], safetyColor[1], safetyColor[2]);
  doc.roundedRect(col2, cardInnerY + 50, 70, 18, 4, 4, "F");
  doc.setFontSize(10);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(255, 255, 255);
  doc.text(safetyText, col2 + 8, cardInnerY + 63);

  // Column 3: Expiry Status
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.text("EXPIRY STATUS", col3, cardInnerY);

  const expiryStatus = data.expiry_status || "No Expiry Data";
  const expiryColor = expiryStatus.includes("EXPIRED")
    ? [239, 68, 68]
    : expiryStatus.includes("ACTIVE")
    ? [34, 197, 94]
    : [148, 163, 184];
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(expiryColor[0], expiryColor[1], expiryColor[2]);
  doc.text(expiryStatus, col3, cardInnerY + 20);

  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(148, 163, 184);
  const expiryDetail = data.expiry_details || "";
  if (expiryDetail) {
    const wrappedExpiry = doc.splitTextToSize(expiryDetail, contentWidth / 3 - 20);
    wrappedExpiry.forEach((line, i) => {
      doc.text(line, col3, cardInnerY + 34 + i * 12);
    });
  }

  y += 116;

  // =====================================================
  // DETAILED ATTRIBUTES TABLE
  // =====================================================
  drawSectionHeading("Detailed Attributes & Purpose");

  const details = data.details || {};
  const detailKeys = Object.keys(details);

  if (detailKeys.length > 0) {
    // Table header
    doc.setFillColor(51, 65, 85);
    doc.roundedRect(margin, y, contentWidth, 22, 3, 3, "F");
    doc.setFontSize(9);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(226, 232, 240);
    doc.text("ATTRIBUTE", margin + 10, y + 15);
    doc.text("VALUE", margin + contentWidth * 0.4, y + 15);
    y += 26;

    detailKeys.forEach((key, idx) => {
      ensureSpace(22);
      // Alternating row bg
      if (idx % 2 === 0) {
        doc.setFillColor(30, 41, 59);
        doc.rect(margin, y - 4, contentWidth, 20, "F");
      }

      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(148, 163, 184);
      doc.text(String(key), margin + 10, y + 10);

      doc.setFont("helvetica", "normal");
      doc.setTextColor(226, 232, 240);
      const val = String(details[key] || "");
      const valWrapped = doc.splitTextToSize(val, contentWidth * 0.55);
      doc.text(valWrapped[0] || "", margin + contentWidth * 0.4, y + 10);
      y += 20;

      // Handle multi-line values
      if (valWrapped.length > 1) {
        for (let vi = 1; vi < valWrapped.length; vi++) {
          ensureSpace(16);
          doc.text(valWrapped[vi], margin + contentWidth * 0.4, y + 6);
          y += 14;
        }
      }
    });
  } else {
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text("No structured attributes extracted.", margin + 8, y + 4);
    y += 20;
  }

  y += 8;

  // =====================================================
  // WARNINGS SECTION (if any)
  // =====================================================
  if (Array.isArray(data.warnings) && data.warnings.length > 0) {
    drawSectionHeading("Security Warnings");

    data.warnings.forEach((w) => {
      ensureSpace(30);
      doc.setFillColor(60, 20, 20);
      doc.roundedRect(margin + 4, y - 2, contentWidth - 8, 22, 3, 3, "F");
      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(248, 113, 113);
      doc.text("! " + w, margin + 12, y + 12);
      y += 28;
    });

    y += 4;
  }

  // =====================================================
  // RAW DECODED CONTENT
  // =====================================================
  drawSectionHeading("Raw Decoded Content");

  const rawContent = data.raw_content || "";
  doc.setFillColor(15, 23, 42);
  doc.setDrawColor(51, 65, 85);

  const rawLines = doc.splitTextToSize(rawContent, contentWidth - 24);
  const rawBlockHeight = Math.min(rawLines.length * 13 + 16, 180);
  ensureSpace(rawBlockHeight + 10);

  doc.roundedRect(margin, y, contentWidth, rawBlockHeight, 4, 4, "FD");

  doc.setFontSize(8);
  doc.setFont("courier", "normal");
  doc.setTextColor(167, 243, 208);

  let rawY = y + 14;
  const maxRawLines = Math.floor((rawBlockHeight - 16) / 13);
  rawLines.slice(0, maxRawLines).forEach((line) => {
    doc.text(line, margin + 12, rawY);
    rawY += 13;
  });
  if (rawLines.length > maxRawLines) {
    doc.setTextColor(148, 163, 184);
    doc.text("... (content truncated in report)", margin + 12, rawY);
  }

  y += rawBlockHeight + 12;

  // =====================================================
  // AI SECURITY & QUISHING AUDIT
  // =====================================================
  drawSectionHeading("AI Security & Threat Intelligence Audit");

  const aiText = data.ai_analysis || "No AI analysis available.";

  // Split AI text into sections if it has markdown headers
  if (aiText.includes("###")) {
    const sections = aiText.split(/(?=###\s+)/);
    sections.forEach((sec) => {
      const trimmed = sec.trim();
      if (!trimmed) return;

      const titleMatch = trimmed.match(/###\s*([^\n\r]+)/);
      const sectionTitle = titleMatch ? titleMatch[1].trim() : "Audit Finding";
      const bodyText = trimmed.replace(/###\s*[^\n\r]+/, "").trim();

      // Section card
      ensureSpace(50);
      doc.setFillColor(30, 41, 59);
      doc.roundedRect(margin + 4, y, contentWidth - 8, 24, 3, 3, "F");
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(129, 140, 248);
      doc.text(sectionTitle, margin + 14, y + 16);
      y += 30;

      // Body lines
      const bodyLines = bodyText.split("\n");
      bodyLines.forEach((l) => {
        const cl = l.trim();
        if (!cl) return;
        ensureSpace(16);

        if (cl.startsWith("-") || cl.startsWith("*") || cl.startsWith("•")) {
          doc.setFontSize(9);
          doc.setFont("helvetica", "normal");
          doc.setTextColor(203, 213, 225);
          const bulletText = cl.replace(/^[-*•]\s*/, "");
          const wrapped = doc.splitTextToSize("  " + bulletText, contentWidth - 30);
          wrapped.forEach((wl) => {
            ensureSpace(14);
            doc.text(wl, margin + 16, y);
            y += 13;
          });
        } else {
          doc.setFontSize(9);
          doc.setFont("helvetica", "normal");
          doc.setTextColor(203, 213, 225);
          const wrapped = doc.splitTextToSize(cl, contentWidth - 20);
          wrapped.forEach((wl) => {
            ensureSpace(14);
            doc.text(wl, margin + 10, y);
            y += 13;
          });
        }
      });

      y += 8;
    });
  } else {
    // Plain text AI analysis
    drawWrappedText(aiText, 9, [203, 213, 225], contentWidth - 16, 14);
  }

  // --- Add footer on the last page ---
  addFooter();

  // --- Save the PDF ---
  const safeCat = (data.category || "barcode").replace(/[^a-zA-Z0-9]/g, "_").toLowerCase();
  const fileName = "barcode_report_" + safeCat + "_" + now.toISOString().slice(0, 10) + ".pdf";
  doc.save(fileName);
}

// Wire up barcode PDF export button
if (bcExportPdfBtn) {
  bcExportPdfBtn.addEventListener("click", handleExportBarcodePdf);
}
