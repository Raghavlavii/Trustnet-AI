/* ============================================================
   TrustNet AI — script.js (FINAL STABLE BUILD)
   ============================================================ */

const BASE_URL = '';

const state = {
  sessionId: null,
  reportId: null,
  isAnalyzing: false,
  isChatting: false,
};

const $ = (id) => document.getElementById(id);

const dom = {
  messageInput: $('messageInput'),
  charCount: $('charCount'),
  analyzeBtn: $('analyzeBtn'),
  emptyState: $('emptyState'),
  resultsCard: $('resultsCard'),
  chatCard: $('chatCard'),
  intelCard: $('intelCard'),
  reportCard: $('reportCard'),
  loadingOverlay: $('loadingOverlay'),
  statusDot: $('statusDot'),
  statusLabel: $('statusLabel'),
  toast: $('toast'),
  toastIcon: $('toastIcon'),
  toastMsg: $('toastMsg'),

  resultLabelBadge: $('resultLabelBadge'),
  verdictBanner: $('verdictBanner'),
  verdictIcon: $('verdictIcon'),
  verdictLabel: $('verdictLabel'),
  verdictSub: $('verdictSub'),
  trustScoreVal: $('trustScoreVal'),
  trustRingFill: $('trustRingFill'),
  mlProbBar: $('mlProbBar'),
  mlProbVal: $('mlProbVal'),
  llmExplanation: $('llmExplanation'),

  intelLoading: $('intelLoading'),
  intelGrid: $('intelGrid'),
  intelPhonesVal: $('intelPhonesVal'),
  intelUrlsVal: $('intelUrlsVal'),
  intelPaymentVal: $('intelPaymentVal'),
  intelScamTypeVal: $('intelScamTypeVal'),
  intelRiskVal: $('intelRiskVal'),

  chatMessages: $('chatMessages'),
  chatInput: $('chatInput'),
  sendBtn: $('sendBtn'),

  // ✅ Already existed in HTML, just ensuring mapping
  reportPreview: $('reportPreview'),
  reportContent: $('reportContent'),
};

/* ================== HELPERS ================== */

function setStatus(state, label) {
  dom.statusDot.className = 'status-dot';
  if (state !== 'ready') dom.statusDot.classList.add(state);
  dom.statusLabel.textContent = label;
}

function showToast(msg, type = 'error') {
  const icons = { error: '⚠️', success: '✅', info: 'ℹ️' };
  dom.toastIcon.textContent = icons[type];
  dom.toastMsg.textContent = msg;
  dom.toast.className = `toast toast--${type}`;
  setTimeout(() => dom.toast.classList.add('hidden'), 4000);
}

function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }

function showLoading(v) {
  dom.loadingOverlay.classList.toggle('hidden', !v);
  dom.analyzeBtn.disabled = v;
}

async function apiFetch(url, options = {}) {
  const res = await fetch(BASE_URL + url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (!res.ok) {
    let errText = "Unknown error";
    try {
      const data = await res.json();
      errText = data.detail || data.error || JSON.stringify(data);
    } catch {
      errText = await res.text();
    }
    throw new Error(errText);
  }

  return res.json();
}

/* ================== VERIFY ================== */

async function handleVerify() {
  const text = dom.messageInput.value.trim();
  if (!text) return showToast("Enter message", "info");

  if (state.isAnalyzing) return;
  state.isAnalyzing = true;

  showLoading(true);
  setStatus("loading", "Analyzing...");

  try {
    const data = await apiFetch("/verify", {
      method: "POST",
      body: JSON.stringify({ text }),
    });

    state.sessionId = data.session_id;
    state.reportId = data.report_id || null;

    // ✅ ONLY CHANGE — RESTORE REPORT TAB
    if (data.report_id) {
      show(dom.reportCard);
      loadReport();
    }

    renderResults(data);
    show(dom.resultsCard);
    hide(dom.emptyState);

    if (data.session_id) {
      show(dom.intelCard);
      loadIntel(data.session_id);
    }

    if (data.followup_available) {
      show(dom.chatCard);

      dom.chatMessages.innerHTML = "";
      startAutoConversation(data.session_id);
    }

    setStatus("ready", "Done");
    showToast(`Analysis: ${data.label}`, data.label === 'Scam' ? 'error' : 'success');

  } catch (err) {
    showToast(err.message, "error");
  } finally {
    showLoading(false);
    state.isAnalyzing = false;
  }
}

/* ================== REPORT ================== */

async function loadReport() {
  if (!state.reportId) return;

  try {
    const data = await apiFetch(`/reports/${state.reportId}`);

    dom.reportContent.textContent =
      typeof data === "string"
        ? data
        : JSON.stringify(data, null, 2);

    show(dom.reportPreview);

  } catch (err) {
    showToast("Failed to load report", "error");
  }
}

function downloadReport() {
  if (!state.reportId) return;

  const url = `${BASE_URL}/reports/${state.reportId}/download`;

  const a = document.createElement("a");
  a.href = url;
  a.download = `report-${state.reportId}.pdf`;
  a.click();
}

/* ================== AUTO AGENT ================== */

async function startAutoConversation(sessionId) {
  appendChatMessage("ai", "🧠 Starting investigation...");

  try {
    const data = await apiFetch(`/chat-followup/${sessionId}`, {
      method: "POST",
      body: JSON.stringify({
        user_message: "Hello, I received this message. Can you explain how this works?"
      }),
    });

    appendChatMessage("ai", data.reply);

    handleDecision(data);

  } catch (e) {
    appendChatMessage("ai", "⚠️ Backend error. Check server.");
    console.error("AUTO START ERROR:", e);
  }
}

/* ================== RESULTS ================== */

function renderResults(data) {
  const isScam = data.label === "Scam";

  dom.resultLabelBadge.textContent = data.label;
  dom.resultLabelBadge.className = `result-label-badge ${isScam ? "scam" : "safe"}`;

  dom.verdictBanner.className = `verdict-banner ${isScam ? "scam" : "safe"}`;
  dom.verdictIcon.textContent = isScam ? "🚨" : "✅";
  dom.verdictLabel.textContent = isScam ? "SCAM DETECTED" : "SAFE";

  const trust = Math.min(100, Math.max(0, Math.round(data.trust_score)));
  dom.trustScoreVal.textContent = trust;

  const circumference = 213.63;
  const offset = circumference - (trust / 100) * circumference;
  dom.trustRingFill.style.strokeDashoffset = offset;

  ensureRingGradient(isScam);

  const ml = Math.round(data.ml_scam_probability * 100);
  dom.mlProbBar.style.width = `${ml}%`;
  dom.mlProbVal.textContent = `${ml}%`;

  dom.llmExplanation.textContent = data.llm_analysis || "No analysis";
}

/* ================== GRADIENT ================== */

function ensureRingGradient(isScam) {
  const svg = dom.trustRingFill.closest("svg");

  let defs = svg.querySelector("defs");
  if (!defs) {
    defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    svg.prepend(defs);
  }

  let grad = defs.querySelector("#ringGrad");
  if (!grad) {
    grad = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    grad.id = "ringGrad";
    defs.appendChild(grad);
  }

  grad.innerHTML = `
    <stop offset="0%" stop-color="${isScam ? "#ff4d6d" : "#00f5c8"}"/>
    <stop offset="100%" stop-color="${isScam ? "#7b5ea7" : "#06d6a0"}"/>
  `;
}

/* ================== INTEL ================== */

async function loadIntel(id) {
  try {
    const data = await apiFetch(`/intel/${id}`);

    dom.intelPhonesVal.textContent = data.phone_numbers?.join(", ") || "None";
    dom.intelUrlsVal.textContent = data.urls?.join(", ") || "None";
    dom.intelPaymentVal.textContent = data.payment_details?.join(", ") || "None";
    dom.intelScamTypeVal.textContent = data.scam_type || "Unknown";
    dom.intelRiskVal.textContent = data.risk_level || "Unknown";

    hide(dom.intelLoading);
    show(dom.intelGrid);

  } catch (e) {
    dom.intelLoading.innerText = "Intel failed";
  }
}

/* ================== CHAT ================== */

async function sendChatMessage() {
  if (!state.sessionId) return;

  const msg = dom.chatInput.value.trim();
  if (!msg) return;

  appendChatMessage("user", msg);
  dom.chatInput.value = "";

  try {
    const data = await apiFetch(`/chat-followup/${state.sessionId}`, {
      method: "POST",
      body: JSON.stringify({ user_message: msg }),
    });

    appendChatMessage("ai", data.reply);

    handleDecision(data);

  } catch (err) {
    appendChatMessage("ai", "⚠️ " + err.message);
  }
}

/* ================== DECISION HANDLER ================== */

function handleDecision(data) {
  if (!data.status) return;

  if (data.status === "confirmed_scam") {
    appendChatMessage("ai", "🚨 Scam confirmed. Ending session.");
  }

  if (data.status === "likely_safe") {
    appendChatMessage("ai", "✅ Looks safe. Ending session.");
  }
}

/* ================== CHAT UI ================== */

function appendChatMessage(role, text) {
  const div = document.createElement("div");
  div.className = `chat-msg chat-msg--${role}`;
  div.innerHTML = `
    <div class="chat-avatar">${role === "ai" ? "AI" : "You"}</div>
    <div class="chat-bubble">${text}</div>
  `;
  dom.chatMessages.appendChild(div);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
}

/* ================== INIT ================== */

(function () {
  setStatus("ready", "Ready");
})();