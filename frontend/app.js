"use strict";

const els = {
  input: document.getElementById("password-input"),
  toggle: document.getElementById("toggle-visibility"),
  analyzeBtn: document.getElementById("analyze-btn"),
  resetBtn: document.getElementById("reset-btn"),
  error: document.getElementById("analyze-error"),
  results: document.getElementById("results"),
  meterBar: document.getElementById("meter-bar"),
  strengthLabel: document.getElementById("strength-label"),
  stats: {
    length: document.getElementById("stat-length"),
    uppercase: document.getElementById("stat-upper"),
    lowercase: document.getElementById("stat-lower"),
    digits: document.getElementById("stat-digits"),
    special: document.getElementById("stat-special"),
    entropy_bits: document.getElementById("stat-entropy"),
  },
  problemsList: document.getElementById("problems-list"),
  genLength: document.getElementById("gen-length"),
  genLengthValue: document.getElementById("gen-length-value"),
  genUpper: document.getElementById("gen-upper"),
  genLower: document.getElementById("gen-lower"),
  genDigits: document.getElementById("gen-digits"),
  genSpecial: document.getElementById("gen-special"),
  generateBtn: document.getElementById("generate-btn"),
  genMsg: document.getElementById("gen-msg"),
  genOutput: document.getElementById("gen-output"),
  copyBtn: document.getElementById("copy-btn"),
  historyList: document.getElementById("history-list"),
  historyEmpty: document.getElementById("history-empty"),
};

const LEVEL_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"];
const HISTORY_LIMIT = 25;
let historyEntries = [];

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

function showError(message) {
  els.error.textContent = message;
  els.error.hidden = false;
}

function clearError() {
  els.error.textContent = "";
  els.error.hidden = true;
}

function isPasswordVisible() {
  return els.input.type === "text";
}

function setVisibility(visible) {
  els.input.type = visible ? "text" : "password";
  els.toggle.classList.toggle("active", visible);
  els.toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    let message = `Request failed (HTTP ${response.status}).`;
    if (Array.isArray(data?.detail) && data.detail.length > 0 && typeof data.detail[0]?.msg === "string") {
      message = data.detail[0].msg;
    } else if (typeof data?.detail === "string") {
      message = data.detail;
    }
    const error = new Error(message);
    error.handled = true;
    throw error;
  }
  return data;
}

function renderAnalysis(data) {
  els.results.hidden = false;
  els.meterBar.style.width = `${Math.max(2, data.strength.score)}%`;
  els.meterBar.className = `meter-bar lv${data.strength.level}`;
  els.strengthLabel.textContent = `${data.strength.label} (${data.strength.score}/100)`;
  for (const key of Object.keys(els.stats)) {
    els.stats[key].textContent =
      key === "entropy_bits" ? String(data.stats[key]) : String(data.stats[key]);
  }
  els.problemsList.replaceChildren();
  if (data.problems.length === 0 || (data.problems.length === 1 && data.stats.length === 0)) {
    const li = document.createElement("li");
    li.className = "ok";
    li.textContent = data.stats.length === 0
      ? "Enter a password above to see its analysis."
      : "No common problems detected. Nice password!";
    els.problemsList.appendChild(li);
  } else {
    for (const problem of data.problems) {
      const li = document.createElement("li");
      li.textContent = problem;
      els.problemsList.appendChild(li);
    }
  }
}

function renderHistory() {
  els.historyList.replaceChildren();
  els.historyEmpty.hidden = historyEntries.length > 0;
  for (const entry of historyEntries) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = "history-dot";
    dot.style.background = LEVEL_COLORS[entry.level] ?? LEVEL_COLORS[0];
    const main = document.createElement("div");
    main.className = "history-main";
    const strengthLine = document.createElement("div");
    strengthLine.className = "history-strength";
    strengthLine.textContent = entry.label;
    const metaLine = document.createElement("div");
    metaLine.className = "history-meta";
    metaLine.textContent = `length ${entry.length} · score ${entry.score}/100 · ${entry.time}`;
    main.append(strengthLine, metaLine);
    li.append(dot, main);
    els.historyList.appendChild(li);
  }
}

function addHistoryEntry(data) {
  historyEntries.unshift({
    label: data.strength.label,
    level: data.strength.level,
    score: data.strength.score,
    length: data.stats.length,
    time: new Date().toLocaleTimeString(),
  });
  if (historyEntries.length > HISTORY_LIMIT) {
    historyEntries.length = HISTORY_LIMIT;
  }
  renderHistory();
}

async function analyze() {
  clearError();
  try {
    const data = await postJson("/api/analyze", { password: els.input.value });
    renderAnalysis(data);
    addHistoryEntry(data);
  } catch (err) {
    showError(err.handled ? err.message : "Could not reach the local analysis server.");
  }
}

function resetAll() {
  els.input.value = "";
  setVisibility(false);
  clearError();
  els.results.hidden = true;
  els.genOutput.value = "";
  els.copyBtn.disabled = true;
  els.copyBtn.classList.remove("copied");
  hideGenMsg();
  historyEntries = [];
  renderHistory();
  els.input.focus();
}

function hideGenMsg() {
  els.genMsg.textContent = "";
  els.genMsg.hidden = true;
}

function showGenMsg(message) {
  els.genMsg.textContent = message;
  els.genMsg.hidden = false;
}

async function generate() {
  hideGenMsg();
  try {
    const data = await postJson("/api/generate", {
      length: Number(els.genLength.value),
      uppercase: els.genUpper.checked,
      lowercase: els.genLower.checked,
      numbers: els.genDigits.checked,
      special: els.genSpecial.checked,
    });
    els.genOutput.value = data.password;
    els.copyBtn.disabled = false;
    els.copyBtn.classList.remove("copied");
  } catch (err) {
    els.genOutput.value = "";
    els.copyBtn.disabled = true;
    showGenMsg(err.handled ? err.message : "Could not reach the local server.");
  }
}

async function copyGenerated() {
  const text = els.genOutput.value;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    els.genOutput.select();
    document.execCommand("copy");
  }
  els.copyBtn.classList.add("copied");
  setTimeout(() => els.copyBtn.classList.remove("copied"), 1200);
}

els.toggle.addEventListener("click", () => setVisibility(!isPasswordVisible()));
els.analyzeBtn.addEventListener("click", analyze);
els.input.addEventListener("keydown", (event) => {
  if (event.key === "Enter") analyze();
});
els.input.addEventListener("input", debounce(() => {
  if (els.input.value.length > 0) analyze();
}, 300));
els.resetBtn.addEventListener("click", resetAll);

els.generateBtn.addEventListener("click", generate);
els.copyBtn.addEventListener("click", copyGenerated);
els.genLength.addEventListener("input", () => {
  els.genLengthValue.textContent = els.genLength.value;
});
for (const checkbox of [els.genUpper, els.genLower, els.genDigits, els.genSpecial]) {
  checkbox.addEventListener("change", hideGenMsg);
}

renderHistory();
