const form = document.getElementById("scan-form");
const textarea = document.getElementById("content");
const charHint = document.getElementById("char-hint");
const scanBtn = document.getElementById("scan-btn");
const resultsSection = document.getElementById("results");
const errorSection = document.getElementById("error");
const heuristicsBody = document.getElementById("heuristics-body");
const aiBody = document.getElementById("ai-body");

textarea.addEventListener("input", () => {
  charHint.textContent = `${textarea.value.length} characters`;
});

function verdictClass(verdict) {
  if (verdict === "PHISHING") return "phishing";
  if (verdict === "SUSPICIOUS") return "suspicious";
  if (verdict === "SAFE") return "safe";
  return "suspicious";
}

function renderHeuristics(data) {
  const { heuristics, max_heuristic_score } = data;

  if (heuristics.urls_found === 0) {
    heuristicsBody.innerHTML = `
      <span class="score-badge suspicious">No URL detected</span>
      <p class="no-flags">No URL was found in the pasted text — heuristics only run on URLs. AI verdict (right) still analyzed the raw text.</p>
    `;
    return;
  }

  let html = "";
  heuristics.results.forEach(r => {
    const badgeClass = r.heuristic_score >= 50 ? "phishing" : r.heuristic_score >= 20 ? "suspicious" : "safe";
    html += `<div class="url-block">${r.url}</div>`;
    html += `<span class="score-badge ${badgeClass}">Risk score: ${r.heuristic_score}/100</span>`;
    if (r.flags.length === 0) {
      html += `<p class="no-flags">No red flags detected by rule-based checks.</p>`;
    } else {
      html += `<ul class="flag-list">${r.flags.map(f => `<li>${f}</li>`).join("")}</ul>`;
    }
  });
  heuristicsBody.innerHTML = html;
}

function renderAI(ai) {
  const cls = verdictClass(ai.verdict);
  aiBody.innerHTML = `
    <span class="score-badge ${cls}">${ai.verdict} · ${ai.confidence}% confidence</span>
    <p class="ai-reasoning">${ai.reasoning}</p>
    <div class="ai-action">→ ${ai.recommended_action}</div>
  `;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorSection.classList.add("hidden");
  resultsSection.classList.add("hidden");

  const content = textarea.value.trim();
  if (!content) return;

  scanBtn.disabled = true;
  scanBtn.querySelector(".btn-label").textContent = "Scanning...";

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ content })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Something went wrong.");
    }

    renderHeuristics(data);
    renderAI(data.ai);
    resultsSection.classList.remove("hidden");

  } catch (err) {
    errorSection.textContent = `Error: ${err.message}`;
    errorSection.classList.remove("hidden");
  } finally {
    scanBtn.disabled = false;
    scanBtn.querySelector(".btn-label").textContent = "Run Scan";
  }
});
