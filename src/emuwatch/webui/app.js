const repoForm = document.querySelector("#repo-form");
const repoInput = document.querySelector("#repo-target");
const repoLoading = document.querySelector("#repo-loading");
const repoResult = document.querySelector("#repo-result");
const fileInput = document.querySelector("#file-input");
const fileResult = document.querySelector("#file-result");
const dropZone = document.querySelector("#drop-zone");

function resultClass(verdict) {
  if (["confirmed-malicious-indicator", "confirmed-malicious-asset", "reported-malicious-repository", "high-risk-metadata"].includes(verdict)) return "danger";
  if (["needs-review", "caution"].includes(verdict)) return "caution";
  return verdict === "known-project-artifact" ? "good" : "unknown";
}

function verdictTitle(verdict) {
  const titles = {
    "confirmed-malicious-indicator": "Exact known-malware match",
    "confirmed-malicious-asset": "Release matches a known malicious file",
    "reported-malicious-repository": "Named in a primary malware report",
    "high-risk-metadata": "Stop and verify this one",
    "needs-review": "This needs a closer look",
    "caution": "A few things look unusual",
    "no-strong-signals": "No strong metadata warning",
    "no-known-hash-match": "Not in the known-hash list",
    "known-project-artifact": "Matches a known project release",
  };
  return titles[verdict] || verdict;
}

function renderResult(container, result) {
  container.replaceChildren();
  container.className = `result ${resultClass(result.verdict)}`;

  const head = document.createElement("div");
  head.className = "result-head";
  const title = document.createElement("h3");
  title.textContent = verdictTitle(result.verdict);
  const badge = document.createElement("span");
  badge.className = "badge";
  badge.textContent = result.status || (result.verdict === "confirmed-malicious-indicator" ? "FAIL" : "UNKNOWN");
  head.append(title, badge);
  container.append(head);

  const meter = document.createElement("div");
  meter.className = "meter";
  const fill = document.createElement("span");
  fill.style.width = `${Math.max(2, result.score)}%`;
  meter.append(fill);
  container.append(meter);

  if (result.signals.length) {
    const list = document.createElement("ul");
    for (const signal of result.signals) {
      const item = document.createElement("li");
      item.textContent = signal.message;
      list.append(item);
    }
    container.append(list);
  } else {
    const text = document.createElement("p");
    text.textContent = "No exact indicator or strong warning was found in this check.";
    container.append(text);
  }

  const limit = document.createElement("p");
  limit.className = "fine-print";
  limit.textContent = result.limitations.join(" ");
  container.append(limit);
  container.hidden = false;
}

function renderError(container, message) {
  container.replaceChildren();
  container.className = "result error";
  const title = document.createElement("h3");
  title.textContent = "Could not finish the check";
  const text = document.createElement("p");
  text.textContent = message;
  container.append(title, text);
  container.hidden = false;
}

repoForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  repoResult.hidden = true;
  repoLoading.hidden = false;
  const button = repoForm.querySelector("button");
  button.disabled = true;
  try {
    const response = await fetch("/api/check-repo", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target: repoInput.value}),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The checker returned an error.");
    renderResult(repoResult, result);
    loadReviewed();
  } catch (error) {
    renderError(repoResult, error.message);
  } finally {
    repoLoading.hidden = true;
    button.disabled = false;
  }
});

async function checkFile(file) {
  fileResult.hidden = true;
  try {
    if (file.size > 128 * 1024 * 1024) throw new Error('For files over 128 MB, use the local CLI to calculate a hash without loading the whole file into browser memory.');
    const [buffer, indicatorResponse] = await Promise.all([
      file.arrayBuffer(),
      fetch("/api/indicators"),
    ]);
    const indicators = await indicatorResponse.json();
    if (!indicatorResponse.ok) throw new Error(indicators.error || "Indicator list unavailable.");
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const sha256 = Array.from(new Uint8Array(hashBuffer), byte => byte.toString(16).padStart(2, "0")).join("");
    const matched = indicators.indicators.some(item => String(item.sha256).toLowerCase() === sha256);
    const knownAsset = indicators.known_assets.find(item => String(item.sha256).toLowerCase() === sha256);
    renderResult(fileResult, {
      verdict: matched ? "confirmed-malicious-indicator" : knownAsset ? "known-project-artifact" : "no-known-hash-match",
      score: matched ? 100 : 0,
      signals: matched
        ? [{message: "SHA-256 exactly matches a confirmed indicator."}]
        : knownAsset
          ? [{message: `Matches ${knownAsset.project} ${knownAsset.release} asset ${knownAsset.name}.`}]
          : [],
      limitations: [
        `SHA-256: ${sha256}`,
        "The file stayed in this browser and was not uploaded or executed.",
        ...(knownAsset ? ["A project-release match establishes provenance, not a guarantee of safety."] : []),
        "No match does not mean the file is safe.",
      ],
    });
  } catch (error) {
    renderError(fileResult, error.message);
  }
}

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) checkFile(fileInput.files[0]);
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
}
dropZone.addEventListener("drop", event => {
  const file = event.dataTransfer.files[0];
  if (file) checkFile(file);
});

async function loadCampaigns() {
  const container = document.querySelector("#campaigns");
  try {
    const response = await fetch("/api/campaigns");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Watchlist unavailable.");
    container.replaceChildren();
    for (const campaign of payload.campaigns) {
      const card = document.createElement("article");
      card.className = "campaign";
      const top = document.createElement("div");
      top.className = "campaign-top";
      const title = document.createElement("h3");
      title.textContent = campaign.impersonated_projects.join(" + ");
      const status = document.createElement("span");
      status.className = "status";
      status.textContent = campaign.status.replaceAll("-", " ");
      top.append(title, status);
      const note = document.createElement("p");
      note.textContent = campaign.validation_notes;
      const list = document.createElement("ul");
      for (const behavior of campaign.reported_behavior) {
        const item = document.createElement("li");
        item.textContent = behavior;
        list.append(item);
      }
      card.append(top, note, list);
      container.append(card);
    }
  } catch (error) {
    renderError(container, error.message);
  }
}

loadCampaigns();

async function loadReviewed() {
  const container = document.querySelector('#reviewed');
  try {
    const [reviewedResponse, historyResponse] = await Promise.all([fetch('/api/reviewed'), fetch('/api/history')]);
    if (!reviewedResponse.ok || !historyResponse.ok) throw new Error('Result history unavailable');
    const reviewed = await reviewedResponse.json();
    const history = await historyResponse.json();
    container.replaceChildren();
    const summary = document.createElement('p');
    summary.textContent = `${reviewed.repositories.length} source-backed repository warnings. ${history.observations.length} recent local observations.`;
    container.append(summary);
    for (const item of reviewed.reviews || []) {
      const card = document.createElement('article');
      card.className = 'campaign';
      card.dataset.status = 'UNKNOWN';
      const title = document.createElement('h3');
      title.textContent = `UNKNOWN · ${item.repository}`;
      const note = document.createElement('p');
      note.textContent = item.observations.join('. ') + '. ' + item.limits;
      const link = document.createElement('a');
      link.textContent = 'Inspect the recorded commit';
      link.href = item.evidence_url;
      link.rel = 'noreferrer';
      card.append(title, note, link);
      container.append(card);
    }
    for (const item of reviewed.repositories) {
      const card = document.createElement('article');
      card.className = 'campaign';
      card.dataset.status = 'FAIL';
      const title = document.createElement('h3');
      title.textContent = `FAIL · ${item.repository}`;
      const note = document.createElement('p');
      note.textContent = `${item.campaign} · ${item.source_name} · ${item.published}`;
      const link = document.createElement('a');
      link.textContent = 'Read the evidence';
      link.href = item.source_url;
      link.rel = 'noreferrer';
      card.append(title, note, link);
      container.append(card);
    }
    for (const item of history.observations.slice(0, 10)) {
      const row = document.createElement('p');
      row.textContent = `${item.status} · ${item.target} · ${item.recorded_at}`;
      container.append(row);
    }
  } catch (error) { renderError(container, error.message); }
  filterRecords();
}

function filterRecords() {
  const text = document.querySelector('#record-filter').value.toLowerCase();
  const status = document.querySelector('#record-status').value;
  for (const card of document.querySelectorAll('#reviewed article')) {
    card.hidden = !card.textContent.toLowerCase().includes(text) || (status !== 'ALL' && card.dataset.status !== status);
  }
}
document.querySelector('#record-filter').addEventListener('input', filterRecords);
document.querySelector('#record-status').addEventListener('change', filterRecords);
loadReviewed();

