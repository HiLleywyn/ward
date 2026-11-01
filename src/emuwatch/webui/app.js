const repoForm = document.querySelector("#repo-form");
const repoInput = document.querySelector("#repo-target");
const repoLoading = document.querySelector("#repo-loading");
const repoResult = document.querySelector("#repo-result");
const fileInput = document.querySelector("#file-input");
const fileResult = document.querySelector("#file-result");
const dropZone = document.querySelector("#drop-zone");

const statusInfo = {
  FAIL: {icon: 'circle-x', label: 'Confirmed malicious record or exact malware match', tone: 'danger'},
  UNKNOWN: {icon: 'circle-minus', label: 'Unverified or still under investigation', tone: 'caution'},
  PASS: {icon: 'circle-check', label: 'Specific check verified; not a guarantee of safety', tone: 'good'},
};

const iconPaths = {
  'circle-x': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="m15 9-6 6"></path>', '<path d="m9 9 6 6"></path>'],
  'circle-minus': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="M8 12h8"></path>'],
  'circle-check': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="m9 12 2 2 4-4"></path>'],
  'chevron-down': ['<path d="m6 9 6 6 6-6"></path>'],
};

function icon(name, className = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.className.baseVal = className;
  svg.innerHTML = iconPaths[name].join('');
  return svg;
}

function statusBadge(status) {
  const info = statusInfo[status] || statusInfo.UNKNOWN;
  const badge = document.createElement('span');
  badge.className = `status-icon ${info.tone}`;
  badge.append(icon(info.icon, 'status-svg'));
  badge.title = info.label;
  badge.setAttribute('aria-label', info.label);
  return badge;
}

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
  const confirmed = ['confirmed-malicious-indicator', 'confirmed-malicious-asset', 'reported-malicious-repository'].includes(result.verdict);
  const badge = statusBadge(confirmed ? 'FAIL' : result.verdict === 'known-project-artifact' ? 'PASS' : 'UNKNOWN');
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
      for (const evidence of campaign.evidence || []) {
        const card = document.createElement("article");
        card.className = "campaign coverage-card";
        const type = document.createElement('span');
        type.className = 'coverage-type';
        type.textContent = evidence.type.startsWith('primary') ? 'Research' : 'News';
        const title = document.createElement("h3");
        title.textContent = campaign.title || campaign.impersonated_projects.join(" + ");
        const byline = document.createElement('p');
        byline.className = 'coverage-byline';
        byline.textContent = `${evidence.attribution} · ${formatDate(campaign.first_public_report)}`;
        const note = document.createElement("p");
        note.textContent = campaign.validation_notes;
        const source = document.createElement('a');
        source.href = evidence.url;
        source.rel = 'noreferrer';
        source.textContent = type.textContent === 'News' ? 'Read the article' : 'Read the research report';
        card.append(type, title, byline, note, source);
        container.append(card);
      }
    }
  } catch (error) {
    renderError(container, error.message);
  }
}

loadCampaigns();

async function loadReviewed() {
  const container = document.querySelector('#reviewed');
  try {
    const reviewedResponse = await fetch('/api/reviewed');
    if (!reviewedResponse.ok) throw new Error('Malware records unavailable');
    const reviewed = await reviewedResponse.json();
    container.replaceChildren();
    const summary = document.createElement('p');
    summary.className = 'record-summary';
    summary.textContent = `${reviewed.records.length} repository-specific malware records. Campaign-only and unverified leads are excluded.`;
    container.append(summary);
    const head = document.createElement('div');
    head.className = 'record-table-head';
    head.innerHTML = '<span></span><span>Repository</span><span>Malware</span><span>Recorded</span><span></span>';
    container.append(head);
    for (const item of reviewed.records) container.append(renderRecord(item));
  } catch (error) { renderError(container, error.message); }
  filterRecords();
}

function formatDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value || '');
  return match ? `${match[2]}/${match[3]}/${match[1]}` : value;
}

function detailField(label, value, code = false) {
  const block = document.createElement('div');
  block.className = 'record-field';
  const heading = document.createElement('h4');
  heading.textContent = label;
  const content = document.createElement(code ? 'code' : 'p');
  content.textContent = value;
  block.append(heading, content);
  return block;
}

function renderRecord(item) {
  const row = document.createElement('details');
  row.className = 'record-row';
  row.dataset.status = item.status;
  const summary = document.createElement('summary');
  summary.append(statusBadge(item.status));
  const repository = document.createElement('strong');
  repository.className = 'record-repository';
  repository.textContent = item.repository;
  const malware = document.createElement('span');
  malware.className = 'record-malware';
  malware.textContent = item.malware;
  const date = document.createElement('time');
  date.dateTime = item.recorded_on;
  date.textContent = formatDate(item.recorded_on);
  summary.append(repository, malware, date, icon('chevron-down', 'record-chevron'));

  const body = document.createElement('div');
  body.className = 'record-body';
  const fields = document.createElement('div');
  fields.className = 'record-fields';
  fields.append(
    detailField('What it promised', item.lure),
    detailField('What Ward confirmed', item.finding),
    detailField('Exact location', `${item.repository} · release ${item.release} · ${item.malicious_path}`, true),
    detailField('What it can do', item.behavior),
    detailField('Symptoms to check', item.symptoms),
    detailField('What to do', item.remediation),
  );
  const scope = document.createElement('p');
  scope.className = 'record-scope';
  scope.textContent = item.scope;
  const actions = document.createElement('div');
  actions.className = 'record-actions';
  const ward = document.createElement('a');
  ward.href = `/api/record?repository=${encodeURIComponent(item.repository)}`;
  ward.textContent = 'Open Ward scan data';
  const malwareDb = document.createElement('a');
  malwareDb.href = item.malware_db_url;
  malwareDb.rel = 'noreferrer';
  malwareDb.textContent = `View observed XMRig family data on ${item.malware_db_name}`;
  actions.append(ward, malwareDb);
  body.append(fields, scope, actions);
  row.append(summary, body);
  return row;
}

function filterRecords() {
  const text = document.querySelector('#record-filter').value.toLowerCase();
  const status = document.querySelector('#record-status').value;
  for (const card of document.querySelectorAll('#reviewed details')) {
    card.hidden = !card.textContent.toLowerCase().includes(text) || (status !== 'ALL' && card.dataset.status !== status);
  }
}
document.querySelector('#record-filter').addEventListener('input', filterRecords);
document.querySelector('#record-status').addEventListener('change', filterRecords);
for (const item of document.querySelectorAll('[data-status-key]')) {
  item.prepend(statusBadge(item.dataset.statusKey));
}
loadReviewed();

