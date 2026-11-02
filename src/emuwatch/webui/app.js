const repoForm = document.querySelector('#repo-form');
const repoInput = document.querySelector('#repo-target');
const repoLoading = document.querySelector('#repo-loading');
const repoResult = document.querySelector('#repo-result');
const recentScans = document.querySelector('#recent-scans');
const knownThreats = document.querySelector('#known-threats');

const iconPaths = {
  'circle-x': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="m15 9-6 6"></path>', '<path d="m9 9 6 6"></path>'],
  'circle-minus': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="M8 12h8"></path>'],
  'circle-check': ['<circle cx="12" cy="12" r="10"></circle>', '<path d="m9 12 2 2 4-4"></path>'],
  'chevron-down': ['<path d="m6 9 6 6 6-6"></path>'],
};

const statusInfo = {
  Malicious: {icon: 'circle-x', tone: 'danger'},
  Corroborated: {icon: 'circle-check', tone: 'caution'},
  Unverified: {icon: 'circle-minus', tone: 'neutral'},
  Matched: {icon: 'circle-check', tone: 'matched'},
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
  const info = statusInfo[status] || statusInfo.Unverified;
  const badge = document.createElement('span');
  badge.className = `status ${info.tone}`;
  badge.append(icon(info.icon, 'status-icon'), document.createTextNode(status));
  return badge;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : new Intl.DateTimeFormat('en-US', {month: '2-digit', day: '2-digit', year: 'numeric'}).format(date);
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 1) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** unit)).toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(milliseconds) {
  return milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
}

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function findingElement(finding) {
  const item = document.createElement('li');
  item.className = `finding severity-${finding.severity}`;
  const heading = document.createElement('div');
  heading.className = 'finding-heading';
  heading.append(
    textElement('strong', '', finding.title),
    textElement('span', 'severity', finding.severity),
  );
  const location = textElement('code', 'finding-path', `${finding.path}${finding.line ? `:${finding.line}` : ''}`);
  const detail = textElement('p', '', finding.detail);
  item.append(heading, location, detail);
  if (finding.sha256) item.append(textElement('code', 'finding-hash', `SHA-256 ${finding.sha256}`));
  if (finding.source_url) {
    const source = document.createElement('a');
    source.href = finding.source_url;
    source.rel = 'noreferrer';
    source.textContent = 'Indicator source';
    source.className = 'finding-source';
    item.append(source);
  }
  return item;
}

function scanDetails(scan, expanded = false) {
  const row = document.createElement('details');
  row.className = 'scan-record';
  row.open = expanded;
  const summary = document.createElement('summary');
  const name = textElement('strong', 'repository-name', scan.repository);
  const date = textElement('time', '', formatDate(scan.scanned_at));
  date.dateTime = scan.scanned_at;
  summary.append(name, statusBadge(scan.status), date, icon('chevron-down', 'chevron'));

  const body = document.createElement('div');
  body.className = 'scan-body';
  const metadata = document.createElement('div');
  metadata.className = 'scan-meta';
  const summaryData = scan.summary || {};
  const values = [
    [`${summaryData.files || 0}`, 'files'],
    [formatBytes(summaryData.hashed_bytes || 0), 'hashed'],
    [`${summaryData.archives || 0}`, 'archives'],
    [formatDuration(scan.duration_ms || 0), 'duration'],
  ];
  for (const [value, label] of values) {
    const metric = document.createElement('span');
    metric.append(textElement('strong', '', value), document.createTextNode(label));
    metadata.append(metric);
  }
  const commit = textElement('code', 'commit', `commit ${String(scan.commit || 'unavailable').slice(0, 12)}`);
  const revision = document.createElement('div');
  revision.className = 'revision';
  revision.append(commit);
  if (scan.branch) revision.append(textElement('code', 'branch', `branch ${scan.branch}`));
  body.append(metadata, revision);

  if (scan.history?.scan_count > 1 || scan.history?.related_repositories?.length) {
    const history = document.createElement('div');
    history.className = 'scan-history';
    history.append(textElement(
      'strong', '',
      `${scan.history.scan_count} recorded scans · ${scan.history.transitions.length} observed changes · ${scan.history.related_repositories.length} shared-commit relatives`,
    ));
    const latest = scan.history.transitions.at(-1);
    if (latest) {
      history.append(textElement(
        'p', '',
        `${latest.from_status} at ${String(latest.base_commit || 'unknown').slice(0, 12)} to ${latest.to_status} at ${String(latest.head_commit || 'unknown').slice(0, 12)}. ${latest.new_findings.length} new finding(s).`,
      ));
    }
    body.append(history);
  }

  if (scan.findings?.length) {
    const list = document.createElement('ul');
    list.className = 'findings';
    for (const finding of scan.findings) list.append(findingElement(finding));
    body.append(list);
  } else {
    body.append(textElement('p', 'no-findings', 'No exact indicator or configured static rule matched. This does not prove the repository is safe.'));
  }

  if (scan.sources?.length) {
    const sources = document.createElement('div');
    sources.className = 'source-links';
    sources.append(textElement('span', '', 'Supporting research'));
    for (const url of scan.sources) {
      const link = document.createElement('a');
      link.href = url;
      link.rel = 'noreferrer';
      link.textContent = new URL(url).hostname;
      sources.append(link);
    }
    body.append(sources);
  }

  const caveat = document.createElement('details');
  caveat.className = 'caveat';
  caveat.append(textElement('summary', '', 'scan limits'));
  const limits = document.createElement('ul');
  for (const limitation of scan.limitations || []) limits.append(textElement('li', '', limitation));
  caveat.append(limits);
  body.append(caveat);
  row.append(summary, body);
  return row;
}

function renderError(container, message) {
  container.replaceChildren(
    textElement('strong', '', 'Scan could not finish'),
    textElement('p', '', message),
  );
  container.className = 'scan-result error';
  container.hidden = false;
}

async function loadRecentScans() {
  try {
    const response = await fetch('/api/scans');
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Recent scans are unavailable.');
    recentScans.replaceChildren();
    if (!payload.scans.length) {
      recentScans.append(textElement('p', 'empty', 'No completed scans yet.'));
      return;
    }
    for (const scan of payload.scans) recentScans.append(scanDetails(scan));
  } catch (error) {
    recentScans.replaceChildren(textElement('p', 'empty error-text', error.message));
  }
}

function threatRow(item) {
  const row = document.createElement('details');
  row.className = 'threat-record';
  const summary = document.createElement('summary');
  const date = textElement('time', '', formatDate(item.recorded_on));
  date.dateTime = item.recorded_on;
  summary.append(
    textElement('strong', 'repository-name', item.repository),
    statusBadge('Malicious'),
    date,
    icon('chevron-down', 'chevron'),
  );
  const body = document.createElement('div');
  body.className = 'threat-body';
  const location = document.createElement('div');
  location.className = 'evidence-first';
  location.append(
    textElement('span', 'field-label', 'affected file'),
    textElement('code', '', `${item.release} · ${item.malicious_path}`),
    textElement('p', '', item.finding),
  );
  const actions = document.createElement('div');
  actions.className = 'record-actions';
  const evidence = document.createElement('a');
  evidence.href = `/api/record?repository=${encodeURIComponent(item.repository)}`;
  evidence.textContent = 'View evidence';
  actions.append(evidence);
  const help = document.createElement('details');
  help.className = 'remediation';
  help.append(textElement('summary', '', 'Symptoms and cleanup'));
  help.append(
    textElement('h4', '', 'Symptoms'),
    textElement('p', '', item.symptoms),
    textElement('h4', '', 'Recommended action'),
    textElement('p', '', item.remediation),
  );
  body.append(location, actions, help);
  row.append(summary, body);
  return row;
}

async function loadKnownThreats() {
  try {
    const response = await fetch('/api/reviewed');
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Threat records are unavailable.');
    knownThreats.replaceChildren();
    const groups = new Map();
    for (const item of payload.records) {
      const records = groups.get(item.malware) || [];
      records.push(item);
      groups.set(item.malware, records);
    }
    for (const [family, records] of groups) {
      const group = document.createElement('article');
      group.className = 'threat-family';
      const header = document.createElement('header');
      const title = textElement('h3', '', family);
      const count = textElement('span', 'record-count', `${records.length} ${records.length === 1 ? 'repository' : 'repositories'}`);
      const description = textElement('p', '', records[0].behavior);
      const links = document.createElement('div');
      links.className = 'family-links';
      const source = document.createElement('a');
      source.href = records[0].source_url;
      source.rel = 'noreferrer';
      source.textContent = records[0].source_name;
      const database = document.createElement('a');
      database.href = records[0].malware_db_url;
      database.rel = 'noreferrer';
      database.textContent = records[0].malware_db_name;
      links.append(source, database);
      header.append(title, count, description, links);
      group.append(header);
      for (const item of records) group.append(threatRow(item));
      knownThreats.append(group);
    }
  } catch (error) {
    knownThreats.replaceChildren(textElement('p', 'empty error-text', error.message));
  }
}

repoForm.addEventListener('submit', async event => {
  event.preventDefault();
  const button = repoForm.querySelector('button');
  repoResult.hidden = true;
  repoLoading.hidden = false;
  repoForm.setAttribute('aria-busy', 'true');
  button.disabled = true;
  try {
    const response = await fetch('/api/v1/scans', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({kind: 'repository', url: repoInput.value}),
    });
    let job = await response.json();
    if (!response.ok) throw new Error(job.error?.message || 'The scanner returned an error.');
    const deadline = Date.now() + 90000;
    while (!['completed', 'failed', 'cancelled', 'incomplete'].includes(job.status) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 750));
      const state = await fetch(job.links.self);
      job = await state.json();
      if (!state.ok) throw new Error(job.error?.message || 'The scan status is unavailable.');
    }
    if (job.status !== 'completed') {
      throw new Error(job.error_message || (Date.now() >= deadline ? 'The scan did not finish within 90 seconds.' : 'The scan did not complete.'));
    }
    const result = job.result;
    repoResult.replaceChildren(scanDetails(result, true));
    repoResult.className = 'scan-result';
    repoResult.hidden = false;
    await loadRecentScans();
  } catch (error) {
    renderError(repoResult, error.message);
  } finally {
    repoLoading.hidden = true;
    repoForm.removeAttribute('aria-busy');
    button.disabled = false;
  }
});

document.querySelector('#refresh-scans').addEventListener('click', loadRecentScans);
loadRecentScans();
loadKnownThreats();
