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
  Suspicious: {icon: 'circle-x', tone: 'caution'},
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

function familyGuidance(records) {
  const section = document.createElement('div');
  section.className = 'remediation';
  for (const [field, label] of [['symptoms', 'Symptoms'], ['remediation', 'Remediation']]) {
    section.append(textElement('h4', '', label));
    const descriptions = [...new Set(records.map(item => item[field]).filter(Boolean))];
    for (const description of descriptions) {
      if (descriptions.length > 1) {
        section.append(textElement('p', 'guidance-scope', records.filter(item => item[field] === description).map(item => item.repository).join(', ')));
      }
      section.append(evidenceParagraphs(description));
    }
  }
  return section;
}

function externalScanLinks(records) {
  const links = textElement('div', 'family-links', '');
  const providers = {'bazaar.abuse.ch': 'MalwareBazaar', 'www.virustotal.com': 'VirusTotal', 'virustotal.com': 'VirusTotal', 'threatfox.abuse.ch': 'ThreatFox'};
  const seen = new Set();
  for (const record of records) {
    for (const value of [record.source_url, record.malware_db_url]) {
      let url;
      try { url = new URL(value); } catch { continue; }
      const provider = providers[url.hostname];
      if (!provider || url.protocol !== 'https:' || url.username || url.password || seen.has(url.href)) continue;
      seen.add(url.href);
      const link = textElement('a', '', 'External Scan');
      link.href = url.href;
      link.rel = 'noreferrer';
      link.title = provider;
      link.setAttribute('aria-label', `External Scan (${provider})`);
      links.append(link);
    }
  }
  return links;
}

function recordActions(scanHref, repositoryUrl) {
  const actions = textElement('div', 'record-actions', '');
  const scan = textElement('a', '', 'Ward Scan');
  scan.href = scanHref;
  actions.append(scan);
  try {
    const url = new URL(repositoryUrl);
    if (url.protocol === 'https:' && !url.username && !url.password) {
      const repository = textElement('a', '', 'Repository');
      repository.href = url.href;
      repository.rel = 'noreferrer';
      actions.append(repository);
    }
  } catch { /* Older records can lack a repository URL. */ }
  return actions;
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
  const detail = evidenceText('p', '', finding.detail);
  item.append(heading, location, detail);
  if (finding.sha256) item.append(textElement('code', 'finding-hash', `SHA-256 ${finding.sha256}`));
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
  summary.append(name, statusBadge(scan.assessment?.status || scan.status), date, icon('chevron-down', 'chevron'));

  const body = document.createElement('div');
  body.className = 'scan-body';
  const metadata = document.createElement('div');
  metadata.className = 'scan-meta';
  const summaryData = scan.summary || {};
  const values = [
    [`${summaryData.files || 0}`, 'files'],
    [formatBytes(summaryData.hashed_bytes || 0), 'hashed'],
    [`${summaryData.archives || 0}`, 'archives'],
    [`${summaryData.text_files || 0}`, 'text files checked'],
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
  if (scan.assessment?.pending) body.append(textElement('p', 'scan-analysis-state', `${scan.assessment.pending} follow-up analysis job(s) running`));
  if (scan.assessment?.coverage === 'partial') body.append(textElement('p', 'scan-analysis-state', 'Follow-up analysis has incomplete coverage. View the engine evidence below.'));
  body.append(recordActions(`/scans/${encodeURIComponent(scan.id)}`, scan.repository_url || `https://github.com/${scan.repository}`));

  for (const analysis of scan.analyses || []) {
    const details = document.createElement('details');
    details.className = 'analysis-result';
    const result = analysis.result;
    const heading = `${analysis.engine === 'remnux' ? 'REMnux' : 'Windows behavior'} · ${analysis.path} · ${analysis.status}`;
    details.append(textElement('summary', '', heading));
    if (analysis.error) details.append(textElement('p', 'error-text', analysis.error));
    if (result) {
      details.append(textElement('p', '', `Coverage: ${result.coverage || 'partial'} · Behavioral execution: ${result.behavioral_analysis || 'not-run'}`));
      for (const engine of result.engines || []) {
        details.append(textElement('strong', '', `${engine.name}: ${engine.status}`));
        if (engine.output) details.append(textElement('p', '', engine.output.trim()));
        if (engine.limitation || engine.detail) details.append(textElement('p', '', engine.limitation || engine.detail));
        for (const detection of engine.result?.detects || []) {
          details.append(textElement('p', '', (detection.values || []).map(value => value.string).join(' · ')));
        }
        if (engine.capabilities?.length) details.append(textElement('p', '', engine.capabilities.map(value => value.name).join(' · ')));
        if (engine.detections?.length) details.append(textElement('p', '', engine.detections.join(' · ')));
      }
      const raw = document.createElement('details');
      raw.append(textElement('summary', '', 'Full analysis evidence'), textElement('pre', '', JSON.stringify(result, null, 2)));
      details.append(raw);
    }
    body.append(details);
  }

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

  const findings = [...(scan.findings || []), ...(scan.assessment?.findings || [])];
  if (findings.length) {
    const list = document.createElement('ul');
    list.className = 'findings';
    for (const finding of findings) list.append(findingElement(finding));
    body.append(list);
  } else {
    body.append(textElement('p', 'no-findings', 'No exact indicator or configured static rule matched. This does not prove the repository is safe.'));
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

let recentPage = 1;
async function loadRecentScans() {
  try {
    const response = await fetch(`/api/scans?page=${recentPage}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Recent scans are unavailable.');
    recentPage = payload.page || 1;
    document.querySelector('#recent-pagination').hidden = !(payload.pages > 1);
    document.querySelector('#recent-page').textContent = `Page ${recentPage} of ${payload.pages || 1} · ${payload.total || 0} scans`;
    document.querySelector('#recent-previous').disabled = recentPage <= 1;
    document.querySelector('#recent-next').disabled = recentPage >= (payload.pages || 1);
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
  const facts = textElement('dl', 'evidence-facts', '');
  const files = textElement('dd', 'affected-files', '');
  for (const path of item.malicious_path.split(' / ')) {
    const code = textElement('code', 'affected-path', path);
    if (path.length >= 32) code.tabIndex = 0;
    files.append(code);
  }
  facts.append(textElement('dt', '', 'Revision'), evidenceText('dd', '', item.release), textElement('dt', '', 'Affected files'), files);
  location.append(facts, textElement('h4', '', 'Finding'), evidenceParagraphs(item.finding));
  const actions = recordActions(`/repository?target=${encodeURIComponent(item.repository)}&latest=1`, `https://github.com/${item.repository}`);
  body.append(location, actions);
  row.append(summary, body);
  return row;
}

let threatRecords = [];
const collapsedFamilies = new Set();
const familyPages = new Map();

function familyPagination(family, page, pages) {
  const nav = document.createElement('nav');
  nav.className = 'pagination';
  nav.setAttribute('aria-label', `${family} record pages`);
  for (const [label, target, disabled] of [['Previous', page - 1, page <= 1], ['Next', page + 1, page >= pages]]) {
    const button = textElement('button', 'quiet-button', label);
    button.type = 'button';
    button.disabled = disabled;
    button.addEventListener('click', () => {
      familyPages.set(family, target);
      collapsedFamilies.delete(family);
      renderKnownThreats();
      const active = [...knownThreats.querySelectorAll('.threat-family')].find(item => item.dataset.family === family);
      active?.querySelector('nav button:not(:disabled)')?.focus({preventScroll: true});
    });
    if (label === 'Next') nav.append(textElement('span', '', `Page ${page} of ${pages}`));
    nav.append(button);
  }
  return nav;
}

function recordType(item) {
  return (item.malicious_path.match(/\.([a-z0-9]+)$/i)?.[1] || 'other').toUpperCase();
}

function renderKnownThreats() {
    const query = document.querySelector('#threat-search').value.trim().toLowerCase();
    const familyFilter = document.querySelector('#threat-family').value;
    const typeFilter = document.querySelector('#threat-type').value;
    const from = document.querySelector('#threat-from').value;
    const to = document.querySelector('#threat-to').value;
    const sort = document.querySelector('#threat-sort').value;
    const filtered = threatRecords.filter(item =>
      (!query || [item.repository, item.malware, item.malicious_path, item.finding, item.lure].join(' ').toLowerCase().includes(query)) &&
      (!familyFilter || item.malware === familyFilter) && (!typeFilter || recordType(item) === typeFilter) &&
      (!from || item.recorded_on >= from) && (!to || item.recorded_on <= to));
    filtered.sort((a, b) => sort === 'family' ? a.malware.localeCompare(b.malware) :
      sort === 'repository' ? a.repository.localeCompare(b.repository) :
      (sort === 'oldest' ? a.recorded_on.localeCompare(b.recorded_on) : b.recorded_on.localeCompare(a.recorded_on)) || a.repository.localeCompare(b.repository));
    document.querySelector('#threat-count').textContent = `${filtered.length} of ${threatRecords.length} records`;
    knownThreats.replaceChildren();
    if (!filtered.length) knownThreats.append(textElement('p', 'empty', 'No matching records.'));
    const groups = new Map();
    for (const item of filtered) {
      const records = groups.get(item.malware) || [];
      records.push(item);
      groups.set(item.malware, records);
    }
    for (const [family, records] of groups) {
      const group = document.createElement('details');
      group.className = 'threat-family';
      group.dataset.family = family;
      group.open = !!query || !!familyFilter || !collapsedFamilies.has(family);
      group.addEventListener('toggle', () => {
        if (group.isConnected && !query && !familyFilter) {
          if (group.open) collapsedFamilies.delete(family); else collapsedFamilies.add(family);
        }
      });
      const summary = document.createElement('summary');
      summary.className = 'family-summary';
      summary.append(textElement('h3', '', family), textElement('span', 'record-count', `${records.length} ${records.length === 1 ? 'repository' : 'repositories'}`), icon('chevron-down', 'chevron'));
      const header = document.createElement('div');
      header.className = 'family-intro';
      const description = evidenceParagraphs(records[0].behavior);
      const links = externalScanLinks(records);
      header.append(description, links, familyGuidance(records));
      group.append(summary, header);
      const pages = Math.max(1, Math.ceil(records.length / 25));
      const page = Math.min(familyPages.get(family) || 1, pages);
      for (const item of records.slice((page - 1) * 25, page * 25)) group.append(threatRow(item));
      if (pages > 1) group.append(familyPagination(family, page, pages));
      knownThreats.append(group);
    }
}

async function loadKnownThreats() {
  try {
    const response = await fetch('/api/reviewed');
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Threat records are unavailable.');
    threatRecords = payload.records;
    for (const [selector, values] of [
      ['#threat-family', [...new Set(threatRecords.map(item => item.malware))].sort()],
      ['#threat-type', [...new Set(threatRecords.map(recordType))].sort()],
    ]) {
      for (const value of values) {
        const option = textElement('option', '', value);
        option.value = value;
        document.querySelector(selector).append(option);
      }
    }
    renderKnownThreats();
  } catch (error) {
    knownThreats.replaceChildren(textElement('p', 'empty error-text', error.message));
  }
}

document.querySelector('#threat-filters').addEventListener('submit', event => event.preventDefault());
document.querySelector('#threat-filters').addEventListener('input', () => { familyPages.clear(); renderKnownThreats(); });
document.querySelector('#threat-filters').addEventListener('reset', () => {
  collapsedFamilies.clear();
  familyPages.clear();
  setTimeout(renderKnownThreats, 0);
});

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
      body: JSON.stringify({kind: 'repository', url: repoInput.value, analysis: document.querySelector('#analysis-mode').value}),
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
    const result = {...job.result, analyses: job.analyses, assessment: job.assessment};
    repoResult.replaceChildren(scanDetails(result, true));
    repoResult.className = 'scan-result';
    repoResult.hidden = false;
    await loadRecentScans();
    if (job.analyses?.some(item => ['queued', 'running'].includes(item.status))) {
      refreshAnalysis(job.links.self, Date.now() + 300000);
    }
  } catch (error) {
    renderError(repoResult, error.message);
  } finally {
    repoLoading.hidden = true;
    repoForm.removeAttribute('aria-busy');
    button.disabled = false;
  }
});

document.querySelector('#refresh-scans').addEventListener('click', loadRecentScans);
document.querySelector('#recent-previous').addEventListener('click', () => { recentPage--; loadRecentScans(); });
document.querySelector('#recent-next').addEventListener('click', () => { recentPage++; loadRecentScans(); });
loadRecentScans();
loadKnownThreats();

async function refreshAnalysis(url, deadline) {
  if (Date.now() > deadline) return;
  await new Promise(resolve => setTimeout(resolve, 3000));
  try {
    const response = await fetch(url);
    if (!response.ok) return;
    const job = await response.json();
    const displayed = repoResult.querySelector('a[href^="/scans/"]');
    if (displayed?.getAttribute('href') === `/scans/${job.id}`) {
      repoResult.replaceChildren(scanDetails({...job.result, analyses: job.analyses, assessment: job.assessment}, true));
    }
    await loadRecentScans();
    if (job.analyses?.some(item => ['queued', 'running'].includes(item.status))) refreshAnalysis(url, deadline);
  } catch { /* The persisted record remains available after a lost connection. */ }
}

fetch('/api/v1/engines').then(response => response.json()).then(value => {
  document.querySelector('#analysis-mode option[value="behavioral"]').disabled = !value.items?.windows?.available;
}).catch(() => {});
