import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import vm from 'node:vm';

const root = process.cwd();
const cases = [];

function check(name, test) {
  const started = performance.now();
  try {
    test();
    cases.push({name, status: 'passed', duration: performance.now() - started});
    console.log(`PASS ${name}`);
  } catch (error) {
    cases.push({name, status: 'failed', duration: performance.now() - started, message: error.message});
    console.error(`FAIL ${name}: ${error.message}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

function json(relative) {
  return JSON.parse(read(relative));
}

function https(value, label) {
  assert(typeof value === 'string' && value.startsWith('https://'), `${label} must use HTTPS`);
}

function escapeXml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

check('browser JavaScript parses', () => {
  for (const file of ['app.js', 'evidence.js']) {
    const result = spawnSync(process.execPath, ['--check', path.join(root, 'src', 'ward', 'webui', file)], {encoding: 'utf8'});
    assert(result.status === 0, result.stderr.trim() || `node --check failed: ${file}`);
  }
});

function evidenceRenderers() {
  class Element {
    constructor(tagName) { this.tagName = tagName; this.children = []; }
    set textContent(value) { this.children = [{textContent: String(value ?? '')}]; }
    get textContent() { return this.children.map(child => child.textContent).join(''); }
    set innerHTML(value) { throw new Error('Evidence must never be parsed as HTML'); }
    append(...children) { this.children.push(...children); }
    setAttribute(name, value) { this[name] = value; }
  }
  const script = read('src/ward/webui/app.js');
  const start = script.indexOf('function familyGuidance(');
  const end = script.indexOf('function findingElement(');
  assert(start >= 0 && end > start, 'record rendering helpers are missing');
  return vm.runInNewContext(`${read('src/ward/webui/evidence.js')}\n${script.slice(start, end)}\n({evidenceText, evidenceParagraphs, familyGuidance, externalScanLinks, recordActions})`, {
    URL,
    document: {createElement: tag => new Element(tag), createTextNode: text => ({textContent: text}), querySelectorAll: () => []},
  });
}

check('evidence preserves text and safely formats technical values', () => {
  const {evidenceText} = evidenceRenderers();
  const hash = 'd3b73a54c8f4825bb10974799ba9674ee41863f8c73e6a059f9206258026d32b';
  const text = `Installer.rar hashes to ${hash}; chacha20_xor writes LOCALAPPDATA\\Microsoft\\Windows\\Update\\rt. <img src=x onerror=alert(1)>`;
  const result = evidenceText('p', '', text);
  assert(result.textContent === text, 'rendering changed or truncated evidence');
  const codes = result.children.filter(child => child.tagName === 'code');
  for (const token of [hash, 'Installer.rar', 'chacha20_xor', 'LOCALAPPDATA\\Microsoft\\Windows\\Update\\rt']) {
    assert(codes.some(child => child.textContent === token), `technical value is not code: ${token}`);
  }
  assert(codes.find(child => child.textContent === hash).tabIndex === 0, 'long hashes must be keyboard accessible');
  assert(result.children.every(child => !child.tagName || child.tagName === 'code'), 'untrusted text became markup');
  assert(evidenceText('p', '', 'Use `gpo_open` here.').textContent === 'Use gpo_open here.', 'explicit inline code is not supported');
  assert(evidenceText('p', '', 'Incomplete `markup').textContent === 'Incomplete `markup', 'incomplete markup lost text');
});

check('complete paths and URLs stay in a single code span', () => {
  const {evidenceText, evidenceParagraphs} = evidenceRenderers();
  const paths = ['encrypted/1.zip', '1/1.exe', '/encrypted/update.ps1', '/screen.php', 'https://git-software.cc/ps/Setup.ps1', 'C:\\Users\\Example\\payload.exe'];
  for (const path of paths) {
    const result = evidenceText('p', '', `Observed ${path}, then stopped.`);
    const codes = result.children.filter(child => child.tagName === 'code');
    assert(codes.length === 1 && codes[0].textContent === path, `path was fragmented: ${path}`);
    assert(result.textContent === `Observed ${path}, then stopped.`, 'formatting changed source punctuation');
  }
  const result = evidenceParagraphs('First sentence. Second sentence. Third sentence. Fourth sentence. Fifth sentence.');
  assert(result.children.filter(child => child.tagName === 'p').length === 3, 'dense findings were not split into paragraphs');
  assert(result.children.filter(child => child.tagName === 'p').map(child => child.textContent).join(' ') === 'First sentence. Second sentence. Third sentence. Fourth sentence. Fifth sentence.', 'paragraph formatting changed evidence');
});

check('record links distinguish external scans from repositories and Ward evidence', () => {
  const {externalScanLinks, recordActions} = evidenceRenderers();
  const links = externalScanLinks([
    {source_url: 'https://github.com/owner/malware/blob/main/README.md', malware_db_url: 'https://www.virustotal.com/gui/file/abc'},
    {source_url: 'https://research.checkpoint.com/report', malware_db_url: 'https://www.virustotal.com/gui/file/abc'},
    {source_url: 'https://ward.lley.cat/api/record', malware_db_url: 'https://ward.lley.cat/api/v1/artifacts/abc'},
    {source_url: 'https://www.virustotal.com.attacker.test/file/abc', malware_db_url: 'https://user:secret@www.virustotal.com/gui/file/abc'},
    {malware_db_url: 'https://threatfox.abuse.ch/ioc/123/'},
    {malware_db_url: 'https://bazaar.abuse.ch/browse/signature/XMRig/'},
  ]).children.filter(child => child.tagName === 'a');
  assert(links.length === 3, 'non-scan links or duplicate external scans were displayed');
  assert(links.every(link => link.textContent === 'External Scan'), 'external scan labels are inconsistent');
  assert(links.map(link => link.title).join('|') === 'VirusTotal|ThreatFox|MalwareBazaar', 'external provider attribution was lost');
  const actions = recordActions('/repository?target=owner%2Frepo&latest=1', 'https://github.com/owner/repo').children.filter(child => child.tagName === 'a');
  assert(actions.map(link => link.textContent).join('|') === 'Ward Scan|Repository', 'child record labels are incorrect');
  assert(actions[0].href === '/repository?target=owner%2Frepo&latest=1' && actions[1].href === 'https://github.com/owner/repo', 'record links target the wrong resources');
  for (const invalid of ['javascript:alert(1)', 'https://user:secret@github.com/owner/repo', undefined]) {
    assert(recordActions('/scans/fixture', invalid).children.filter(child => child.tagName === 'a').length === 1, 'unsafe repository link was accepted');
  }
  assert(!read('src/ward/webui/app.js').includes('Supporting research'), 'repository was labelled supporting research');
});

check('parent guidance deduplicates shared text and preserves scoped variants', () => {
  const {familyGuidance} = evidenceRenderers();
  const records = [
    {repository: 'owner/one', symptoms: 'Unexpected elevation.', remediation: 'Preserve evidence.'},
    {repository: 'owner/two', symptoms: 'Unexpected elevation.', remediation: 'Preserve evidence.'},
    {repository: 'owner/three', symptoms: 'Unexpected elevation.', remediation: 'Inspect the scheduled task.'},
  ];
  const result = familyGuidance(records);
  assert(result.children.filter(child => child.tagName === 'h4').map(child => child.textContent).join('|') === 'Symptoms|Remediation', 'parent section labels are incorrect');
  assert(result.children.filter(child => child.textContent === 'Unexpected elevation.').length === 1, 'shared symptoms were duplicated');
  assert(result.children.filter(child => child.textContent === 'Preserve evidence.').length === 1, 'shared remediation was duplicated');
  assert(result.textContent.includes('Inspect the scheduled task.'), 'a remediation variant was lost');
  assert(result.textContent.includes('owner/one, owner/two') && result.textContent.includes('owner/three'), 'variant scope was lost');
});

check('package version is consistent', () => {
  const project = read('pyproject.toml').match(/^version = "([^"]+)"/m)?.[1];
  const module = read('src/ward/__init__.py').match(/^__version__ = "([^"]+)"/m)?.[1];
  assert(project && module && project === module, 'pyproject.toml and ward.__version__ differ');
  const packaging = read('pyproject.toml');
  assert(packaging.includes('ward = "ward.cli:main"'), 'Ward CLI entry point is missing');
});

check('advisory JSON is valid', () => {
  const directory = path.join(root, 'src', 'ward', 'advisories');
  const files = fs.readdirSync(directory).filter(name => name.endsWith('.json'));
  assert(files.length > 0, 'no advisory files were found');
  for (const file of files) {
    const value = JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
    assert(value.schema_version === 1, `${file} must use schema version 1`);
  }
});

check('confirmed indicators are exact and unique', () => {
  const data = json('src/ward/advisories/indicators.json');
  const hashes = new Set();
  for (const item of data.indicators) {
    if (item.status !== 'confirmed') continue;
    assert(/^[a-f0-9]{64}$/i.test(item.sha256), `invalid SHA-256: ${item.sha256}`);
    assert(!hashes.has(item.sha256.toLowerCase()), `duplicate SHA-256: ${item.sha256}`);
    hashes.add(item.sha256.toLowerCase());
    https(item.source_url, `indicator ${item.sha256}`);
  }
});

check('malware records are traceable and unique', () => {
  const data = json('src/ward/advisories/malware-records.json');
  const repositories = new Set();
  for (const item of data.records) {
    const key = item.repository.toLowerCase();
    assert(!repositories.has(key), `duplicate repository: ${item.repository}`);
    repositories.add(key);
    assert(item.malware && item.malicious_path && item.finding, `incomplete record: ${item.repository}`);
    https(item.source_url, `record ${item.repository}`);
    https(item.malware_db_url, `malware database ${item.repository}`);
  }
});

check('homepage hierarchy stays compact', () => {
  const page = read('src/ward/webui/index.html');
  const scanner = page.indexOf('>Scanner<');
  const database = page.indexOf('>Malware Database<');
  const recent = page.indexOf('>Recent Scans<');
  assert(scanner >= 0 && scanner < database && database < recent, 'primary section order changed');
  for (const removed of ['file-input', 'drop-zone', 'Three rules', 'Coverage & research']) {
    assert(!page.includes(removed), `removed homepage panel returned: ${removed}`);
  }
});

check('scanner API wiring stays present', () => {
  const script = read('src/ward/webui/app.js');
  assert(script.includes('/api/v1/scans'), 'repository scan endpoint is missing');
  assert(script.includes('/api/scans'), 'recent scan endpoint is missing');
  assert(!script.includes('/api/campaigns'), 'standalone research feed returned');
});

check('OpenAPI contract covers implemented resources', () => {
  const document = json('src/ward/openapi.json');
  assert(document.openapi === '3.1.0', 'OpenAPI must use version 3.1.0');
  for (const route of [
    '/api/v1/scans', '/api/v1/scans/{scan_id}', '/api/v1/scans/{scan_id}/events',
    '/api/v1/repositories/history', '/api/v1/comparisons', '/api/v1/malware-records',
    '/api/v1/artifacts/{sha256}', '/api/v1/reports/{scan_id}',
    '/api/v1/badges/{owner}/{repository}.svg', '/mcp',
    '/api/v1/badge.svg',
  ]) {
    assert(document.paths[route], `OpenAPI route is missing: ${route}`);
  }
});

check('Ward plugin package is portable and secret-free', () => {
  const plugin = json('integrations/ward-plugin/plugin.json');
  const mcp = json('integrations/ward-plugin/mcp.json');
  const skill = read('integrations/ward-plugin/skills/ward-scanner/SKILL.md').replace(/\r\n/g, '\n');
  assert(plugin.$schema === 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json', 'plugin schema is invalid');
  assert(plugin.extensions?.['com.openai']?.interface?.shortDescription?.length <= 30, 'plugin subtitle exceeds 30 characters');
  assert(mcp.$schema === 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json', 'MCP schema is invalid');
  assert(mcp.mcpServers?.ward?.url === 'https://ward.lley.cat/mcp', 'MCP endpoint is incorrect');
  assert(skill.startsWith('---\nname: ward-scanner\n'), 'Ward skill frontmatter is invalid');
  assert(!/token|password|secret\s*[:=]\s*\S+/i.test(JSON.stringify({plugin, mcp})), 'plugin package may contain a credential');
});

check('responsive accessibility styles stay present', () => {
  const styles = read('src/ward/webui/styles.css');
  assert(styles.includes('@media (max-width: 680px)'), 'mobile layout is missing');
  assert(styles.includes('@media (prefers-reduced-motion: reduce)'), 'reduced motion support is missing');
  assert(styles.includes('focus-visible'), 'keyboard focus styles are missing');
});

const failures = cases.filter(item => item.status === 'failed');
const totalSeconds = cases.reduce((sum, item) => sum + item.duration, 0) / 1000;
const xmlCases = cases.map(item => {
  const failure = item.status === 'failed'
    ? `<failure message="${escapeXml(item.message)}">${escapeXml(item.message)}</failure>`
    : '';
  return `<testcase classname="ward.integrity" name="${escapeXml(item.name)}" time="${(item.duration / 1000).toFixed(4)}">${failure}</testcase>`;
}).join('');
const xml = `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Ward integrity" tests="${cases.length}" failures="${failures.length}" errors="0" skipped="0" time="${totalSeconds.toFixed(4)}">${xmlCases}</testsuite>`;
fs.mkdirSync(path.join(root, 'reports'), {recursive: true});
fs.writeFileSync(path.join(root, 'reports', 'ci.xml'), xml);

console.log(`${cases.length - failures.length}/${cases.length} Ward integrity checks passed`);
if (failures.length) process.exitCode = 1;
