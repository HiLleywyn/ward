import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';

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
  const result = spawnSync(process.execPath, ['--check', path.join(root, 'src', 'emuwatch', 'webui', 'app.js')], {
    encoding: 'utf8',
  });
  assert(result.status === 0, result.stderr.trim() || 'node --check failed');
});

check('package version is consistent', () => {
  const project = read('pyproject.toml').match(/^version = "([^"]+)"/m)?.[1];
  const module = read('src/emuwatch/__init__.py').match(/^__version__ = "([^"]+)"/m)?.[1];
  assert(project && module && project === module, 'pyproject.toml and emuwatch.__version__ differ');
});

check('advisory JSON is valid', () => {
  const directory = path.join(root, 'src', 'emuwatch', 'advisories');
  const files = fs.readdirSync(directory).filter(name => name.endsWith('.json'));
  assert(files.length > 0, 'no advisory files were found');
  for (const file of files) {
    const value = JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
    assert(value.schema_version === 1, `${file} must use schema version 1`);
  }
});

check('confirmed indicators are exact and unique', () => {
  const data = json('src/emuwatch/advisories/indicators.json');
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
  const data = json('src/emuwatch/advisories/malware-records.json');
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
  const page = read('src/emuwatch/webui/index.html');
  const scanner = page.indexOf('>Scanner<');
  const database = page.indexOf('>Malware Database<');
  const recent = page.indexOf('>Recent Scans<');
  assert(scanner >= 0 && scanner < database && database < recent, 'primary section order changed');
  for (const removed of ['file-input', 'drop-zone', 'Three rules', 'Coverage & research']) {
    assert(!page.includes(removed), `removed homepage panel returned: ${removed}`);
  }
});

check('scanner API wiring stays present', () => {
  const script = read('src/emuwatch/webui/app.js');
  assert(script.includes('/api/scan-repo'), 'repository scan endpoint is missing');
  assert(script.includes('/api/scans'), 'recent scan endpoint is missing');
  assert(!script.includes('/api/campaigns'), 'standalone research feed returned');
});

check('responsive accessibility styles stay present', () => {
  const styles = read('src/emuwatch/webui/styles.css');
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
