function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function evidenceText(tag, className, value) {
  const element = textElement(tag, className, '');
  const text = String(value ?? '');
  const tokens = /`[^`\n]+`|https?:\/\/[^\s`<>"()]*[\w/#=-]|\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b|(?:[A-Za-z]:)?[\\/]?(?:[\w.$-]+[\\/])+[\w.$-]*[\w$-]|\/?\b[\w.-]+\.(?:exe|dll|rar|zip|aes|key|ps1|bat|cmd|js|py|json|php|md|xml)\b|\b[A-Za-z]\w*_\w+\b/gi;
  let end = 0;
  for (const match of text.matchAll(tokens)) {
    element.append(document.createTextNode(text.slice(end, match.index)));
    const code = textElement('code', '', match[0].startsWith('`') ? match[0].slice(1, -1) : match[0]);
    element.append(code);
    end = match.index + match[0].length;
  }
  element.append(document.createTextNode(text.slice(end)));
  return element;
}

function evidenceParagraphs(value) {
  const section = textElement('div', 'evidence-copy', '');
  const sentences = String(value ?? '').split(/(?<=[.!?])\s+(?=[A-Z])/);
  for (let index = 0; index < sentences.length; index += 2) {
    section.append(evidenceText('p', '', sentences.slice(index, index + 2).join(' ')));
  }
  return section;
}

function recordReport(record, template) {
  const report = textElement('article', 'record-report', '');
  const substitute = value => String(value ?? '').replace(/\{(artifact|malicious_path)\}/g, (_, key) => record[key] || 'Not recorded');
  const facts = textElement('dl', 'report-facts', '');
  const fact = (label, value) => {
    facts.append(textElement('dt', '', label), evidenceText('dd', '', value));
  };
  const revision = String(record.release || '').match(/^(.+?) at ([a-f0-9]{40})(?:; (.*))?$/i);
  if (revision) {
    fact('Revision', `\`${revision[1]}\` @ \`${revision[2]}\``);
    if (revision[3]) {
      const observed = revision[3].match(/^external (?:stages|artifact) observed (\d{4}-\d{2}-\d{2})$/);
      fact(observed ? 'External stages observed' : 'Release details', observed ? observed[1] : revision[3]);
    }
  } else {
    fact('Release', record.release || 'Not recorded');
  }
  report.append(facts);

  const basis = `${record.finding || ''} ${record.behavior || ''}`;
  const supported = template && Array.isArray(template.chain) && Array.isArray(template.stages)
    && Array.isArray(template.hashes) && template.stages.length
    && template.chain.every(item => typeof item === 'string')
    && template.stages.every(item => typeof item.title === 'string' && typeof item.artifact === 'string' && typeof item.text === 'string')
    && template.hashes.every(item => /^[a-f0-9]{64}$/i.test(item.sha256) && basis.includes(item.sha256));
  if (supported) {
    fact('Delivery', template.delivery);
    report.append(textElement('h3', '', 'Execution Chain'));
    const chain = textElement('p', 'report-chain', '');
    template.chain.forEach((item, index) => {
      if (index) chain.append(document.createTextNode(' → '));
      chain.append(textElement('code', '', substitute(item)));
    });
    report.append(chain, textElement('h3', '', 'Technical Analysis'));
    const stages = textElement('ol', 'report-stages', '');
    for (const [index, stage] of template.stages.entries()) {
      const item = textElement('li', '', '');
      const title = textElement('p', 'report-stage-title', '');
      title.append(textElement('strong', '', `${index + 1}. ${stage.title}`), document.createTextNode(' · '), textElement('code', '', substitute(stage.artifact)));
      item.append(title, evidenceParagraphs(substitute(stage.text)));
      stages.append(item);
    }
    report.append(stages, textElement('h3', '', 'Artifact Hashes (SHA-256)'));
    if (template.hashes.length) {
      const hashes = textElement('dl', 'report-hashes', '');
      for (const hash of template.hashes) {
        const value = textElement('dd', '', '');
        value.append(textElement('code', '', hash.sha256));
        hashes.append(textElement('dt', '', substitute(hash.artifact)), value);
      }
      report.append(hashes);
    } else {
      report.append(evidenceParagraphs(template.hash_note || 'No artifact hashes recorded.'));
    }
    report.append(textElement('h3', '', 'Assessment'), evidenceParagraphs(template.assessment));
  } else {
    fact('Affected files', record.malicious_path || 'Not recorded');
    report.append(textElement('h3', '', 'Finding'), evidenceParagraphs(record.finding));
  }
  if (record.scope) {
    report.append(textElement('h3', '', 'Evidence Boundary'), evidenceParagraphs(record.scope));
  }
  return report;
}

for (const element of document.querySelectorAll('[data-evidence]')) {
  const paragraphs = evidenceParagraphs(element.textContent);
  element.replaceChildren(...paragraphs.childNodes);
}

for (const element of document.querySelectorAll('[data-reviewed-report]')) {
  try {
    const {record, template} = JSON.parse(element.dataset.reviewedReport);
    element.replaceChildren(recordReport(record, template));
  } catch {
    // Keep the escaped original evidence readable if presentation data is unavailable.
  }
}
