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
    if (code.textContent.length >= 32) code.tabIndex = 0;
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

for (const element of document.querySelectorAll('[data-evidence]')) {
  const paragraphs = evidenceParagraphs(element.textContent);
  element.replaceChildren(...paragraphs.childNodes);
}
