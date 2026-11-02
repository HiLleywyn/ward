'use strict';

const status = document.querySelector('#copy-status');

async function copyText(button) {
  const targetId = button.dataset.copyTarget;
  const text = targetId
    ? document.getElementById(targetId)?.innerText
    : button.dataset.copy;
  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
    status.textContent = 'Copied to clipboard.';
  } catch {
    button.textContent = 'Select';
    status.textContent = 'Clipboard access was unavailable. Select the text manually.';
  }
  window.setTimeout(() => { button.textContent = 'Copy'; }, 1600);
}

document.querySelectorAll('.copy-button').forEach((button) => {
  button.addEventListener('click', () => copyText(button));
});
