'use strict';

const $ = id => document.getElementById(id);
const KEY_SLOT = 'chats-key';
const OPENING_CHAT = 143;
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

let key = null;
let chats = [];
let index = -1;
let shownMonth = null;
let loadToken = 0;

/* ---------- Crypto ---------- */

const b64ToBytes = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const bytesToB64 = b => btoa(String.fromCharCode(...b));

async function deriveKey(password, meta) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(meta.salt), iterations: meta.iterations },
    base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}

async function fetchChecked(url) {
  const res = await fetch(url, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`Could not load ${url} (${res.status})`);
  return res;
}

async function readEncrypted(file, withKey = key) {
  const bytes = new Uint8Array(await (await fetchChecked(`data/${file}`)).arrayBuffer());
  const zipped = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, withKey, bytes.slice(12));
  const stream = new Blob([zipped]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(stream).text());
}

/* ---------- Markdown ---------- */

const escapeHtml = s => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function renderMath(tex, displayMode) {
  try {
    const html = katex.renderToString(tex, { displayMode, throwOnError: true, output: 'html' });
    return displayMode ? `<div class="math-block">${html}</div>` : html;
  } catch {
    return `<code>${escapeHtml(tex)}</code>`;
  }
}

// A lone $ is math only when it hugs its content and is not followed by a
// digit, so prices such as "$5 and $10" stay as text.
const INLINE_MATH = [
  /^\\\(([\s\S]+?)\\\)/,
  /^\$(?![\s\d])((?:[^$\n\\]|\\.)+?)(?<![\s])\$(?![\d\w])/,
];
const BLOCK_MATH = [/^\$\$\s*([\s\S]+?)\s*\$\$(?:\n+|$)/, /^\\\[\s*([\s\S]+?)\s*\\\](?:\n+|$)/];

marked.use({
  breaks: false,
  gfm: true,
  renderer: {
    html: token => escapeHtml(token.text),
    table(token) {
      return `<div class="table-wrap">${marked.Renderer.prototype.table.call(this, token)}</div>`;
    },
    link(token) {
      const text = this.parser.parseInline(token.tokens);
      if (!/^(https?:|mailto:)/i.test(token.href)) return text;
      return `<a href="${escapeHtml(token.href)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
    },
    image: token => escapeHtml(token.text || ''),
  },
  extensions: [
    {
      name: 'mathBlock', level: 'block',
      start: src => { const i = src.search(/\$\$|\\\[/); return i < 0 ? undefined : i; },
      tokenizer(src) {
        for (const re of BLOCK_MATH) {
          const m = re.exec(src);
          if (m) return { type: 'mathBlock', raw: m[0], text: m[1] };
        }
      },
      renderer: token => renderMath(token.text, true),
    },
    {
      name: 'mathInline', level: 'inline',
      start: src => { const i = src.search(/\$|\\\(/); return i < 0 ? undefined : i; },
      tokenizer(src) {
        for (const re of INLINE_MATH) {
          const m = re.exec(src);
          if (m) return { type: 'mathInline', raw: m[0], text: m[1] };
        }
      },
      renderer: token => renderMath(token.text, false),
    },
  ],
});

function markdownInto(el, source, breaks) {
  el.innerHTML = DOMPurify.sanitize(marked.parse(source, { breaks }), { ADD_ATTR: ['target'] });
}

/* ---------- Dates ---------- */

const monthKey = date => date.slice(0, 7);
function monthLabel(key) {
  const [y, m] = key.split('-');
  return `${MONTHS[+m - 1]} ${y}`;
}
function longDate(date) {
  const [y, m, d] = date.split('-');
  return `${MONTHS[+m - 1]} ${+d}, ${y}`;
}
function dayLabel(date) {
  const [, m, d] = date.split('-');
  return `${MONTHS[+m - 1].slice(0, 3)} ${+d}`;
}

/* ---------- Reader ---------- */

function renderTool(part) {
  const box = document.createElement('details');
  box.className = 'tool';
  const summary = document.createElement('summary');
  summary.textContent = `Used ${part.name}`;
  box.append(summary);
  // Tool output can be huge, so it is built when opened.
  box.addEventListener('toggle', () => {
    if (!box.open || box.childElementCount > 1) return;
    for (const p of part.params || []) {
      const label = document.createElement('p');
      label.className = 'tool-param';
      label.textContent = p.name;
      const pre = document.createElement('pre');
      pre.textContent = p.value;
      box.append(label, pre);
    }
    if (part.raw) {
      const pre = document.createElement('pre');
      pre.textContent = part.raw;
      box.append(pre);
    }
  });
  return box;
}

function renderMessage(msg) {
  const el = document.createElement('article');
  el.className = msg.role === 'User' ? 'msg msg-user' : 'msg msg-claude';
  el.setAttribute('aria-label', msg.role === 'User' ? 'You' : 'Claude');
  if (msg.sent) {
    const time = document.createElement('span');
    time.className = 'msg-time';
    time.textContent = msg.sent.split(' ')[1];
    el.append(time);
  }
  for (const part of msg.parts) {
    if (part.type === 'tool') {
      el.append(renderTool(part));
    } else {
      const prose = document.createElement('div');
      prose.className = 'prose';
      markdownInto(prose, part.md, msg.role === 'User');
      el.append(prose);
    }
  }
  return el;
}

function pagerButton(chat, label, go) {
  const btn = document.createElement('button');
  btn.type = 'button';
  const small = document.createElement('small');
  small.textContent = `${label}, ${dayLabel(chat.date)}`;
  btn.append(small, chat.title);
  btn.addEventListener('click', go);
  return btn;
}

async function show(i, { fromHash = false } = {}) {
  if (i < 0 || i >= chats.length) return;
  index = i;
  const chat = chats[i];
  const token = ++loadToken;
  if (!fromHash) history.replaceState(null, '', `#${chat.n}`);
  document.title = `${chat.date} ${chat.title}`;
  $('picker-date').textContent = longDate(chat.date);
  $('picker-title').textContent = chat.title;
  $('position').textContent = `${i + 1} of ${chats.length}`;
  $('older').disabled = i === 0;
  $('newer').disabled = i === chats.length - 1;
  $('older').setAttribute('aria-label', i ? `Older: ${chats[i - 1].title}` : 'No older conversation');
  $('newer').setAttribute('aria-label', i < chats.length - 1 ? `Newer: ${chats[i + 1].title}` : 'No newer conversation');
  $('older').title = i ? `Older: ${chats[i - 1].title}` : '';
  $('newer').title = i < chats.length - 1 ? `Newer: ${chats[i + 1].title}` : '';
  shownMonth = monthKey(chat.date);
  if (!$('panel').hidden) renderBrowser();

  const reader = $('reader');
  const head = document.createElement('header');
  head.className = 'chat-head';
  const dateEl = document.createElement('p');
  dateEl.className = 'chat-date';
  dateEl.textContent = longDate(chat.date);
  const titleEl = document.createElement('h1');
  titleEl.className = 'chat-title';
  titleEl.textContent = chat.title;
  head.append(dateEl, titleEl);
  const status = document.createElement('p');
  status.className = 'status';
  status.textContent = 'Opening conversation';
  reader.replaceChildren(head, status);
  window.scrollTo(0, 0);

  try {
    const data = await readEncrypted(chat.file);
    if (token !== loadToken) return;
    if (data.url) {
      const link = document.createElement('a');
      link.className = 'chat-link';
      link.href = data.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = 'Open in Claude';
      head.append(link);
    }
    const frag = document.createDocumentFragment();
    frag.append(head);
    data.messages.forEach(m => frag.append(renderMessage(m)));
    const pager = document.createElement('nav');
    pager.className = 'pager';
    pager.setAttribute('aria-label', 'Older and newer');
    if (i > 0) pager.append(pagerButton(chats[i - 1], 'Older', () => show(i - 1)));
    if (i < chats.length - 1) pager.append(pagerButton(chats[i + 1], 'Newer', () => show(i + 1)));
    frag.append(pager);
    reader.replaceChildren(frag);
  } catch (err) {
    if (token !== loadToken) return;
    status.textContent = `This conversation did not open. ${err.message}. Reload the page and try again.`;
  }
}

/* ---------- Browse panel ---------- */

function groupByMonth(items) {
  const groups = new Map();
  for (const chat of items) {
    const k = monthKey(chat.date);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(chat);
  }
  return groups;
}

function renderMonths() {
  const groups = groupByMonth(chats);
  const max = Math.max(...[...groups.values()].map(g => g.length));
  const strip = $('months');
  strip.replaceChildren();
  let lastYear = null;
  for (const [k, group] of groups) {
    const [year, mon] = k.split('-');
    if (lastYear && year !== lastYear) {
      const gap = document.createElement('span');
      gap.className = 'year-break';
      strip.append(gap);
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'month';
    btn.dataset.month = k;
    btn.setAttribute('aria-label', `${monthLabel(k)}, ${group.length} conversations`);
    btn.title = `${monthLabel(k)}: ${group.length}`;
    const count = document.createElement('span');
    count.className = 'month-count';
    count.textContent = group.length;
    const bar = document.createElement('span');
    bar.className = 'month-bar';
    bar.style.height = `${Math.round((group.length / max) * 56)}px`;
    const name = document.createElement('span');
    name.className = 'month-name';
    name.textContent = mon === '01' || !lastYear ? `${MONTHS[+mon - 1].slice(0, 3)} ${year.slice(2)}` : MONTHS[+mon - 1].slice(0, 3);
    btn.append(count, bar, name);
    btn.addEventListener('click', () => {
      $('search').value = '';
      shownMonth = k;
      renderBrowser();
    });
    strip.append(btn);
    lastYear = year;
  }
}

function itemButton(chat) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'item';
  btn.textContent = chat.title;
  if (chats[index] === chat) btn.setAttribute('aria-current', 'true');
  btn.addEventListener('click', () => {
    closePanel();
    show(chats.indexOf(chat));
  });
  return btn;
}

function renderDays(parent, items) {
  const byDay = new Map();
  for (const chat of items) {
    if (!byDay.has(chat.date)) byDay.set(chat.date, []);
    byDay.get(chat.date).push(chat);
  }
  for (const [date, group] of byDay) {
    const row = document.createElement('div');
    row.className = 'day';
    const label = document.createElement('div');
    label.className = 'day-label';
    label.textContent = dayLabel(date);
    const col = document.createElement('div');
    col.className = 'day-items';
    group.forEach(chat => col.append(itemButton(chat)));
    row.append(label, col);
    parent.append(row);
  }
}

function renderBrowser() {
  const query = $('search').value.trim().toLowerCase();
  const list = $('list');
  list.replaceChildren();
  const matches = query ? chats.filter(c => c.title.toLowerCase().includes(query)) : null;
  const months = matches ? groupByMonth(matches) : new Map([[shownMonth, chats.filter(c => monthKey(c.date) === shownMonth)]]);

  document.querySelectorAll('.month').forEach(btn => {
    const active = matches ? months.has(btn.dataset.month) : btn.dataset.month === shownMonth;
    btn.setAttribute('aria-pressed', String(active));
  });

  if (matches && !matches.length) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'No title contains that text.';
    list.append(empty);
    return;
  }
  for (const [k, group] of months) {
    const h = document.createElement('h2');
    h.className = 'list-month';
    h.textContent = monthLabel(k);
    list.append(h);
    renderDays(list, group);
  }
}

function openPanel() {
  $('panel').hidden = false;
  $('picker').setAttribute('aria-expanded', 'true');
  $('search').value = '';
  shownMonth = monthKey(chats[index].date);
  renderBrowser();
  document.querySelector('.month[aria-pressed="true"]')?.scrollIntoView({ block: 'nearest', inline: 'center' });
  $('list').querySelector('[aria-current="true"]')?.scrollIntoView({ block: 'nearest' });
  $('search').focus({ preventScroll: true });
}

function closePanel() {
  $('panel').hidden = true;
  $('picker').setAttribute('aria-expanded', 'false');
}

/* ---------- Startup ---------- */

function indexFromHash() {
  const n = Number(location.hash.slice(1));
  return chats.findIndex(c => c.n === n);
}

async function enterApp() {
  chats = await readEncrypted('manifest.bin');
  $('gate').hidden = true;
  $('app').hidden = false;
  renderMonths();
  const fromHash = indexFromHash();
  const opening = chats.findIndex(c => c.n === OPENING_CHAT);
  await show(fromHash >= 0 ? fromHash : opening >= 0 ? opening : chats.length - 1);
}

function lock() {
  try { sessionStorage.removeItem(KEY_SLOT); } catch { /* storage may be blocked */ }
  key = null;
  chats = [];
  $('reader').replaceChildren();
  history.replaceState(null, '', location.pathname);
  location.reload();
}

$('gate-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('unlock');
  btn.disabled = true;
  btn.textContent = 'Opening';
  $('gate-error').textContent = '';
  try {
    const meta = await (await fetchChecked('data/meta.json')).json();
    key = await deriveKey($('password').value, meta);
    await enterApp();
    try {
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      sessionStorage.setItem(KEY_SLOT, bytesToB64(raw));
    } catch { /* storage may be blocked; the password is asked again on reload */ }
    $('password').value = '';
  } catch (err) {
    key = null;
    $('gate-error').textContent = err.name === 'OperationError'
      ? 'That password is not correct. Try again.'
      : `The site did not open. ${err.message}.`;
    $('password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Open';
  }
});

$('older').addEventListener('click', () => show(index - 1));
$('newer').addEventListener('click', () => show(index + 1));
$('lock').addEventListener('click', lock);
$('search').addEventListener('input', renderBrowser);
$('picker').addEventListener('click', () => ($('panel').hidden ? openPanel() : closePanel()));
window.addEventListener('hashchange', () => {
  const i = indexFromHash();
  if (i >= 0 && i !== index) show(i, { fromHash: true });
});
document.addEventListener('keydown', e => {
  if ($('app').hidden) return;
  if (e.key === 'Escape' && !$('panel').hidden) {
    closePanel();
    $('picker').focus();
    return;
  }
  if (e.target.matches('input') || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'ArrowLeft') show(index - 1);
  if (e.key === 'ArrowRight') show(index + 1);
});
document.addEventListener('click', e => {
  if (!$('panel').hidden && !e.target.closest('#panel, #picker')) closePanel();
});

(async () => {
  let saved = null;
  try { saved = sessionStorage.getItem(KEY_SLOT); } catch { /* storage may be blocked */ }
  if (!saved) return;
  try {
    key = await crypto.subtle.importKey('raw', b64ToBytes(saved), 'AES-GCM', true, ['decrypt']);
    await enterApp();
  } catch {
    key = null;
    try { sessionStorage.removeItem(KEY_SLOT); } catch { /* ignore */ }
  }
})();
