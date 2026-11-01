// Encrypts conversations/*.md into docs/data/. Only docs/ is published.
// Usage: node build.mjs
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const SRC = path.join(ROOT, 'conversations');
const OUT = path.join(ROOT, 'docs', 'data');
const ENV_FILE = path.join(ROOT, '.env');
const ITERATIONS = 600000;
// In these periods only the KEEP_DATES and KEEP_CHATS are published. Other files stay local.
const SELECTIVE_PERIODS = /^(2025-|2026-01-|2026-02-|2026-03-|2026-04-02)/;
const KEEP_DATES = new Set(['2025-09-03', '2025-10-15', '2026-01-22', '2026-01-24', '2026-01-26', '2026-03-24', '2026-03-26', '2026-03-30']);
const KEEP_CHATS = new Set(['142']);

function readPassword() {
  const env = fs.existsSync(ENV_FILE) ? fs.readFileSync(ENV_FILE, 'utf8') : '';
  const m = env.match(/^\s*(?:export\s+)?CHAT_PASSWORD\s*=\s*(.*?)\s*$/m);
  const password = m ? m[1].replace(/^(['"])(.*)\1$/, '$2') : '';
  if (!password) throw new Error('Set CHAT_PASSWORD in .env');
  return password;
}

const deriveKey = (password, salt) => crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
const hmac = (key, text) => crypto.createHmac('sha256', key).update(text).digest();

// The IV comes from the content, so an unchanged conversation encrypts to
// identical bytes and a rebuild only changes files whose content changed.
function encrypt(key, value) {
  const plain = zlib.gzipSync(JSON.stringify(value), { mtime: 0, level: 9 });
  const iv = hmac(key, Buffer.concat([Buffer.from('iv:'), plain])).subarray(0, 12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([iv, body]);
}

function canDecrypt(key, bytes) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(-16));
    decipher.update(bytes.subarray(12, -16));
    decipher.final();
    return true;
  } catch {
    return false;
  }
}

// Keep the salt while the password is unchanged, so rebuilds stay small.
function loadOrCreateKey(password) {
  const metaPath = path.join(OUT, 'meta.json');
  const manifestPath = path.join(OUT, 'manifest.bin');
  if (fs.existsSync(metaPath) && fs.existsSync(manifestPath)) {
    const salt = Buffer.from(JSON.parse(fs.readFileSync(metaPath, 'utf8')).salt, 'base64');
    const key = deriveKey(password, salt);
    if (canDecrypt(key, fs.readFileSync(manifestPath))) return { key, salt };
  }
  const salt = crypto.randomBytes(16);
  return { key: deriveKey(password, salt), salt };
}

function parseTool(lines) {
  const name = (lines[0].match(/^<tool name="([^"]*)"/) || [])[1] || 'tool';
  const body = lines.slice(1, -1).join('\n');
  const params = [...body.matchAll(/<parameter name="([^"]*)">([\s\S]*?)<\/parameter>/g)]
    .map(m => ({ name: m[1], value: m[2] }));
  return { type: 'tool', name, params, raw: params.length ? undefined : body };
}

function cleanText(text) {
  return text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>\n?/g, '').trim();
}

// Splits one export into messages. A role heading inside a tool call is not a
// new message, and a repeated role is a heading quoted in the text.
export function parseConversation(md) {
  const lines = md.split('\n');
  const meta = {};
  let i = 1;
  for (; i < lines.length && lines[i] !== '---'; i++) {
    const m = lines[i].match(/^- ([^:]+): (.*)$/);
    if (m) meta[m[1]] = m[2];
  }
  const messages = [];
  let current = null;
  let text = [];
  let tool = null;
  const flush = () => {
    const cleaned = cleanText(text.join('\n'));
    if (current && cleaned) current.parts.push({ type: 'text', md: cleaned });
    text = [];
  };
  for (i += 1; i < lines.length; i++) {
    const line = lines[i];
    if (tool) {
      tool.push(line);
      if (line === '</tool>') {
        current.parts.push(parseTool(tool));
        tool = null;
      }
      continue;
    }
    const role = line.match(/^## (User|Claude)$/);
    if (role && (!current || current.role !== role[1])) {
      flush();
      current = { role: role[1], parts: [] };
      messages.push(current);
      continue;
    }
    if (current && /^<tool name="[^"]*">$/.test(line)) {
      flush();
      tool = [line];
      continue;
    }
    const sent = line.match(/Message sent at \w+ (\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}) local time/);
    if (sent && current && !current.sent) current.sent = sent[1];
    text.push(line);
  }
  if (tool) text.push(...tool);
  flush();
  return { url: meta.URL, messages };
}

function build() {
  const password = readPassword();
  const { key, salt } = loadOrCreateKey(password);
  fs.mkdirSync(OUT, { recursive: true });

  const names = fs.readdirSync(SRC).filter(f => f.endsWith('.md')).sort();
  const manifest = [];
  const keep = new Set(['meta.json', 'manifest.bin']);
  for (const name of names) {
    const m = name.match(/^(\d{3}) (\d{4}-\d{2}-\d{2}) (.+)\.md$/);
    if (!m) throw new Error(`Unexpected file name: ${name}`);
    if (SELECTIVE_PERIODS.test(m[2]) && !KEEP_DATES.has(m[2]) && !KEEP_CHATS.has(m[1])) continue;
    const md = fs.readFileSync(path.join(SRC, name), 'utf8');
    const title = (md.match(/^# (.+)$/m) || [])[1] || m[3];
    const conversation = parseConversation(md);
    const file = hmac(key, `file:${m[1]}`).toString('hex').slice(0, 24) + '.bin';
    fs.writeFileSync(path.join(OUT, file), encrypt(key, conversation));
    keep.add(file);
    manifest.push({ n: Number(m[1]), date: m[2], title, file });
  }
  manifest.sort((a, b) => a.date.localeCompare(b.date) || a.n - b.n);

  fs.writeFileSync(path.join(OUT, 'manifest.bin'), encrypt(key, manifest));
  fs.writeFileSync(path.join(OUT, 'meta.json'),
    JSON.stringify({ salt: salt.toString('base64'), iterations: ITERATIONS }));
  for (const f of fs.readdirSync(OUT)) {
    if (!keep.has(f)) fs.unlinkSync(path.join(OUT, f));
  }
  console.log(`Encrypted ${manifest.length} conversations into docs/data/`);
}

if (process.argv[1] === new URL(import.meta.url).pathname) build();
