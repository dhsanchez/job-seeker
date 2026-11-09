'use strict';
/**
 * audit-log.js — append-only, tamper-evident audit trail of everything the
 * agent does on the user's behalf (sites visited, interactions, sends, DB writes).
 *
 * Storage: logs/audit/YYYY-MM-DD.jsonl (gitignored, local only). One JSON event
 * per line. Each event carries `prev` (hash of the previous event) and `hash`
 * (sha256 of the event body + prev), so edits or deletions are detectable with
 * `node scripts/audit.js verify`.
 *
 * Privacy: typed text, eval code, SQL and message bodies are NEVER stored
 * verbatim. Only length + short sha256 fingerprint (see `fingerprint`), so the
 * log can be shared with an auditor without leaking credentials or PII.
 *
 * Never throws: auditing must not break a flow. Failures go to stderr.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO_ROOT = process.cwd();
const AUDIT_DIR = process.env.AUDIT_LOG_DIR || path.join(REPO_ROOT, 'logs', 'audit');
const LOCK_PATH = path.join(AUDIT_DIR, '.lock');
const STATE_PATH = path.join(AUDIT_DIR, '.state.json');
const GENESIS = '0'.repeat(64);

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** {len, sha} stand-in for sensitive text. */
function fingerprint(text) {
  const s = text == null ? '' : String(text);
  return { len: s.length, sha: sha(s).slice(0, 12) };
}

/** Hostname of a URL, or null. */
function siteOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; }
}

/** Strip query/hash (may hold tokens) from a URL. */
function cleanUrl(url) {
  try { const u = new URL(url); return u.origin + u.pathname; } catch { return null; }
}

function sleepMs(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(fn) {
  fs.mkdirSync(AUDIT_DIR, { recursive: true });
  let fd = null;
  for (let i = 0; i < 100 && fd === null; i++) {
    try { fd = fs.openSync(LOCK_PATH, 'wx'); }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try { if (Date.now() - fs.statSync(LOCK_PATH).mtimeMs > 5000) fs.unlinkSync(LOCK_PATH); } catch {}
      sleepMs(20);
    }
  }
  try { return fn(); }
  finally { if (fd !== null) { fs.closeSync(fd); try { fs.unlinkSync(LOCK_PATH); } catch {} } }
}

function dayFile(d) { return path.join(AUDIT_DIR, `${d.toISOString().slice(0, 10)}.jsonl`); }

function listLogFiles() {
  try { return fs.readdirSync(AUDIT_DIR).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort(); }
  catch { return []; }
}

/** Hash of the most recent event across all day files (chain continues across days). */
function lastHash() {
  const files = listLogFiles();
  for (let i = files.length - 1; i >= 0; i--) {
    const lines = fs.readFileSync(path.join(AUDIT_DIR, files[i]), 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length) { try { return JSON.parse(lines[lines.length - 1]).hash; } catch { return GENESIS; } }
  }
  return GENESIS;
}

/**
 * Record one event.
 * @param {object} ev { actor, type, site?, url?, session?, target?, detail?, ok? }
 *   type examples: navigate, click, fill, type, press, upload, eval, send_email, db_write
 */
function log(ev) {
  try {
    return withLock(() => {
      const now = new Date();
      const body = { ts: now.toISOString(), pid: process.pid, ...ev };
      if (body.url && !body.site) body.site = siteOf(body.url);
      if (body.url) body.url = cleanUrl(body.url);
      body.prev = lastHash();
      body.hash = sha(JSON.stringify(body));
      fs.appendFileSync(dayFile(now), JSON.stringify(body) + '\n');
      return body;
    });
  } catch (e) {
    console.error(`[audit] failed to write log: ${e.message}`);
    return null;
  }
}

/** Last URL seen per browser session, so clicks/fills can be attributed to a site. */
function readState() { try { return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')); } catch { return {}; } }
function setSessionUrl(session, url) {
  try {
    withLock(() => {
      const s = readState();
      s[session || 'default'] = url;
      fs.writeFileSync(STATE_PATH, JSON.stringify(s));
    });
  } catch {}
}
function getSessionUrl(session) { return readState()[session || 'default'] || null; }

/** Read all events (optionally filtered by ISO date range, inclusive). */
function readEvents({ from, to } = {}) {
  const out = [];
  for (const f of listLogFiles()) {
    const day = f.slice(0, 10);
    if ((from && day < from) || (to && day > to)) continue;
    for (const line of fs.readFileSync(path.join(AUDIT_DIR, f), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { out.push(JSON.parse(line)); } catch { out.push({ corrupt: true, raw: line, file: f }); }
    }
  }
  return out;
}

/** Verify the hash chain across all files. Returns {ok, count, error?}. */
function verify() {
  let prev = null, count = 0;
  for (const ev of readEvents()) {
    if (ev.corrupt) return { ok: false, count, error: `unparseable line in ${ev.file}` };
    const { hash, ...rest } = ev;
    if (sha(JSON.stringify(rest)) !== hash) return { ok: false, count, error: `hash mismatch at event ${count + 1} (${ev.ts})` };
    if (prev !== null && ev.prev !== prev) return { ok: false, count, error: `broken chain at event ${count + 1} (${ev.ts}): an entry was removed or reordered` };
    prev = hash; count++;
  }
  return { ok: true, count };
}

module.exports = { log, fingerprint, siteOf, cleanUrl, readEvents, verify, setSessionUrl, getSessionUrl, AUDIT_DIR };
