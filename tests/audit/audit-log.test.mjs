import { describe, it, expect, beforeEach } from 'vitest';
import { createRequire } from 'module';
import fs from 'fs';
import os from 'os';
import path from 'path';

const require = createRequire(import.meta.url);
let audit, dir;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  process.env.AUDIT_LOG_DIR = dir;
  const p = require.resolve('../../lib/audit-log.js');
  delete require.cache[p];
  audit = require(p);
});

describe('audit-log', () => {
  it('records events with site derived from url and strips query strings', () => {
    audit.log({ actor: 't', type: 'navigate', url: 'https://www.linkedin.com/jobs/view/1?token=secret' });
    const [e] = audit.readEvents();
    expect(e.site).toBe('linkedin.com');
    expect(e.url).toBe('https://www.linkedin.com/jobs/view/1');
  });

  it('never stores sensitive text, only a fingerprint', () => {
    audit.log({ actor: 't', type: 'fill', detail: { text: audit.fingerprint('hunter2') } });
    expect(fs.readdirSync(dir).map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('')).not.toContain('hunter2');
  });

  it('verifies an intact chain', () => {
    audit.log({ actor: 't', type: 'a' }); audit.log({ actor: 't', type: 'b' });
    expect(audit.verify()).toEqual({ ok: true, count: 2 });
  });

  it('detects edited and deleted entries', () => {
    for (const t of ['a', 'b', 'c']) audit.log({ actor: 't', type: t });
    const f = path.join(dir, fs.readdirSync(dir).find((x) => x.endsWith('.jsonl')));
    const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
    fs.writeFileSync(f, [lines[0], lines[1].replace('"b"', '"x"'), lines[2]].join('\n') + '\n');
    expect(audit.verify().ok).toBe(false);
    fs.writeFileSync(f, [lines[0], lines[2]].join('\n') + '\n');
    expect(audit.verify().ok).toBe(false);
  });
});
