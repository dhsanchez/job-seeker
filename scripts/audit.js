#!/usr/bin/env node
/**
 * audit.js — report on / verify the agent's audit trail (logs/audit/*.jsonl).
 *
 *   node scripts/audit.js summary [--from YYYY-MM-DD] [--to YYYY-MM-DD]   sites + action counts per day
 *   node scripts/audit.js report  [--from ..] [--to ..] [--site <host>] [--type <t>] [--csv]   full event list
 *   node scripts/audit.js verify                                          check the tamper-evident hash chain
 */
const audit = require('../lib/audit-log');

const args = process.argv.slice(2);
const cmd = args[0] || 'summary';
const opt = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const from = opt('--from'), to = opt('--to'), site = opt('--site'), type = opt('--type');

if (cmd === 'verify') {
  const r = audit.verify();
  console.log(r.ok ? `OK: ${r.count} events, chain intact` : `FAILED: ${r.error} (after ${r.count} valid events)`);
  process.exit(r.ok ? 0 : 2);
}

let events = audit.readEvents({ from, to });
if (site) events = events.filter((e) => e.site === site || (e.site || '').endsWith('.' + site));
if (type) events = events.filter((e) => e.type === type);

if (cmd === 'report') {
  if (args.includes('--csv')) {
    const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    console.log('ts,actor,type,site,url,session,target,ok,detail');
    for (const e of events) console.log([e.ts, e.actor, e.type, e.site, e.url, e.session, e.target, e.ok, JSON.stringify(e.detail || '')].map(q).join(','));
  } else {
    for (const e of events) {
      console.log(`${e.ts}  ${e.ok === false ? 'FAIL ' : ''}${e.type.padEnd(10)} ${(e.site || '-').padEnd(24)} ${e.url || ''} ${e.target || ''} ${e.detail ? JSON.stringify(e.detail) : ''}`.trimEnd());
    }
  }
} else if (cmd === 'summary') {
  const days = {};
  for (const e of events) {
    const d = (e.ts || '').slice(0, 10);
    const day = (days[d] ||= { sites: new Set(), types: {} });
    if (e.site) day.sites.add(e.site);
    day.types[e.type] = (day.types[e.type] || 0) + 1;
  }
  for (const d of Object.keys(days).sort()) {
    console.log(`${d}  sites: ${[...days[d].sites].sort().join(', ') || '-'}`);
    console.log(`            actions: ${Object.entries(days[d].types).map(([k, v]) => `${k}=${v}`).join(' ')}`);
  }
  if (!events.length) console.log('No audit events in range.');
} else {
  console.error('Usage: audit.js summary|report|verify [--from D] [--to D] [--site host] [--type t] [--csv]');
  process.exit(1);
}
