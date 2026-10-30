import { collectFiles, readFile, usesPayPal } from './detect.js';
import { relative } from 'node:path';
import * as webhook from './rules/webhook-verification.js';
import * as amount from './rules/amount-tampering.js';
import * as idem from './rules/idempotency.js';
import * as leak from './rules/key-leak.js';
import * as envmix from './rules/sandbox-live.js';
import * as clientSide from './rules/client-side-order.js';

export const RULES = [webhook, amount, idem, leak, envmix, clientSide];

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function scan(root) {
  const files = collectFiles(root);
  const paypalDetected = usesPayPal(files);
  const findings = [];
  for (const file of files) {
    const content = readFile(file);
    if (!content) continue;
    for (const rule of RULES) {
      try {
        const res = rule.check({ path: file, content }) || [];
        for (const f of res) findings.push({ ...f, path: relative(root, f.path) || f.path });
      } catch (e) {
        // a broken rule must never crash the scan
      }
    }
  }
  findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const summary = countBy(findings);
  return { root, filesScanned: files.length, paypalDetected, findings, summary };
}

function countBy(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  for (const f of findings) if (s[f.severity] !== undefined) s[f.severity]++;
  return s;
}
