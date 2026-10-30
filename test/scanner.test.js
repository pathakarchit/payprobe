import { test } from 'node:test';
import assert from 'node:assert';
import { scan } from '../src/scanner/index.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

test('detects unverified webhook', () => {
  const r = scan(root);
  assert.ok(r.findings.some(f => f.id === 'PP-WEBHOOK-UNVERIFIED'), 'should flag unverified webhook');
});

test('detects idempotency gap', () => {
  const r = scan(root);
  assert.ok(r.findings.some(f => f.id === 'PP-IDEMPOTENCY'));
});

test('detects amount tampering', () => {
  const r = scan(root);
  assert.ok(r.findings.some(f => f.id === 'PP-AMOUNT-TAMPERING'));
});

test('detects hardcoded secret without printing it', () => {
  const r = scan(root);
  const leak = r.findings.find(f => f.id === 'PP-SECRET-LEAK');
  assert.ok(leak, 'should flag hardcoded secret');
  assert.ok(!JSON.stringify(leak).includes('EOsecretTOKENvalue'), 'must not echo the secret value');
});

test('detects secret exposed to client bundle', () => {
  const r = scan(root);
  assert.ok(r.findings.some(f => f.id === 'PP-SECRET-IN-CLIENT'));
});

test('clean file produces no critical from clean.js', () => {
  const r = scan(root);
  const fromClean = r.findings.filter(f => f.path.endsWith('clean.js'));
  assert.strictEqual(fromClean.length, 0, 'clean.js should be clean');
});

test('findings are severity-sorted (critical first)', () => {
  const r = scan(root);
  const order = { critical:0, high:1, medium:2, low:3, info:4 };
  for (let i=1;i<r.findings.length;i++) assert.ok(order[r.findings[i-1].severity] <= order[r.findings[i].severity]);
});
