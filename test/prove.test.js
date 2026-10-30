import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { proveWebhookForgery, proveAmountTampering } from '../src/prover/prove.js';

// Port 0 = let the OS pick a free port, so the tests still pass while the
// README demo shops are running on 4100/4200.
let vuln, fixed, V, F;
const ready = s => (s.listening ? Promise.resolve() : new Promise(r => s.once('listening', r)));
before(async () => {
  process.env.PORT = '0';
  vuln = (await import('../examples/vulnerable-shop/server.js')).default;
  fixed = (await import('../examples/fixed-shop/server.js')).default;
  await Promise.all([ready(vuln), ready(fixed)]);
  V = `http://127.0.0.1:${vuln.address().port}`;
  F = `http://127.0.0.1:${fixed.address().port}`;
});
after(() => { vuln?.close(); fixed?.close(); });

test('webhook forgery is fulfilled by the vulnerable shop', async () => {
  const r = await proveWebhookForgery(`${V}/paypal/webhook`);
  assert.strictEqual(r.fulfilled, true);
});

test('webhook forgery is ignored by the fixed shop', async () => {
  const r = await proveWebhookForgery(`${F}/paypal/webhook`);
  assert.strictEqual(r.fulfilled, false);
});

test('amount tampering accepted by vulnerable shop', async () => {
  const r = await proveAmountTampering(`${V}/create-order`);
  assert.strictEqual(r.acceptedValue, '0.01');
});

test('amount tampering rejected by fixed shop (server price used)', async () => {
  const r = await proveAmountTampering(`${F}/create-order`);
  assert.notStrictEqual(r.acceptedValue, '0.01');
});
