import { test } from 'node:test';
import assert from 'node:assert';
import { looksDegenerate } from '../src/ai/explain.js';

test('rejects AI output that loops on the same line', () => {
  const loop = Array.from({ length: 6 }, (_, i) => `${40 + i}: const event_id_column = 'paypal_event_id';`).join('\n');
  assert.equal(looksDegenerate('FIX:\n' + loop), true);
});

test('keeps a normal AI patch', () => {
  const ok = 'PLAIN: The server trusts the client price.\n\nFIX:\nconst price = PRICES[req.body.sku];\nif (!price) return res.writeHead(400).end();\nconst value = price.toFixed(2);';
  assert.equal(looksDegenerate(ok), false);
});
