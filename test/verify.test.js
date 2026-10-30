import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { crc32, verifyWebhookOffline } from '../src/paypal/verify-webhook.js';

test('crc32 matches known vector', () => {
  // CRC-32 of "123456789" is 0xCBF43926
  assert.strictEqual(crc32(Buffer.from('123456789')), 0xCBF43926);
});

test('offline verify rejects missing headers', async () => {
  const r = await verifyWebhookOffline({ headers: {}, rawBody: '{}', webhookId: 'WH' });
  assert.strictEqual(r.valid, false);
});

test('offline verify rejects non-paypal cert host', async () => {
  const r = await verifyWebhookOffline({
    headers: {
      'paypal-transmission-id': 'x', 'paypal-transmission-time': 't',
      'paypal-transmission-sig': Buffer.from('sig').toString('base64'),
      'paypal-cert-url': 'https://evil.example.com/cert.pem',
    }, rawBody: '{}', webhookId: 'WH',
  });
  assert.strictEqual(r.valid, false);
  assert.match(r.reason, /non-PayPal/i);
});
