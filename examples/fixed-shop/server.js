// FIXED demo shop: the same endpoints done safely. This is the "after" PayProbe
// guides you to. Amount from trusted catalog, webhook signature verified,
// idempotent, secret from env, env-driven base URL.
import http from 'node:http';
import { verifyWebhookOffline } from '../../src/paypal/verify-webhook.js';

const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;           // from env
const PAYPAL_API = process.env.PAYPAL_ENV === 'live'                      // env-driven
  ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || '';

// Trusted server-side catalog. Amount NEVER comes from the client.
const CATALOG = { 'sku-pro': { value: '100.00', currency: 'USD' } };
const processedEvents = new Set();
const paid = new Set();

const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);
  let body = {};
  try { body = raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch {}

  if (req.method === 'POST' && req.url === '/create-order') {
    const item = CATALOG[body.sku];
    if (!item) { res.writeHead(400); return res.end(JSON.stringify({ error: 'unknown sku' })); }
    const order = { intent: 'CAPTURE', purchase_units: [{ amount: { currency_code: item.currency, value: item.value } }] };
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ created: true, order }));
  }

  if (req.method === 'POST' && req.url === '/paypal/webhook') {
    const headers = lower(req.headers);
    const { valid } = await verifyWebhookOffline({ headers, rawBody: raw, webhookId: WEBHOOK_ID });
    if (!valid) { res.writeHead(200); return res.end(JSON.stringify({ ok: true, ignored: 'unverified' })); }
    const eventId = body.id;
    if (processedEvents.has(eventId)) { res.writeHead(200); return res.end(JSON.stringify({ ok: true, duplicate: true })); }
    processedEvents.add(eventId);
    if (body.event_type === 'PAYMENT.CAPTURE.COMPLETED') paid.add(body.resource?.id);
    res.writeHead(200); return res.end(JSON.stringify({ ok: true, fulfilled: [...paid] }));
  }

  res.writeHead(404); res.end('not found');
});

function lower(h) { const o = {}; for (const k in h) o[k.toLowerCase()] = h[k]; return o; }
const PORT = process.env.PORT || 4200;
server.listen(PORT, () => console.log(`fixed-shop on :${PORT}`));
export default server;
