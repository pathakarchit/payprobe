// Minimal, dependency-free PayPal REST client for the SANDBOX.
// Used by the live "prove" mode to create and inspect real sandbox orders.
// Credentials come from env only (PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET).
const BASE = process.env.PAYPAL_ENV === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

let cachedToken = null;
let cachedAt = 0;

export function haveCreds() {
  return !!(process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_CLIENT_SECRET);
}

export async function getAccessToken() {
  if (!haveCreds()) throw new Error('Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (sandbox) in the environment.');
  if (cachedToken && Date.now() - cachedAt < 8 * 60 * 1000) return cachedToken;
  const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
  const res = await fetch(`${BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: { authorization: `Basic ${auth}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  });
  if (!res.ok) throw new Error(`OAuth failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  cachedToken = data.access_token; cachedAt = Date.now();
  return cachedToken;
}

export async function createOrder({ value = '100.00', currency = 'USD' } = {}) {
  const token = await getAccessToken();
  const res = await fetch(`${BASE}/v2/checkout/orders`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'PayPal-Request-Id': crypto.randomUUID() },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [{ amount: { currency_code: currency, value } }],
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`createOrder failed: ${res.status} ${JSON.stringify(data)}`);
  return data; // { id, status, ... }
}

export async function getOrder(id) {
  const token = await getAccessToken();
  const res = await fetch(`${BASE}/v2/checkout/orders/${id}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`getOrder failed: ${res.status} ${JSON.stringify(data)}`);
  return data;
}

export { BASE };
