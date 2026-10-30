// Correct, dependency-free PayPal webhook signature verification (offline self-verify).
// PayProbe uses this both as the reference "right way" and to prove that a target's
// handler accepts forged events. Algorithm per PayPal docs:
//   message = `${transmissionId}|${transmissionTime}|${webhookId}|${crc32(rawBody)}`
//   verify RSA-SHA256(message, signature) with the public key at paypal-cert-url.
import crypto from 'node:crypto';

// CRC-32 (IEEE) as unsigned decimal over the RAW body bytes.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const certCache = new Map();
async function fetchCert(certUrl) {
  const u = new URL(certUrl);
  if (!(u.hostname === 'paypal.com' || u.hostname.endsWith('.paypal.com'))) {
    throw new Error(`Refusing cert from non-PayPal host: ${u.hostname}`);
  }
  if (certCache.has(certUrl)) return certCache.get(certUrl);
  const res = await fetch(certUrl);
  if (!res.ok) throw new Error(`cert fetch failed ${res.status}`);
  const pem = await res.text();
  certCache.set(certUrl, pem);
  return pem;
}

// headers: object with paypal-transmission-id/-time/-sig/-cert-url
export async function verifyWebhookOffline({ headers, rawBody, webhookId }) {
  const id = headers['paypal-transmission-id'];
  const time = headers['paypal-transmission-time'];
  const sig = headers['paypal-transmission-sig'];
  const certUrl = headers['paypal-cert-url'];
  if (!id || !time || !sig || !certUrl || !webhookId) return { valid: false, reason: 'missing headers or webhookId' };
  const raw = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  const message = `${id}|${time}|${webhookId}|${crc32(raw)}`;
  let pem;
  try { pem = await fetchCert(certUrl); } catch (e) { return { valid: false, reason: e.message }; }
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(message); verifier.end();
  let valid = false;
  try { valid = verifier.verify(pem, Buffer.from(sig, 'base64')); } catch (e) { return { valid: false, reason: e.message }; }
  return { valid, message };
}

// Postback verification via PayPal API (needs an OAuth token).
export async function verifyWebhookPostback({ base, token, headers, event, webhookId }) {
  const res = await fetch(`${base}/v1/notifications/verify-webhook-signature`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      transmission_id: headers['paypal-transmission-id'],
      transmission_time: headers['paypal-transmission-time'],
      cert_url: headers['paypal-cert-url'],
      auth_algo: headers['paypal-auth-algo'],
      transmission_sig: headers['paypal-transmission-sig'],
      webhook_id: webhookId,
      webhook_event: event,
    }),
  });
  const data = await res.json();
  return { valid: data.verification_status === 'SUCCESS', raw: data };
}
