// Intentionally insecure demo shop. DO NOT deploy. This is PayProbe's "patient":
// a vibe-coded PayPal checkout with the mistakes PayProbe is built to catch.
// Each mistake is marked [FLAW]; PayProbe finds them without reading these notes.
import http from 'node:http';

// [FLAW] secret hardcoded in source instead of read from the environment.
const PAYPAL_CLIENT_SECRET = "EJfakeSECRETvalue1234567890abcdefHARDCODED";
// [FLAW] base URL hardcoded, not chosen by an environment switch.
const PAYPAL_API = "https://api-m.sandbox.paypal.com";

const paid = new Set();

const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const rawBody = Buffer.concat(chunks).toString('utf8');
  let body = {};
  try { body = rawBody ? JSON.parse(rawBody) : {}; } catch {}

  if (req.method === 'POST' && req.url === '/create-order') {
    // [FLAW] amount taken straight from the client request.
    const order = {
      intent: 'CAPTURE',
      purchase_units: [{ amount: { currency_code: 'USD', value: body.amount } }],
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ created: true, order }));
  }

  if (req.method === 'POST' && req.url === '/paypal/webhook') {
    // [FLAW] trusts the event with no signature check and no replay protection.
    const event_type = body.event_type;
    if (event_type === 'PAYMENT.CAPTURE.COMPLETED') {
      const orderId = body.resource?.id || 'unknown';
      paid.add(orderId);
      grantAccess(orderId);
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, fulfilled: [...paid] }));
  }

  res.writeHead(404); res.end('not found');
});

function grantAccess(orderId) { /* ship goods / credit the buyer's account */ }

const PORT = process.env.PORT || 4100;
server.listen(PORT, () => console.log(`vulnerable-shop on :${PORT}`));
export default server;
