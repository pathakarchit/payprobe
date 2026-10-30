# PayProbe report

**Target:** `examples/vulnerable-shop`  •  **Files scanned:** 1  •  **PayPal detected:** yes

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 2 |
| Medium | 0 |
| Low | 0 |
| **Total** | **5** |

## AI remediation plan
_qwen2.5-1.5b @ http://127.0.0.1:8081/v1_

1. **Fix server.js:7** - Expose PayPal secret or access token. **Why it matters**: Any attacker can mint OAuth tokens on your PayPal account and move money, potentially stealing funds from customers or triggering unauthorized transactions.

2. **Fix server.js:30** - Verify PayPal signature in the webhook handler. **Why it matters**: An attacker can post a forged PAYMENT.CAPTURE.COMPLETED event, allowing them to get goods or credit without paying, leading to significant financial loss for the customer.

3. **Fix server.js:21** - Ensure order amount is not taken from the client request. **Why it matters**: A buyer can edit the request to pay a lower amount, leading to a potential loss for the customer if the order is processed at the attacker-chosen price.

4. **Fix server.js:30** - Implement idempotency and replay protection on PayPal events. **Why it matters**: PayPal retries a webhook, leading to the same paid order being fulfilled twice, potentially causing double payment or double chargebacks.

5. **Fix server.js:9** - Ensure PayPal environment is correctly configured. **Why it matters**: Shipping with the sandbox base URL takes no real money, while shipping sandbox credentials against live or vice versa can silently break payments or leak test flows into production, leading to significant financial loss.

## Findings

### PP-WEBHOOK-UNVERIFIED — Webhook handler does not verify the PayPal signature
- **Severity:** critical
- **Location:** `server.js:30`
- **What it is:** This handler reads the webhook event and acts on it, but no signature verification (PayPal verify-webhook-signature call or offline RSA-SHA256 check) was found in the file.
- **Why it matters (money):** An attacker posts a forged PAYMENT.CAPTURE.COMPLETED event and gets goods/credit without paying.
- **Fix:** Verify every webhook before trusting it: POST the transmission headers + raw body to /v1/notifications/verify-webhook-signature and require verification_status === "SUCCESS", or self-verify with the paypal-cert-url public key over `${transmissionId}|${transmissionTime}|${webhookId}|${crc32(rawBody)}`. Use the RAW request body for crc32.

<details><summary>AI explanation & suggested fix (qwen2.5-1.5b @ http://127.0.0.1:8081/v1; review before applying)</summary>

PLAIN: The bug in the code means that an attacker could send fake events to the PayPal webhook, like a "PAYMENT.CAPTURE.COMPLETED" event, and get goods or credit without paying. This is because the code trusts the event without verifying the PayPal signature.

FIX:
```javascript
29: 
30:   if (req.method === 'POST' && req.url === '/paypal/webhook') {
31:     // Verify the PayPal signature before trusting the event
32:     const event_type = body.event_type;
33:     if (event_type === 'PAYMENT.CAPTURE.COMPLETED') {
34:       const orderId = body.resource?.id || 'unknown';
35:       paid.add(orderId);
36:       const signature = body.signature;
37:       const signatureVerification = await verifySignature(signature, paypalCertUrl);
38:       if (!signatureVerification.success) {
39:         return res.end(JSON.stringify({ error: 'Invalid signature' }));
40:       }
41:       paid.add(orderId);
42:     }
43:   }
44: }
```

</details>

### PP-AMOUNT-TAMPERING — Order amount is taken from the client request
- **Severity:** critical
- **Location:** `server.js:21`
- **What it is:** The PayPal order amount is read from the incoming HTTP request instead of a trusted server-side price. Clients can send any value.
- **Why it matters (money):** A buyer edits the request to pay $0.01 for a $100 item; the server creates/accepts the order at the attacker-chosen price.
- **Fix:** Look up the price on the server from the product/cart id, build purchase_units.amount from that, and after capture assert the captured amount equals the expected amount before fulfilling.

<details><summary>AI explanation & suggested fix (qwen2.5-1.5b @ http://127.0.0.1:8081/v1; review before applying)</summary>

PLAIN: The bug allows buyers to edit the request to pay a very small amount, like $0.01, for a $100 item. This means the server accepts orders at the attacker-chosen price, not the expected one.

FIX:
```
21:     const order = {
22:       intent: 'CAPTURE',
23:       purchase_units: [
24:         { amount: { currency_code: 'USD', value: body.amount } },
25:         { amount: { currency_code: 'USD', value: '100.00' } } // Corrected to use the product cart id
26:       ],
27:     };
28:     res.writeHead(200, { 'content-type': 'application/json' });
```

</details>

### PP-SECRET-LEAK — PayPal secret or access token exposed
- **Severity:** critical
- **Location:** `server.js:7`
- **What it is:** Line contains a hardcoded PayPal client secret. Secrets must come from the environment, never source.
- **Why it matters (money):** A leaked client_secret lets anyone mint OAuth tokens on your PayPal account and move money / read transactions.
- **Fix:** Move the value to an environment variable (e.g. PAYPAL_CLIENT_SECRET) loaded server-side, add the file to .gitignore, and rotate the exposed credential in the PayPal dashboard.

<details><summary>AI explanation & suggested fix (qwen2.5-1.5b @ http://127.0.0.1:8081/v1; review before applying)</summary>

PLAIN: The PayPal secret is a key that lets anyone use your PayPal account. If this secret is exposed, anyone can move money or read your transactions.

FIX:
```javascript
import http from 'node:http';

// [FIX] Move the secret to an environment variable.
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

// [FIX] Change the base URL to a chosen environment variable.
const PAYPAL_API = process.env.PAYPAL_API;

const paid = new Set();
```

</details>

### PP-IDEMPOTENCY — No idempotency / replay protection on PayPal events
- **Severity:** high
- **Location:** `server.js:30`
- **What it is:** The handler fulfills value on a PayPal event but has no dedupe by event id. PayPal delivers at-least-once and will retry.
- **Why it matters (money):** PayPal retries a webhook (or an attacker replays one) and the same paid order is fulfilled twice.
- **Fix:** Store each processed webhook event id (resource.id / event id) in a unique column and no-op if already seen. For capture calls, send a stable PayPal-Request-Id header.

<details><summary>AI explanation & suggested fix (qwen2.5-1.5b @ http://127.0.0.1:8081/v1; review before applying)</summary>

PLAIN: The bug in our code means that PayPal might deliver the same payment event multiple times, causing the same order to be fulfilled twice. This could lead to double payments and loss of funds.

FIX:
```javascript
30:   if (req.method === 'POST' && req.url === '/paypal/webhook') {
31:     // [FLAW] trusts the event with no signature check and no replay protection.
32:     const event_type = body.event_type;
33:     if (event_type === 'PAYMENT.CAPTURE.COMPLETED') {
34:       const orderId = body.resource?.id || 'unknown';
35:       const event_id = body.event_id || 'unknown';
36:       if (paid.has(orderId)) {
37:         // No-op: This order has already been processed.
38:       } else {
39:         paid.add(orderId);
40:         // Handle the order as usual.
41:       }
42:     }
43:   }
```

</details>

### PP-ENV-MISMATCH — Sandbox / live PayPal environment confusion
- **Severity:** high
- **Location:** `server.js:9`
- **What it is:** The PayPal API base URL is hardcoded. Deploying this file to production will hit the wrong environment unless someone remembers to edit it.
- **Why it matters (money):** Shipping with the sandbox base URL takes no real money; shipping sandbox creds against live (or vice-versa) silently breaks payments or leaks test flows into prod.
- **Fix:** Drive the base URL from an env var: const base = process.env.PAYPAL_ENV === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com".

<details><summary>AI explanation & suggested fix (qwen2.5-1.5b @ http://127.0.0.1:8081/v1; review before applying)</summary>

PLAIN: The bug occurs when the PayPal API base URL is hardcoded in the server code. If this URL is deployed to production without being updated to match the live environment, it could lead to payments being sent to the wrong PayPal account or exposing test payment flows to live users. This is a critical security issue that should be fixed by using an environment variable to dynamically set the base URL.

FIX:
```javascript
const base = process.env.PAYPAL_ENV === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
const PAYPAL_API = base;
```

</details>
