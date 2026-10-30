// Rule: PayPal webhook handler must verify the transmission signature.
// Either POST /v1/notifications/verify-webhook-signature, or offline RSA-SHA256
// self-verification. A handler that parses the event and acts on it without any
// verification lets anyone forge "payment completed" events.
export const id = 'PP-WEBHOOK-UNVERIFIED';
export const title = 'Webhook handler does not verify the PayPal signature';
export const severity = 'critical';
export const money = 'An attacker posts a forged PAYMENT.CAPTURE.COMPLETED event and gets goods/credit without paying.';

const WEBHOOK_HINT = /(webhook|notifications?)\b|PAYMENT\.CAPTURE|CHECKOUT\.ORDER|BILLING\.SUBSCRIPTION/i;
const VERIFY_HINT = /verify-webhook-signature|verifyWebhookSignature|crc32|paypal-transmission-sig|createVerify\(\s*['"]RSA-SHA256|verifyWebhook/i;
const RAW_BODY_HINT = /express\.raw|bodyParser\.raw|rawBody|request\.text\(\)|await\s+req\.text/i;

export function check({ path, content }) {
  const findings = [];
  if (!WEBHOOK_HINT.test(content)) return findings;
  // Only flag files that look like they receive & act on PayPal events.
  const actsOnEvent = /event(_type|\.event_type|\['event_type'\]|\.resource)|req\.body\.event_type|resource\.(amount|id)/i.test(content);
  if (!actsOnEvent) return findings;

  if (!VERIFY_HINT.test(content)) {
    findings.push({
      id, title, severity, money, path,
      line: lineOf(content, WEBHOOK_HINT),
      detail: 'This handler reads the webhook event and acts on it, but no signature verification (PayPal verify-webhook-signature call or offline RSA-SHA256 check) was found in the file.',
      fixHint: 'Verify every webhook before trusting it: POST the transmission headers + raw body to /v1/notifications/verify-webhook-signature and require verification_status === "SUCCESS", or self-verify with the paypal-cert-url public key over `${transmissionId}|${transmissionTime}|${webhookId}|${crc32(rawBody)}`. Use the RAW request body for crc32.'
    });
  } else if (VERIFY_HINT.test(content) && !RAW_BODY_HINT.test(content) && /JSON\.stringify\(\s*(req\.body|request\.body|event)\s*\)/.test(content)) {
    findings.push({
      id: 'PP-WEBHOOK-RESTRINGIFIED',
      title: 'Webhook verified against re-stringified JSON, not the raw body',
      severity: 'high',
      money: 'Signature check silently fails or is bypassable because crc32 is computed over re-serialized JSON, not the bytes PayPal signed.',
      path,
      line: lineOf(content, /JSON\.stringify/),
      detail: 'crc32 must be computed over the raw request bytes. Re-stringifying the parsed body changes whitespace/key order and breaks verification.',
      fixHint: 'Capture the raw body (express.raw({type:"application/json"}) or request.text()) and use those exact bytes for crc32 and verification.'
    });
  }
  return findings;
}

function lineOf(content, re) {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return 1;
}
