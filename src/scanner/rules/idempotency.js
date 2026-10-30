// Rule: webhook/capture processing must be idempotent (dedupe by event id or
// use PayPal-Request-Id) so retries and replays don't double-fulfill.
export const id = 'PP-IDEMPOTENCY';
export const title = 'No idempotency / replay protection on PayPal events';
export const severity = 'high';
export const money = 'PayPal retries a webhook (or an attacker replays one) and the same paid order is fulfilled twice.';

export function check({ path, content }) {
  const findings = [];
  const isWebhook = /(webhook|PAYMENT\.CAPTURE|event_type|notifications)/i.test(content);
  const isCapture = /capture|createOrder|orders.*create|\/v2\/checkout\/orders/i.test(content);
  if (!isWebhook && !isCapture) return findings;
  const hasIdempotency = /idempotenc|PayPal-Request-Id|request[_-]?id|already.?(processed|handled)|seen.*event|dedup|UNIQUE.*event_id|event_id.*exists|processedEvents/i.test(content);
  const fulfills = /(fulfil|grant|credit|unlock|ship|markPaid|setPaid|deliver|activate)/i.test(content);
  if (isWebhook && fulfills && !hasIdempotency) {
    findings.push({
      id, title, severity, money, path, line: lineOf(content, /event_type|webhook/i),
      detail: 'The handler fulfills value on a PayPal event but has no dedupe by event id. PayPal delivers at-least-once and will retry.',
      fixHint: 'Store each processed webhook event id (resource.id / event id) in a unique column and no-op if already seen. For capture calls, send a stable PayPal-Request-Id header.'
    });
  }
  return findings;
}
function lineOf(content, re){const l=content.split('\n');for(let i=0;i<l.length;i++)if(re.test(l[i]))return i+1;return 1;}
