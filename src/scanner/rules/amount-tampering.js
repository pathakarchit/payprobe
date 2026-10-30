// Rule: server must not trust a client-supplied amount when creating/capturing
// a PayPal order. The amount must come from the server's own price source and
// the order should be captured by id, then the captured amount re-checked.
export const id = 'PP-AMOUNT-TAMPERING';
export const title = 'Order amount is taken from the client request';
export const severity = 'critical';
export const money = 'A buyer edits the request to pay $0.01 for a $100 item; the server creates/accepts the order at the attacker-chosen price.';

export function check({ path, content }) {
  const findings = [];
  const lines = content.split('\n');
  // amount value wired directly from req/body/client input into a PayPal order
  const sinkRe = /(amount|value|purchase_units)[\s\S]{0,120}?(req\.body|request\.body|req\.query|req\.params|body\.(amount|price|total|value)|params\.(amount|price))/i;
  const createOrder = /purchase_units|orders?\b.*create|\/v2\/checkout\/orders|actions\.order\.create/i;
  if (!createOrder.test(content)) return findings;
  for (let i = 0; i < lines.length; i++) {
    const window = lines.slice(i, i + 4).join('\n');
    if (/value\s*:\s*(req\.body|request\.body|body\.|req\.query|params\.)/i.test(window) ||
        /amount[^=]*[:=]\s*(req\.body|request\.body|body\.(amount|price|total)|req\.query)/i.test(lines[i])) {
      findings.push({
        id, title, severity, money, path, line: i + 1,
        detail: 'The PayPal order amount is read from the incoming HTTP request instead of a trusted server-side price. Clients can send any value.',
        fixHint: 'Look up the price on the server from the product/cart id, build purchase_units.amount from that, and after capture assert the captured amount equals the expected amount before fulfilling.'
      });
      break;
    }
  }
  // capture without amount re-check
  const capturesById = /\/v2\/checkout\/orders\/[^'"`]*\/capture|orders\.capture|captureOrder/i.test(content);
  const rechecks = /captured?.*amount|amount.*===|expectedAmount|assert.*amount|compare.*amount/i.test(content);
  if (capturesById && !rechecks && findings.length === 0) {
    findings.push({
      id: 'PP-AMOUNT-NO-RECHECK',
      title: 'Captured amount is never re-verified against the expected price',
      severity: 'high', money,
      path, line: lineOf(content, /capture/i),
      detail: 'The order is captured but the captured amount/currency is never compared to the server-side expected total before fulfilling.',
      fixHint: 'After capture, read capture.purchase_units[0].payments.captures[0].amount and require it equals your server-computed total and currency before granting value.'
    });
  }
  return findings;
}
function lineOf(content, re){const l=content.split('\n');for(let i=0;i<l.length;i++)if(re.test(l[i]))return i+1;return 1;}
