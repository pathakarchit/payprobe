// Rule: orders must be created/captured server-side, not with client-side
// actions.order.create/capture, which the buyer fully controls.
export const id = 'PP-CLIENT-SIDE-ORDER';
export const title = 'Order created/captured on the client with actions.order.*';
export const severity = 'high';
export const money = 'The buyer\'s browser controls the order amount and capture, so prices and totals can be rewritten before they reach PayPal.';

export function check({ path, content }) {
  const findings = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/actions\.order\.(create|capture)\s*\(/.test(lines[i])) {
      findings.push({
        id, title, severity, money, path, line: i + 1,
        detail: 'Uses the client-side SDK actions.order.create/capture, so order details originate in the browser and are attacker-controllable.',
        fixHint: 'Use server-side createOrder/captureOrder: the button calls your backend, which builds purchase_units from trusted prices and captures by order id, then verifies the captured amount.'
      });
    }
  }
  return findings;
}
