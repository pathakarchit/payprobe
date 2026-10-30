// Rule: catch sandbox/live PayPal environment confusion.
export const id = 'PP-ENV-MISMATCH';
export const title = 'Sandbox / live PayPal environment confusion';
export const severity = 'high';
export const money = 'Shipping with the sandbox base URL takes no real money; shipping sandbox creds against live (or vice-versa) silently breaks payments or leaks test flows into prod.';

export function check({ path, content }) {
  const findings = [];
  const lines = content.split('\n');
  const envDriven = /process\.env\.(PAYPAL_ENV|PAYPAL_API|NODE_ENV)|import\.meta\.env|config\.paypal|PAYPAL_API_BASE|PAYPAL_BASE_URL/i.test(content);
  for (let i = 0; i < lines.length; i++) {
    if (/https?:\/\/api-m\.(sandbox\.)?paypal\.com/i.test(lines[i]) && !/process\.env|import\.meta\.env|\?/.test(lines[i])) {
      findings.push({
        id, title, severity, money, path, line: i + 1,
        detail: 'The PayPal API base URL is hardcoded. Deploying this file to production will hit the wrong environment unless someone remembers to edit it.',
        fixHint: 'Drive the base URL from an env var: const base = process.env.PAYPAL_ENV === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com".'
      });
      break;
    }
  }
  const hasSandboxUrl = /api-m\.sandbox\.paypal\.com/i.test(content);
  const hasLiveUrl = /api-m\.paypal\.com/i.test(content);
  // Only noise if both appear AND there is no env switch choosing between them.
  if (hasSandboxUrl && hasLiveUrl && !envDriven) {
    findings.push({
      id: 'PP-ENV-MIXED', title: 'Both sandbox and live PayPal URLs appear without an environment switch',
      severity: 'medium', money,
      path, line: lineOf(content, /paypal\.com/i),
      detail: 'Both sandbox and live endpoints are referenced together with no env-driven switch, a common source of using the wrong one.',
      fixHint: 'Keep a single environment switch (e.g. process.env.PAYPAL_ENV) and derive every URL from it.'
    });
  }
  return findings;
}
function lineOf(content, re){const l=content.split('\n');for(let i=0;i<l.length;i++)if(re.test(l[i]))return i+1;return 1;}
