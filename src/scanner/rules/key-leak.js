// Rule: PayPal client secret / access token must never be hardcoded, committed,
// or exposed to the browser bundle.
export const id = 'PP-SECRET-LEAK';
export const title = 'PayPal secret or access token exposed';
export const severity = 'critical';
export const money = 'A leaked client_secret lets anyone mint OAuth tokens on your PayPal account and move money / read transactions.';

// Hardcoded-secret patterns. We flag the LOCATION; we never print the value.
const PATTERNS = [
  { re: /(client[_-]?secret|clientSecret)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i, what: 'hardcoded PayPal client secret' },
  { re: /access[_-]?token\s*[:=]\s*['"][A-Za-z0-9._\-]{30,}['"]/i, what: 'hardcoded access token' },
  { re: /\b(A21AA|EC-|access_token\$sandbox|access_token\$production)[A-Za-z0-9._\-]{10,}/, what: 'PayPal token literal' },
];

// Secrets handed to the client bundle.
const CLIENT_EXPOSURE = /(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)[A-Z_]*(SECRET|CLIENT_SECRET|ACCESS_TOKEN)/;

export function check({ path, content }) {
  const findings = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const p of PATTERNS) {
      if (p.re.test(lines[i]) && !/process\.env|getenv|os\.environ|import\.meta\.env/i.test(lines[i])) {
        findings.push({
          id, title, severity, money, path, line: i + 1,
          detail: `Line contains a ${p.what}. Secrets must come from the environment, never source.`,
          fixHint: 'Move the value to an environment variable (e.g. PAYPAL_CLIENT_SECRET) loaded server-side, add the file to .gitignore, and rotate the exposed credential in the PayPal dashboard.',
          redacted: true
        });
      }
    }
    if (CLIENT_EXPOSURE.test(lines[i])) {
      findings.push({
        id: 'PP-SECRET-IN-CLIENT',
        title: 'PayPal secret exposed to the browser via a public env var',
        severity: 'critical', money,
        path, line: i + 1,
        detail: 'A NEXT_PUBLIC_/VITE_/REACT_APP_ variable carrying a secret is inlined into the client bundle and visible to every visitor.',
        fixHint: 'Only the client-id is public. Keep the secret server-side in a non-public env var and call PayPal from the server.'
      });
    }
  }
  // committed .env with secrets
  if (/\.env(\.|$)/.test(path) && /(CLIENT_SECRET|ACCESS_TOKEN|SECRET)\s*=\s*\S+/.test(content) && !/\.env\.example/.test(path)) {
    findings.push({
      id: 'PP-ENV-COMMITTED',
      title: 'A .env file with real secret values is present in the repo tree',
      severity: 'high',
      money: 'If committed, the PayPal secret is public forever in git history.',
      path, line: lineOf(content, /SECRET|ACCESS_TOKEN/),
      detail: 'A .env with secret assignments sits in the scanned tree. Ensure it is git-ignored and never committed; commit only .env.example with blank values.',
      fixHint: 'Add .env to .gitignore, remove it from history if committed, ship .env.example instead, and rotate the secret.'
    });
  }
  return findings;
}
function lineOf(content, re){const l=content.split('\n');for(let i=0;i<l.length;i++)if(re.test(l[i]))return i+1;return 1;}
