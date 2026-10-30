import { relative, isAbsolute } from 'node:path';
const C = { reset: '\x1b[0m', red: '\x1b[31m', yellow: '\x1b[33m', mag: '\x1b[35m', cyan: '\x1b[36m', gray: '\x1b[90m', bold: '\x1b[1m', green: '\x1b[32m' };
const sevColor = { critical: C.red, high: C.mag, medium: C.yellow, low: C.cyan, info: C.gray };
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const col = (c, s) => (useColor ? c + s + C.reset : s);
// Show the scanned folder relative to where you ran PayProbe, so reports you share
// don't carry your machine's absolute paths. Folders outside the cwd stay absolute.
const shownRoot = (root) => { const r = relative(process.cwd(), root); return r === '' ? '.' : (r.startsWith('..') || isAbsolute(r) ? root : r); };

export function renderTerminal(result, aiPlan) {
  const L = [];
  L.push(col(C.bold, `\nPayProbe — PayPal integration audit`));
  L.push(col(C.gray, `scanned ${result.filesScanned} files in ${shownRoot(result.root)}`));
  L.push(col(C.gray, `PayPal integration detected: ${result.paypalDetected ? 'yes' : 'no (is this the right directory?)'}`));
  const s = result.summary;
  L.push(`\n${col(C.red, s.critical + ' critical')}  ${col(C.mag, s.high + ' high')}  ${col(C.yellow, s.medium + ' medium')}  ${col(C.cyan, s.low + ' low')}  (${s.total} total)\n`);
  for (const f of result.findings) {
    L.push(`${col(sevColor[f.severity] || '', '●')} ${col(C.bold, f.id)}  ${f.title}`);
    L.push(`   ${col(C.gray, f.path + ':' + f.line)}`);
    L.push(`   ${f.detail}`);
    L.push(`   ${col(C.gray, '💸 ' + f.money)}`);
    L.push(`   ${col(C.green, '→ fix: ')}${f.fixHint}\n`);
  }
  if (!result.findings.length) L.push(col(C.green, '✓ No PayPal integration issues found.\n'));
  if (aiPlan) { L.push(col(C.bold, 'AI remediation plan ') + col(C.gray, '(' + aiPlan.by + ')')); L.push(aiPlan.plan + '\n'); }
  return L.join('\n');
}

export function renderMarkdown(result, aiPlan, explanations = []) {
  const s = result.summary;
  const L = [];
  L.push(`# PayProbe report\n`);
  L.push(`**Target:** \`${shownRoot(result.root)}\`  •  **Files scanned:** ${result.filesScanned}  •  **PayPal detected:** ${result.paypalDetected ? 'yes' : 'no'}\n`);
  L.push(`| Severity | Count |`);
  L.push(`|---|---|`);
  L.push(`| Critical | ${s.critical} |`);
  L.push(`| High | ${s.high} |`);
  L.push(`| Medium | ${s.medium} |`);
  L.push(`| Low | ${s.low} |`);
  L.push(`| **Total** | **${s.total}** |\n`);
  if (aiPlan) { L.push(`## AI remediation plan\n_${aiPlan.by}_\n\n${aiPlan.plan}\n`); }
  L.push(`## Findings\n`);
  for (const f of result.findings) {
    L.push(`### ${f.id} — ${f.title}`);
    L.push(`- **Severity:** ${f.severity}`);
    L.push(`- **Location:** \`${f.path}:${f.line}\``);
    L.push(`- **What it is:** ${f.detail}`);
    L.push(`- **Why it matters (money):** ${f.money}`);
    L.push(`- **Fix:** ${f.fixHint}`);
    const ex = explanations.find(e => e.id === f.id && e.path === f.path && e.line === f.line);
    if (ex) L.push(`\n<details><summary>AI explanation & suggested fix (${ex.by}; review before applying)</summary>\n\n${ex.text}\n\n</details>`);
    L.push('');
  }
  if (!result.findings.length) L.push(`_No issues found._`);
  return L.join('\n');
}

export function renderJSON(result, aiPlan) {
  return JSON.stringify({ ...result, aiPlan: aiPlan || null }, null, 2);
}
