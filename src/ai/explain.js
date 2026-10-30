// AI layer: (1) triage/prioritize findings into a remediation plan,
// (2) per-finding plain-English explanation + concrete fix patch.
// Falls back to deterministic templates when no model is configured, so output
// is always useful; with a model you get repo-specific explanations and patches.
import { chat } from './provider.js';
import { readFile } from '../scanner/detect.js';
import { join } from 'node:path';

const SYS = `You are PayProbe, a precise application-security reviewer specialized in PayPal integrations.
You explain payment/security bugs to a non-expert founder and write minimal, correct fixes.
Be concrete and short. Never invent findings. Never print real secret values.
Never invent dollar amounts, loss estimates or statistics; describe money risk in words.`;

export async function triage(result) {
  const list = result.findings.map((f, i) =>
    `${i + 1}. [${f.severity.toUpperCase()}] ${f.id} ${f.title} (${f.path}:${f.line}) — ${f.money}`).join('\n');
  const prompt = `A scan of a PayPal integration found these issues:\n\n${list}\n\n` +
    `Write a short prioritized remediation plan (max 6 bullets). Lead with whatever lets an attacker move money or get goods for free. One line each: what to fix and why it matters in money terms. Use only the file:line locations given above. Do not make up dollar figures or loss estimates.`;
  const { text, provider, model, error } = await chat([
    { role: 'system', content: SYS }, { role: 'user', content: prompt }
  ], { maxTokens: 500 });
  if (text) return { plan: text, by: `${model} @ ${provider}` };
  return { plan: offlinePlan(result), by: 'offline-analyst', error };
}

export async function explainFinding(finding, root) {
  const snippet = codeSnippet(root, finding);
  const prompt = `Issue: ${finding.id} — ${finding.title}
File: ${finding.path}:${finding.line}
Why it matters: ${finding.money}
Scanner detail: ${finding.detail}
Fix direction: ${finding.fixHint}

Relevant code:
\`\`\`
${snippet}
\`\`\`

Respond in two parts:
PLAIN: 2-3 sentences explaining the bug to a non-technical founder, in money terms.
FIX: a minimal corrected code block (same language) that resolves it. Do not include real secrets; use env vars.`;
  const { text, provider, model } = await chat([
    { role: 'system', content: SYS }, { role: 'user', content: prompt }
  ], { maxTokens: 650 });
  if (text && !looksDegenerate(text)) return { text, by: `${model} @ ${provider}` };
  const why = text ? 'offline-analyst (model output rejected: repetitive)' : 'offline-analyst';
  return { text: offlineExplain(finding), by: why };
}

// Small local models sometimes loop and repeat the same line until the token
// limit. A patch like that is worse than none, so we reject it and fall back.
export function looksDegenerate(text) {
  const lines = String(text).split('\n').map(l => l.replace(/^\s*\d+:\s*/, '').trim()).filter(l => l.length > 8);
  const seen = new Map();
  for (const l of lines) {
    const n = (seen.get(l) || 0) + 1;
    if (n >= 4) return true;
    seen.set(l, n);
  }
  return false;
}

function codeSnippet(root, f) {
  const content = readFile(join(root, f.path));
  if (!content) return '(source unavailable)';
  const lines = content.split('\n');
  const a = Math.max(0, f.line - 4), b = Math.min(lines.length, f.line + 5);
  return lines.slice(a, b).map((l, i) => `${a + i + 1}: ${l}`).join('\n');
}

function offlinePlan(result) {
  const bySev = {};
  for (const f of result.findings) (bySev[f.severity] ||= []).push(f);
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const out = [];
  for (const sev of order) for (const f of (bySev[sev] || []))
    out.push(`- [${sev.toUpperCase()}] ${f.path}:${f.line} — ${f.title}. ${f.money}`);
  return out.join('\n') || '- No issues found.';
}

function offlineExplain(f) {
  return `PLAIN: ${f.detail} In money terms: ${f.money}\n\nFIX: ${f.fixHint}`;
}
