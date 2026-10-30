#!/usr/bin/env node
import { scan } from './scanner/index.js';
import { triage, explainFinding } from './ai/explain.js';
import { renderTerminal, renderMarkdown, renderJSON } from './report/render.js';
import { aiConfig } from './ai/provider.js';
import { proveWebhookForgery, proveAmountTampering, proveLiveSandbox } from './prover/prove.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flags = new Set(argv.filter(a => a.startsWith('--')));
const positional = argv.slice(1).filter(a => !a.startsWith('--'));
const flagVal = (name) => { const a = argv.find(x => x.startsWith(name + '=')); return a ? a.split('=').slice(1).join('=') : null; };

function help() {
  console.log(`PayProbe — AI auditor for PayPal integrations

Usage:
  payprobe scan <dir> [--md] [--json] [--ai] [--explain] [--out=FILE]
  payprobe prove --webhook=URL        prove webhook forgery against a target
  payprobe prove --amount=URL         prove amount tampering against a target
  payprobe prove --sandbox            create a real sandbox order (needs PAYPAL_* env)
  payprobe ai-status                  show which AI backend is configured

Env:
  PAYPROBE_AI_BASE_URL  OpenAI-compatible endpoint (OpenAI, Groq, llama.cpp, Ollama...)
  PAYPROBE_AI_KEY       API key for hosted endpoints (not needed for local models)
  PAYPROBE_AI_MODEL     model name
  PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET   sandbox app creds (for 'prove --sandbox')
`);
}

async function main() {
  if (!cmd || flags.has('--help') || cmd === 'help') return help();

  if (cmd === 'ai-status') {
    const c = aiConfig();
    console.log(JSON.stringify(c.kind === 'offline' ? { backend: 'offline-analyst', note: 'set PAYPROBE_AI_BASE_URL for a model' } : { backend: c.base, model: c.model, keySet: !!c.key }, null, 2));
    return;
  }

  if (cmd === 'scan') {
    const dir = resolve(positional[0] || '.');
    const result = scan(dir);
    let aiPlan = null;
    const explanations = [];
    if (flags.has('--ai') || flags.has('--explain')) {
      aiPlan = await triage(result);
      if (flags.has('--explain')) {
        for (const f of result.findings) {
          const ex = await explainFinding(f, dir);
          explanations.push({ id: f.id, path: f.path, line: f.line, ...ex });
        }
      }
    }
    let out;
    if (flags.has('--json')) out = renderJSON(result, aiPlan);
    else if (flags.has('--md')) out = renderMarkdown(result, aiPlan, explanations);
    else out = renderTerminal(result, aiPlan);
    const outFile = flagVal('--out');
    if (outFile) { writeFileSync(outFile, out); console.log(`wrote ${outFile}`); }
    else console.log(out);
    process.exitCode = result.summary.critical > 0 ? 2 : 0;
    return;
  }

  if (cmd === 'prove') {
    const results = [];
    if (flagVal('--webhook')) results.push(await proveWebhookForgery(flagVal('--webhook')));
    if (flagVal('--amount')) results.push(await proveAmountTampering(flagVal('--amount')));
    if (flags.has('--sandbox')) results.push(await proveLiveSandbox());
    if (!results.length) { help(); return; }
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  help();
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
