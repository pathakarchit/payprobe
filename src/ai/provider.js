// Pluggable AI provider. Talks to any OpenAI-compatible chat endpoint.
// Defaults (in order):
//   1. PAYPROBE_AI_BASE_URL (OpenAI-compatible: OpenAI, Groq, Together, Ollama, llama.cpp, LM Studio, vLLM...)
//   2. Offline deterministic analyst (no network) so the tool always runs.
// No key is ever required for a local model; set PAYPROBE_AI_KEY for hosted APIs.

const DEFAULT_TIMEOUT = Number(process.env.PAYPROBE_AI_TIMEOUT_MS || 60000);

export function aiConfig() {
  const base = process.env.PAYPROBE_AI_BASE_URL || '';
  const key = process.env.PAYPROBE_AI_KEY || process.env.OPENAI_API_KEY || '';
  const model = process.env.PAYPROBE_AI_MODEL || (base.includes('11434') ? 'qwen2.5-coder:3b' : 'gpt-4o-mini');
  if (base) return { kind: 'openai', base: base.replace(/\/$/, ''), key, model };
  return { kind: 'offline', base: '', key: '', model: 'offline-analyst' };
}

export async function chat(messages, { temperature = 0.2, maxTokens = 700 } = {}) {
  const cfg = aiConfig();
  if (cfg.kind === 'offline') return { text: null, provider: 'offline', model: cfg.model };
  const url = `${cfg.base}/chat/completions`;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), DEFAULT_TIMEOUT);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(cfg.key ? { authorization: `Bearer ${cfg.key}` } : {}) },
      body: JSON.stringify({ model: cfg.model, messages, temperature, max_tokens: maxTokens, stream: false }),
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`AI endpoint ${res.status}`);
    const data = await res.json();
    const text = data?.choices?.[0]?.message?.content?.trim() || '';
    return { text, provider: cfg.base, model: cfg.model };
  } catch (e) {
    return { text: null, provider: cfg.base || 'unavailable', model: cfg.model, error: String(e.message || e) };
  } finally {
    clearTimeout(t);
  }
}

export async function aiAvailable() {
  const cfg = aiConfig();
  if (cfg.kind === 'offline') return false;
  const r = await chat([{ role: 'user', content: 'reply with: ok' }], { maxTokens: 5 });
  return !!r.text;
}
