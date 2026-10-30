// Detect whether a file touches PayPal, and collect source files to scan.
import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, extname } from 'node:path';

const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.rb', '.go', '.env', '']);
const SKIP_DIR = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', 'vendor', '.venv', '__pycache__']);

const PAYPAL_HINT = /paypal|api-m\.(sandbox\.)?paypal\.com|@paypal\/|braintree|venmo|PAYPAL_|verify-webhook-signature|actions\.order/i;

export function collectFiles(root) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir); } catch { return; }
    for (const name of entries) {
      const p = join(dir, name);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) {
        if (!SKIP_DIR.has(name)) walk(p);
      } else if (st.isFile() && st.size < 2_000_000) {
        const ext = extname(name);
        const isEnv = name.startsWith('.env') || name === '.env';
        if (CODE_EXT.has(ext) || isEnv) out.push(p);
      }
    }
  };
  walk(root);
  return out;
}

export function readFile(path) {
  try { return readFileSync(path, 'utf8'); } catch { return ''; }
}

// Does the repo actually use PayPal? Used to warn if we are scanning the wrong thing.
export function usesPayPal(files) {
  for (const f of files) {
    if (PAYPAL_HINT.test(f) || PAYPAL_HINT.test(readFile(f))) return true;
  }
  return false;
}
