#!/usr/bin/env node
// ship-safe-check · free leaked-secret check for AI-built apps (@stackdrawn)
// Reads your code locally. Nothing is uploaded, nothing is sent anywhere.
//   npx ship-safe-check [dir] [--json]
// Exit code 1 when a critical finding is found, so it can gate CI.
// A clean result means "no obvious leaked secrets", not "secure".

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const VERSION = "1.0.0";
const KIT = "https://ship-safe-kit.pages.dev";
const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  console.log(`ship-safe-check ${VERSION}
  npx ship-safe-check [dir] [--json]

Finds secrets that leaked into browser code or Git:
  · API keys hard-coded in source (OpenAI, Anthropic, Stripe, Supabase, AWS, GitHub, Slack, private keys)
  · secret-looking env vars with a public prefix (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_, PUBLIC_)
  · server SDKs or the Supabase service_role key used in client components
  · .env files committed to Git, and .env missing from .gitignore`);
  process.exit(0);
}
const JSON_OUT = argv.includes("--json");
const ROOT = path.resolve(argv.find((a) => !a.startsWith("--")) || ".");

// ------------------------------------------------------------------ files
const SKIP = new Set(["node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".vercel", ".turbo", ".svelte-kit", ".expo", ".output", ".cache", "vendor"]);
const EXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro)$/i;
const files = [];
(function walk(dir, depth = 0) {
  if (depth > 12) return;
  let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP.has(e.name) || e.name.startsWith(".") && e.isDirectory()) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, depth + 1);
    else if ((EXT.test(e.name) || /^\.env/.test(e.name)) && fs.statSync(p).size < 1_500_000) files.push(p);
  }
})(ROOT);
const rel = (p) => path.relative(ROOT, p).split(path.sep).join("/");
const read = (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return ""; } };
const lineOf = (t, idx) => t.slice(0, idx).split("\n").length;
const snip = (t, idx) => t.split("\n")[lineOf(t, idx) - 1]?.trim().slice(0, 140) || "";
const mask = (k) => k.length > 12 ? k.slice(0, 7) + "…" + k.slice(-3) : "…";
const pkg = (() => { try { return JSON.parse(read(path.join(ROOT, "package.json"))); } catch { return null; } })();
const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
const isVite = !!deps.vite && !deps.next;
const code = files.filter((f) => EXT.test(f)).map((f) => ({ r: rel(f), t: read(f) }));
const isClient = (s) => /^\s*(['"])use client\1/m.test(s.t.slice(0, 400)) ||
  (isVite && /^(src|app)\//.test(s.r) && !/(server|api|functions|backend)\//.test(s.r));

const findings = [];
const add = (severity, title, fix, where = "", snippet = "") => findings.push({ severity, title, fix, where, snippet });

// ------------------------------------------------------------------ hard-coded keys
const SECRET_RX = [
  [/sk-(?:proj-)?[A-Za-z0-9_-]{32,}/g, "OpenAI-style secret key"], [/sk-ant-[A-Za-z0-9_-]{20,}/g, "Anthropic API key"],
  [/sk_live_[0-9A-Za-z]{16,}/g, "Stripe live secret key"], [/rk_live_[0-9A-Za-z]{16,}/g, "Stripe restricted key"],
  [/sb_secret_[A-Za-z0-9_-]{16,}/g, "Supabase secret key"], [/AKIA[0-9A-Z]{16}/g, "AWS access key"],
  [/gh[pousr]_[A-Za-z0-9]{36}/g, "GitHub token"], [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "Slack token"],
  [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, "Private key"],
];
for (const s of code) for (const [rx, name] of SECRET_RX) for (const m of s.t.matchAll(rx))
  add("critical", `${name} hard-coded in ${isClient(s) ? "browser" : "source"} code`,
    isClient(s) ? "Every visitor can read this key. Move the call to a server route, keep the key in a server-only env var and rotate it."
      : "Keys in source end up in Git history and every clone. Move it to an env var and rotate it.", `${s.r}:${lineOf(s.t, m.index)}`, mask(m[0]));

// ------------------------------------------------------------------ public-prefixed secrets
const PUB = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_)([A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|OPENAI|ANTHROPIC|GROQ|GEMINI|MISTRAL|REPLICATE|RESEND|TWILIO|SENDGRID|DATABASE_URL|STRIPE_SECRET|WEBHOOK)[A-Z0-9_]*)/g;
const seen = new Set();
for (const f of files) {
  const t = read(f), r = rel(f);
  for (const m of t.matchAll(PUB)) {
    const k = m[0]; if (seen.has(k) || /PUBLISHABLE|PUBLIC_KEY$/.test(k) && !/SECRET/.test(k)) continue; seen.add(k);
    add("critical", `Secret-looking variable is public: ${k}`, `Anything prefixed ${m[1]} is bundled into browser code. Rename it without the prefix, use it only on the server and rotate the key.`, `${r}:${lineOf(t, m.index)}`);
  }
}

// ------------------------------------------------------------------ server-only things in client code
for (const s of code.filter(isClient)) {
  const m = s.t.match(/from\s+['"](openai|@anthropic-ai\/sdk|stripe|@google\/generative-ai|groq-sdk|resend|twilio|@aws-sdk\/[^'"]+)['"]/);
  if (m) add("critical", `Server SDK "${m[1]}" imported in browser code`, "Provider SDKs need secret keys. Call them from a route handler or server action instead.", `${s.r}:${lineOf(s.t, m.index)}`, snip(s.t, m.index));
  const sr = s.t.search(/SERVICE_ROLE|service_role|sb_secret/);
  if (sr >= 0) add("critical", "Supabase service-role / secret key referenced in browser code", "That key skips Row Level Security. It must only exist in trusted server code.", `${s.r}:${lineOf(s.t, sr)}`, snip(s.t, sr));
}

// ------------------------------------------------------------------ git
let tracked = [];
try { tracked = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); } catch { /* not a git repo */ }
for (const t of tracked) if (/(^|\/)\.env(\.|$)/.test(t) && !/\.(example|sample|template|defaults)$/.test(t))
  add("critical", `Env file committed to Git: ${t}`, "Its values stay in your history. Untrack it (git rm --cached), add it to .gitignore and rotate every secret inside.", t);
if (tracked.length && !/^\s*\.env/m.test(read(path.join(ROOT, ".gitignore"))))
  add("medium", ".env files are not in .gitignore", "Add `.env` and `.env.*` (keep !.env.example) so secrets can't be committed by accident.", ".gitignore");
for (const f of files.filter((f) => /\.env\.(example|sample|template)$/.test(f))) {
  const t = read(f);
  for (const [rx, name] of SECRET_RX) for (const m of t.matchAll(rx)) add("critical", `Real-looking ${name} in ${path.basename(f)}`, "Example env files should hold placeholders only. Replace it and rotate the key.", rel(f), mask(m[0]));
}

// ------------------------------------------------------------------ report
const crit = findings.filter((f) => f.severity === "critical").length;
if (JSON_OUT) { console.log(JSON.stringify({ version: VERSION, root: ROOT, files: files.length, findings }, null, 2)); process.exit(crit ? 1 : 0); }
const tty = process.stdout.isTTY, c = (n, s) => tty ? `\x1b[${n}m${s}\x1b[0m` : s;
console.log(`\n${c(1, "ship-safe-check")} ${VERSION} · ${files.length} files in ${ROOT}\n`);
if (!findings.length) console.log(c(32, "✓ No leaked secrets found.") + c(2, " (That's one class of hole, not a guarantee your app is secure.)") + "\n");
for (const f of findings) {
  console.log(`${f.severity === "critical" ? c(31, "✗ CRITICAL") : c(33, "! MEDIUM")} ${c(1, f.title)}`);
  if (f.where) console.log(`  ${c(2, f.where)}${f.snippet ? c(2, "  " + f.snippet) : ""}`);
  console.log(`  → ${f.fix}\n`);
}
console.log(c(2, `This free check covers leaked secrets only. Missing RLS, IDOR, unverified webhooks and 11 more holes are in the Ship Safe kit: ${KIT}\n`));
process.exit(crit ? 1 : 0);
