# ship-safe-check

**Did your AI coding tool leak your API keys?** Find out in 10 seconds.

```bash
npx ship-safe-check
```

Run it in your project folder. It reads your code locally. Nothing is uploaded and nothing leaves your machine.

## What it finds

| Check | Why it matters |
|---|---|
| API keys hard-coded in source (OpenAI, Anthropic, Stripe, Supabase, AWS, GitHub, Slack, private keys) | Bots scan public sites and repos for these around the clock. The bill goes to you. |
| Secret-looking env vars with a public prefix (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`) | Anything with these prefixes is bundled into the JavaScript every visitor downloads. |
| Server SDKs (`openai`, `stripe`, `@anthropic-ai/sdk`…) or the Supabase `service_role` key in client components | These need secret keys, and `service_role` skips Row Level Security entirely. |
| `.env` files committed to Git, `.env` missing from `.gitignore` | A deleted secret is still in your Git history. |

It exits with code `1` when it finds something critical, so you can use it in CI:

```yaml
# .github/workflows/secrets.yml
name: secrets
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx ship-safe-check
```

Options: `npx ship-safe-check path/to/app`, `--json` for machine-readable output.

## Found something?

1. Move the call that needs the key to a server route, server action or edge function. Only the server holds the key.
2. **Rotate the key** in the provider's dashboard. Once it has been public, assume it has been copied.
3. Set a monthly spend limit at your AI provider.

## What it doesn't check

Leaked secrets are one hole out of many. This tool does **not** check Row Level Security, users reading each other's data (IDOR), unverified Stripe webhooks, missing rate limits, storage buckets or prompt injection.

The full checklist for those is in the [Ship Safe kit](https://ship-safe-kit.pages.dev): 15 holes, a 5-minute test for each, copy-paste fix prompts for Cursor, Claude Code and Lovable, and a deeper local scanner. There's a free 5-hole checklist there too.

## Notes

- A clean result means "no obvious leaked secrets", not "secure".
- Pattern matching can miss keys in unusual formats and can flag test keys. Check each finding.
- Needs Node 18+. No dependencies.

Made by [@stackdrawn](https://x.com/stackdrawn): hand-drawn explainers on how real systems work, and how they break. MIT licensed.
