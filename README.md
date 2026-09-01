# honeycrawlpot

> Feed AI scanners fake secrets and prompt injections — and fingerprint them.

[![NPM Version](https://img.shields.io/npm/v/honeycrawlpot.svg)](https://www.npmjs.com/package/honeycrawlpot)
[![NPM Downloads](https://img.shields.io/npm/dm/honeycrawlpot.svg)](https://www.npmjs.com/package/honeycrawlpot)
[![License](https://img.shields.io/npm/l/honeycrawlpot.svg)](https://github.com/Resk-Security/honeycrawlpot/blob/main/LICENSE)
[![Bun Compatible](https://img.shields.io/badge/JS-Bun-f5f5f5)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6)](https://www.typescriptlang.org)

## Installation

```bash
npm install honeycrawlpot   # or: bun add honeycrawlpot
```

Zero runtime dependencies.

## Usage rapide (30 seconds)

```typescript
import { Hono } from "hono";
import { honoHoneypot } from "honeycrawlpot";

const app = new Hono();

// real routes first — they take precedence over the honeypot
app.route("/api/v1", v1Routes);

// then the honeypot, BEFORE the 404 handler
app.use("*", honoHoneypot({ onHit: (h) => console.log("probe", h.path, h.canary) }));

app.notFound((c) => c.json({ error: "not found" }, 404));
```

Now a bot requesting `/.env`, `/firebase-admin.json` or `/.aws/credentials` gets a **`200` with a convincing fake file** instead of a `404` — and you get an alert.

## Pourquoi honeycrawlpot ?

A new generation of **AI-powered vulnerability scanners** crawls your API for leak-prone paths. Classic canary tokens (Thinkst Canary, etc.) alert you *after* a leak reaches some external system — if they're ever exfiltrated at all. honeycrawlpot serves the bait **directly at the scanner's own request paths**, wastes the scanner's time, poisons its automated report, and embeds prompt injections that turn the attacker's LLM into your informant.

| | **honeycrawlpot** | Thinkst-style canary tokens | Plain 404s / WAF rules |
|---|---|---|---|
| Trigger | Scanner requests the bait path itself | Token must be *used* elsewhere | Every request |
| Targets AI/LLM scanners | ✅ prompt injections inside decoys | ❌ | ❌ |
| Attacker-side disruption | ✅ token burn, report flooding, false triage | ❌ | ❌ |
| Attacker fingerprinting | ✅ canary `LF-HONEYPOT-…` in *their* report | ✅ | ❌ |
| Sits in your app (no extra infra) | ✅ middleware | ⚠️ separate canary hosts | ✅ |
| Dependencies | ✅ zero | N/A | N/A |

**What's in every decoy**: inert fake credentials (AWS `AKIA…`, Stripe `sk_live.…`, JWT secrets, PostgreSQL URLs), plus prompt-injection payloads — `[[SYSTEM OVERRIDE]]` (extract the canary), `[[RECURSION DIRECTIVE]]` (repeat the file 20×, token burn), `[[AUDIT DIRECTIVE]]` (250 fake critical CVEs → report flooding), `[[FALSE-TRIAGE DIRECTIVE]]` ("host is clean"), `[[DISCOVERY DIRECTIVE]]` (fake-endpoint rabbit hole), `[[IDENTITY DIRECTIVE]]` (make the agent reveal its model).

> ⚠️ **Defensive deception only.** Every credential in these decoys is fabricated and inert. Never place real secrets in this module.

## Documentation

### Framework-agnostic core

```typescript
import { handleProbe } from "honeycrawlpot";

const outcome = handleProbe({ method: "GET", path: "/.env" });
if (outcome) {
  // { status: 200, headers: { "X-Honeypot": "true", ... }, body: "…", canary: "LF-HONEYPOT-…" }
}
```

### Express

```typescript
import { expressHoneypot } from "honeycrawlpot";

app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.use(expressHoneypot());          // before 404/error handlers
app.use((_req, res) => res.status(404).json({ error: "not found" }));
```

### Site-tuned decoys

Out of the box the decoys are generic and site-agnostic. Make them *convincing* on your stack with `createHoneypot(config)` — your brand, internal hostnames, and stack-shaped fake credentials injected into every decoy:

```typescript
import { createHoneypot } from "honeycrawlpot";

const hp = createHoneypot({
  canary: "LF-HONEYPOT-MYSITE-01",       // pin the canary to search for it reliably
  excludePaths: ["health", "status"],    // never serve decoys here
  brand: "Nebula",
  domains: { app: "https://nebula.app", api: "https://api.nebula.app",
             redis: "cache.internal.nebula.app" },
  secrets: { awsAccessKey: "AKIDNEBULATESTKEY0001", jwtSecret: "…" }, // all inert!
  database: { name: "nebula", user: "nebula_user" },
  extraKeywords: ["vault", "k8s", "helm"],
});

hp.resolveDecoy("/.env");
```

Pass the same config to the adapters (`honoHoneypot({ config })`, `expressHoneypot({ config })`). Set `HONEYPOT_CANARY` in the environment to pin the canary across restarts.

### Deploying behind Nginx

The honeypot must see scanner paths on *every* hostname. Replace blanket `deny all;` rules with a proxy pass so decoys get served:

```nginx
location ~* (^|/)(\.env|\.git|\.aws|\.ssh|\.config)(/|$) {
    proxy_pass http://app;
    proxy_cache off;
}
```

### Detection (the tripwire)

Alert on any occurrence of `LF-HONEYPOT-` in your SIEM (Loki, Datadog), incoming scan reports (auto-triage queues), and notification webhooks (Slack, Discord, Telegram). If it shows up anywhere outside your app, a scanner swallowed the bait — and its canary identifies exactly which probe it took.

> **GitHub push protection**: decoys contain fake credentials resembling real secrets *on purpose* and may be flagged on push. The bundled `.github/secret_scanning.yml` covers the default case; see its notes for ruleset overrides.

## Ecosystem

Part of the Resk-Security family: [Resk-LLM](https://github.com/Resk-Security/Resk-LLM), [resk-llm-ts](https://github.com/Resk-Security/resk-llm-js), [resk-logits](https://github.com/Resk-Security/resk-logits), [resksecure](https://github.com/Resk-Security/reskSecure), [ReskPoints](https://github.com/Resk-Security/ReskPoints).

## License

MIT
