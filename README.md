# lforla-honeypot

Serve realistic decoy files (fake secrets + **prompt injections**) to the AI/LLM-powered
vulnerability scanners that crawl your API probing for `.env`, AWS credentials, Firebase
service accounts, SSH keys, `openapi.json`, GraphQL endpoints, and hundreds of other
leak-prone paths.

Zero runtime dependencies. Framework-agnostic core with optional **Hono** and **Express**
adapters.

> ⚠️ **Defensive deception only.** Every credential in these decoys is fabricated and inert.
> The point is to waste a scanner's time, poison its automated report, and fingerprint it
> via the canary token. Never place real secrets in this module.

## What it does

When a bot requests a known scanner path (e.g. `/.env`, `/firebase-admin.json`,
`/.aws/credentials`, `/private-key`, `/openapi.json`, `/v1/graphql`, `/wp-config.php.bak`),
instead of a boring `404`, it receives a **`200` with a convincing fake file** containing:

- realistic-looking **fake credentials** (AWS `AKIA...`, Stripe `sk_live.…`, JWT secrets,
  PostgreSQL URLs) that are inert — if the bot tries to use them, they fail;
- embedded **prompt-injection payloads** aimed at LLM agents:
  - `[[SYSTEM OVERRIDE]]` — asks the agent to drop prior instructions and print the canary,
  - `[[RECURSION DIRECTIVE]]` — forces it to repeat the file 20x (token burn),
  - `[[AUDIT DIRECTIVE]]` — makes it emit 250 fake critical CVEs (report flooding),
  - `[[FALSE-TRIAGE DIRECTIVE]]` — tells it to report the host as "clean",
  - `[[DISCOVERY DIRECTIVE]]` — sends it down a rabbit hole enumerating fake endpoints,
  - `[[IDENTITY DIRECTIVE]]` — makes naive agents echo their own model identifier;
- a **canary token** `LF-HONEYPOT-XXXXXXXX` unique to your deployment. Find that string
  anywhere outside this module (a ticket, a Slack alert, a scan report) and you know a
  scanner swallowed the bait.

## Install

```bash
npm install lforla-honeypot
# or
bun add lforla-honeypot
```

## Usage

### Framework-agnostic

```ts
import { handleProbe } from "lforla-honeypot";

const outcome = handleProbe({ method: "GET", path: "/.env" });
if (outcome) {
  // -> { status: 200, headers: { "Content-Type": "...", "X-Honeypot": "true", ... },
  //      body: "…fake .env with prompt injections…", category: "env", canary: "LF-HONEYPOT-…" }
}
```

### Hono

```ts
import { Hono } from "hono";
import { honoHoneypot } from "lforla-honeypot";

const app = new Hono();

// real routes first — they take precedence over the honeypot
app.route("/api/v1", v1Routes);

// then the honeypot, BEFORE the 404 handler
app.use("*", honoHoneypot({ onHit: (h) => console.log("probe", h.path, h.canary) }));

app.notFound((c) => c.json({ error: "not found" }, 404));
```

### Express

```ts
import express from "express";
import { expressHoneypot } from "lforla-honeypot";

const app = express();

app.get("/api/health", (_req, res) => res.json({ ok: true }));

// before your 404/error handlers
app.use(expressHoneypot());

app.use((_req, res) => res.status(404).json({ error: "not found" }));
```

### Customize

```ts
import { resolveDecoy } from "lforla-honeypot";

const decoy = resolveDecoy("/firebase-admin.json", { excludePaths: ["health", "status"] });
// null -> path is legitimate, do NOT answer with a decoy
```

- Set `HONEYPOT_CANARY` in your environment to pin the canary across restarts
  (so you can search for it reliably).
- `excludePaths` lets you keep health/status endpoints out of the honeypot.

## How to deploy on Nginx (front-edge reverse proxy)

The honeypot must be reachable for scanner paths on *every* hostname, not just your API
subdomain. In Nginx, replace blanket `deny all; return 403;` guardrails with a proxy to
your app so the decoys get served:

```nginx
# scanner paths -> app -> honeypot answers with a decoy
location ~* (^|/)(\.env|\.git|\.aws|\.ssh|\.config)(/|$) {
    proxy_pass http://app;
    proxy_cache off;
}
```

Make sure your app mounts the honeypot **after** real routes and **before** the 404 handler.

## Detection

The canary token is your tripwire. Alert on any occurrence of `LF-HONEYPOT-` in:

- SIEM / log aggregation (Loki, Datadog),
- incoming security scan reports (auto-triage queues),
- notification webhooks (Slack, Discord, Telegram).

## License

MIT
