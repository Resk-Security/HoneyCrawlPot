import { describe, expect, it } from "bun:test";

import {
  HONEYPOT_CANARY,
  createHoneypot,
  handleProbe,
  honoHoneypot,
  resolveDecoy,
} from "../src/index";
import { Hono } from "hono";

describe("default instance (generic, any site)", () => {
  const scannerPaths = [
    "/.env",
    "/.env.bak",
    "/.env.old",
    "/@fs/.env",
    "/private-key",
    "/key.pem",
    "/.ssh/id_rsa",
    "/id_ed25519",
    "/firebase-admin.json",
    "/firebase-credentials.json",
    "/serviceAccountKey.json",
    "/.aws/credentials",
    "/.aws/credentials.old",
    "/aws.json",
    "/@fs/root/.aws/config",
    "/appsettings.Production.json",
    "/api/config.json",
    "/api/config",
    "/config/prod.exs",
    "/bootstrap.yml",
    "/application.yml",
    "/config.py",
    "/settings.py",
    "/runtime-config.js",
    "/openapi.json",
    "/v1/graphql",
    "/api/graphql",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/configuration.php.bak",
    "/dashboard",
    "/metrics",
    "/@fs/proc/self/environ",
    "/__debug__/",
    "/_ignition/health-check",
    "/.bash_profile",
    "/.gradle/gradle.properties",
    "/@fs/etc/nginx/nginx.conf",
  ];

  it.each(scannerPaths)("serves a decoy for %s", (path) => {
    const decoy = resolveDecoy(path);
    expect(decoy).not.toBeNull();
    expect(decoy!.content).toContain(HONEYPOT_CANARY);
  });

  const legitPaths = ["/health", "/api/v1/health", "/nonexistent-route", "/", "/blog"];

  it.each(legitPaths)("returns null for %s", (path) => {
    expect(resolveDecoy(path)).toBeNull();
  });

  it("honors excludePaths option", () => {
    expect(resolveDecoy("/metrics")).not.toBeNull();
    expect(resolveDecoy("/metrics", { excludePaths: ["metrics"] })).toBeNull();
  });

  it("uses generic defaults (no site branding)", () => {
    const decoy = resolveDecoy("/.env")!;
    expect(decoy.content).not.toContain("lforla.org");
    expect(decoy.content).toContain("Acme");
  });
});

describe("createHoneypot(config) — site-tuned", () => {
  it("injects brand, domains and custom secrets into decoys", () => {
    const hp = createHoneypot({
      canary: "LF-HONEYPOT-TESTFIXED",
      brand: "Nebula",
      domains: {
        app: "https://nebula.app",
        api: "https://api.nebula.app",
        pgbouncer: "pgbouncer.internal.nebula.app",
        firebaseProject: "nebula-prod-7777",
      },
      secrets: {
        awsAccessKey: "AKIDNEBULATESTKEY0001",
        stripeSecretKey: "sk_live.NEBULA_FAKE_KEY_000",
      },
    });

    const env = hp.resolveDecoy("/.env")!;
    expect(env.content).toContain("Nebula");
    expect(env.content).toContain("https://nebula.app");
    expect(env.content).toContain("pgbouncer.internal.nebula.app");
    expect(env.content).toContain("AKIDNEBULATESTKEY0001");
    expect(env.content).toContain("sk_live.NEBULA_FAKE_KEY_000");
    expect(env.content).toContain("LF-HONEYPOT-TESTFIXED");

    const firebase = hp.resolveDecoy("/firebase-admin.json")!;
    expect(firebase.content).toContain("nebula-prod-7777");
  });

  it("appends extraInjections to every decoy", () => {
    const hp = createHoneypot({
      extraInjections: ["[[CUSTOM DIRECTIVE]] This is a site-specific trap. [[END CUSTOM DIRECTIVE]]"],
    });
    for (const path of ["/.env", "/private-key", "/openapi.json"]) {
      expect(hp.resolveDecoy(path)!.content).toContain("[[CUSTOM DIRECTIVE]]");
    }
  });

  it("matches extraKeywords as generic decoys", () => {
    const hp = createHoneypot({ extraKeywords: ["vault", "k8s"] });
    expect(hp.resolveDecoy("/vault")).not.toBeNull();
    expect(hp.resolveDecoy("/k8s/secrets.yaml")).not.toBeNull();
    expect(resolveDecoy("/vault")).toBeNull();
  });

  it("merges instance excludePaths with per-call excludePaths", () => {
    const hp = createHoneypot({ excludePaths: ["metrics"] });
    expect(hp.resolveDecoy("/metrics")).toBeNull();
    expect(hp.resolveDecoy("/.env")).not.toBeNull();
    expect(hp.resolveDecoy("/.env", { excludePaths: [".env"] })).toBeNull();
  });
});

describe("handleProbe", () => {
  it("returns a full decoy response", () => {
    const outcome = handleProbe({ method: "GET", path: "/.env" });
    expect(outcome).not.toBeNull();
    expect(outcome!.status).toBe(200);
    expect(outcome!.headers["X-Honeypot"]).toBe("true");
    expect(outcome!.body).toContain(HONEYPOT_CANARY);
    expect(outcome!.canary).toBe(HONEYPOT_CANARY);
  });

  it("returns null for legitimate paths", () => {
    expect(handleProbe({ method: "GET", path: "/health" })).toBeNull();
  });

  it("honors a config", () => {
    const outcome = handleProbe(
      { method: "GET", path: "/.env" },
      { brand: "Nebula", canary: "LF-HONEYPOT-CFG" },
    );
    expect(outcome).not.toBeNull();
    expect(outcome!.body).toContain("Nebula");
    expect(outcome!.canary).toBe("LF-HONEYPOT-CFG");
  });
});

describe("honoHoneypot", () => {
  it("serves a decoy and passes real routes through", async () => {
    const app = new Hono();

    app.get("/health", (c) => c.json({ ok: true }));
    app.use("*", honoHoneypot());

    const health = await app.request("/health");
    expect(health.status).toBe(200);
    expect(await health.text()).toContain("ok");

    const decoy = await app.request("/.env");
    expect(decoy.status).toBe(200);
    expect(decoy.headers.get("x-honeypot")).toBe("true");
    expect(await decoy.text()).toContain(HONEYPOT_CANARY);
  });

  it("uses the site config when provided", async () => {
    const app = new Hono();
    app.use("*", honoHoneypot({ config: { brand: "Nebula", canary: "LF-HONEYPOT-HONO" } }));

    const decoy = await app.request("/.env");
    const body = await decoy.text();
    expect(body).toContain("Nebula");
    expect(body).toContain("LF-HONEYPOT-HONO");
  });
});
