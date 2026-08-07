import { describe, expect, it } from "bun:test";

import { HONEYPOT_CANARY, handleProbe, honoHoneypot, resolveDecoy } from "../src/index";
import { Hono } from "hono";

describe("resolveDecoy", () => {
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
});
