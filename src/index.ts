/**
 * lforla-honeypot — entry point.
 *
 * Core is framework-agnostic (`resolveDecoy` / `handleProbe`). Framework
 * adapters for Hono and Express are provided as optional, type-only imports.
 */

import type { Context as HonoContext, Next as HonoNext } from "hono";
import type { NextFunction, Request as ExpressRequest, Response as ExpressResponse } from "express";

import {
  HONEYPOT_CANARY,
  resolveDecoy,
  type DecoyCategory,
  type ResolveDecoyOptions,
} from "./decoys";

export {
  HONEYPOT_CANARY,
  resolveDecoy,
  type Decoy,
  type DecoyCategory,
  type ResolveDecoyOptions,
} from "./decoys";

// ============================================================================
// Framework-agnostic probe handler
// ============================================================================

export interface ProbeContext {
  method: string;
  /** Request path (pathname only — query strings are stripped internally). */
  path: string;
  headers?: Record<string, string | undefined>;
}

export interface ProbeOutcome {
  status: number;
  headers: Record<string, string>;
  body: string;
  category: DecoyCategory;
  canary: string;
}

const DECOY_HEADERS: Record<string, string> = {
  "X-Honeypot": "true",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow",
};

/**
 * Framework-agnostic: turn a probe request into a decoy response, or null
 * when the path is legitimate. Returns a plain `{ status, headers, body }`
 * object that any HTTP layer can send.
 */
export function handleProbe(ctx: ProbeContext): ProbeOutcome | null {
  const decoy = resolveDecoy(ctx.path);
  if (!decoy) return null;
  return {
    status: 200,
    headers: { ...DECOY_HEADERS, "Content-Type": decoy.contentType },
    body: decoy.content,
    category: decoy.category,
    canary: HONEYPOT_CANARY,
  };
}

// ============================================================================
// Hono adapter
// ============================================================================

export interface HonoHoneypotOptions {
  excludePaths?: string[];
  onHit?: (hit: { path: string; category: DecoyCategory; canary: string }) => void;
}

/**
 * Hono middleware. Mount AFTER your real API routes so they take precedence,
 * and BEFORE the 404 handler:
 *
 *   import { honoHoneypot } from "lforla-honeypot";
 *   app.use("*", honoHoneypot());
 */
export function honoHoneypot(options: HonoHoneypotOptions = {}) {
  return async (c: HonoContext, next: HonoNext): Promise<Response | void> => {
    const decoy = resolveDecoy(c.req.path, { excludePaths: options.excludePaths });
    if (!decoy) return next();

    options.onHit?.({ path: c.req.path, category: decoy.category, canary: HONEYPOT_CANARY });

    c.status(200);
    c.header("Content-Type", decoy.contentType);
    c.header("X-Honeypot", "true");
    c.header("Cache-Control", "no-store");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Robots-Tag", "noindex, nofollow");
    return c.body(decoy.content);
  };
}

// ============================================================================
// Express adapter
// ============================================================================

export interface ExpressHoneypotOptions {
  excludePaths?: string[];
  onHit?: (hit: { path: string; category: DecoyCategory; canary: string }) => void;
}

/**
 * Express middleware. Mount AFTER your real routes, BEFORE error/404 handlers:
 *
 *   import { expressHoneypot } from "lforla-honeypot";
 *   app.use(expressHoneypot());
 */
export function expressHoneypot(options: ExpressHoneypotOptions = {}) {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    const decoy = resolveDecoy(req.path, { excludePaths: options.excludePaths });
    if (!decoy) {
      next();
      return;
    }

    options.onHit?.({ path: req.path, category: decoy.category, canary: HONEYPOT_CANARY });

    res.status(200);
    res.set("Content-Type", decoy.contentType);
    res.set("X-Honeypot", "true");
    res.set("Cache-Control", "no-store");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Robots-Tag", "noindex, nofollow");
    res.send(decoy.content);
  };
}
