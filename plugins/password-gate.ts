import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Logger, Plugin } from "vite";
import { renderLoginPage } from "../shared/login-page";

const COOKIE_NAME = "word_atlas_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const MAX_BODY_BYTES = 4096;
const MAX_SESSIONS = 1000;

type Next = (err?: unknown) => void;

function readCookie(req: IncomingMessage, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return undefined;
}

function passwordMatches(input: string, expected: string): boolean {
  const left = Buffer.from(input, "utf8");
  const right = Buffer.from(expected, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      body += chunk;
      if (body.length > MAX_BODY_BYTES)
        reject(new Error("request body too large"));
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function safeNext(value: string | null, fallback: string): string {
  if (!value || !value.startsWith("/") || value.startsWith("//"))
    return fallback;
  return value;
}

function isSecureRequest(req: IncomingMessage): boolean {
  const proto = req.headers["x-forwarded-proto"];
  if (proto === "https" || (Array.isArray(proto) && proto.includes("https")))
    return true;
  return Boolean((req.socket as { encrypted?: boolean }).encrypted);
}

function createGate(password: string, base: string) {
  const sessionTokens = new Set<string>();
  const authPaths = new Set([`${base}__auth`, "/__auth"]);

  function sendLogin(res: ServerResponse, next: string, error?: string) {
    const action = `${base}__auth?next=${encodeURIComponent(safeNext(next, base))}`;
    res.statusCode = error ? 401 : 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(renderLoginPage(action, error));
  }

  return async function gate(
    req: IncomingMessage,
    res: ServerResponse,
    next: Next,
  ) {
    if (!password) {
      next();
      return;
    }

    const url = new URL(req.url || "/", "http://localhost");
    const route = url.pathname;

    if (authPaths.has(route)) {
      const target = safeNext(url.searchParams.get("next"), base);
      const token = readCookie(req, COOKIE_NAME);
      if (token && sessionTokens.has(token) && req.method !== "POST") {
        res.statusCode = 303;
        res.setHeader("Location", target);
        res.end();
        return;
      }
      if (req.method === "POST") {
        let body: string;
        try {
          body = await readBody(req);
        } catch {
          res.statusCode = 413;
          res.end();
          return;
        }
        const supplied = new URLSearchParams(body).get("password") || "";
        if (!passwordMatches(supplied, password)) {
          sendLogin(res, target, "Incorrect password. Try again.");
          return;
        }
        if (sessionTokens.size >= MAX_SESSIONS) sessionTokens.clear();
        const session = randomBytes(32).toString("base64url");
        sessionTokens.add(session);
        res.setHeader(
          "Set-Cookie",
          `${COOKIE_NAME}=${session}; Path=${base}; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}${
            isSecureRequest(req) ? "; Secure" : ""
          }`,
        );
        res.statusCode = 303;
        res.setHeader("Location", target);
        res.end();
        return;
      }
      if (req.method !== "GET" && req.method !== "HEAD") {
        res.statusCode = 405;
        res.setHeader("Allow", "GET, HEAD, POST");
        res.end();
        return;
      }
      sendLogin(res, target);
      return;
    }

    const token = readCookie(req, COOKIE_NAME);
    if (token && sessionTokens.has(token)) {
      next();
      return;
    }

    const wantsHtml = (req.headers.accept || "").includes("text/html");
    if (!wantsHtml) {
      res.statusCode = 401;
      res.setHeader("Cache-Control", "no-store");
      res.end("Unauthorized");
      return;
    }
    sendLogin(res, req.url || base);
  };
}

export function passwordGate(password: string, source = "environment"): Plugin {
  const gateBase = (base: string) => (base.endsWith("/") ? base : `${base}/`);
  const announce = (logger: Logger) => {
    if (!password) {
      logger.info("password gate: PASSWORD not set, access is open");
      return;
    }
    logger.info(`password gate: enabled (PASSWORD from ${source})`);
  };
  return {
    name: "word-atlas-password-gate",
    configureServer(server) {
      server.middlewares.use(
        createGate(password, gateBase(server.config.base)),
      );
      announce(server.config.logger);
    },
    configurePreviewServer(server) {
      server.middlewares.use(
        createGate(password, gateBase(server.config.base)),
      );
      announce(server.config.logger);
    },
  };
}
