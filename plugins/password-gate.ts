import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";

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

function escapeHtml(value: string): string {
  const entities: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return value.replace(/[&<>"']/g, (char) => entities[char] ?? char);
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

function loginPage(action: string, error?: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" />
<title>Word Atlas · Password required</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0d1120;
    --card: #161c30;
    --line: #2a3350;
    --text: #f3f0e8;
    --muted: #9aa3bd;
    --accent: #ad5038;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
    background: radial-gradient(1200px 600px at 50% -10%, #23305a 0%, var(--bg) 60%);
    color: var(--text);
    font: 16px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .card {
    width: 100%;
    max-width: 380px;
    padding: 32px;
    border: 1px solid var(--line);
    border-radius: 20px;
    background: var(--card);
    box-shadow: 0 30px 80px rgb(0 0 0 / 45%);
  }
  .brand {
    font-size: 12px;
    letter-spacing: 0.32em;
    color: var(--muted);
  }
  h1 {
    margin: 12px 0 6px;
    font-size: 24px;
    font-weight: 600;
  }
  .hint {
    margin: 0 0 24px;
    color: var(--muted);
    font-size: 14px;
  }
  form { display: grid; gap: 12px; }
  input {
    width: 100%;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-radius: 12px;
    background: #0f1526;
    color: var(--text);
    font: inherit;
    outline: none;
  }
  input:focus { border-color: var(--accent); }
  button {
    padding: 12px 16px;
    border: 0;
    border-radius: 12px;
    background: var(--accent);
    color: #fff;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover { filter: brightness(1.08); }
  .error {
    margin: 4px 0 0;
    color: #ff9d8a;
    font-size: 13px;
  }
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
</head>
<body>
  <main class="card">
    <div class="brand">WORD ATLAS</div>
    <h1>Password required</h1>
    <p class="hint">This atlas is protected. Enter the password to continue.</p>
    <form method="post" action="${escapeHtml(action)}">
      <label class="sr-only" for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="Password" autocomplete="current-password" required autofocus />
      <button type="submit">Unlock</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}
    </form>
  </main>
</body>
</html>`;
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
    res.end(loginPage(action, error));
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

export function passwordGate(password: string): Plugin {
  const gateBase = (base: string) => (base.endsWith("/") ? base : `${base}/`);
  return {
    name: "word-atlas-password-gate",
    configureServer(server) {
      server.middlewares.use(
        createGate(password, gateBase(server.config.base)),
      );
      if (!password) {
        server.config.logger.info(
          "password gate: PASSWORD not set, access is open",
        );
      }
    },
    configurePreviewServer(server) {
      server.middlewares.use(
        createGate(password, gateBase(server.config.base)),
      );
    },
  };
}
