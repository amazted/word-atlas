import { renderLoginPage } from "./shared/login-page";
import { sha256Hex } from "./shared/sha256";

const COOKIE_NAME = "word_atlas_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const MAX_BODY_BYTES = 4096;
const TOKEN_CONTEXT = "word-atlas-auth-v1";

let cachedPassword = "";
let cachedToken = "";

function basePath(): string {
  const base = process.env.ATLAS_BASE || "/";
  return base.endsWith("/") ? base : `${base}/`;
}

function tokenFor(password: string): string {
  if (password === cachedPassword && cachedToken) return cachedToken;
  const token = sha256Hex(`${TOKEN_CONTEXT}:${password}`);
  cachedPassword = password;
  cachedToken = token;
  return token;
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      const value = part.slice(eq + 1).trim();
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }
  return undefined;
}

function safeNext(value: string | null, fallback: string): string {
  if (!value || !value.startsWith("/") || value.startsWith("//"))
    return fallback;
  return value;
}

function nextResponse(): Response {
  return new Response(null, { headers: { "x-middleware-next": "1" } });
}

function htmlPage(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex",
    },
  });
}

function redirect(location: string, cookie?: string): Response {
  const headers: Record<string, string> = {
    Location: location,
    "Cache-Control": "no-store",
  };
  if (cookie) headers["Set-Cookie"] = cookie;
  return new Response(null, { status: 303, headers });
}

async function handle(request: Request): Promise<Response> {
  const password = process.env.PASSWORD;
  if (!password) return nextResponse();

  const url = new URL(request.url);
  if (url.pathname.startsWith("/_vercel/")) return nextResponse();

  const base = basePath();
  const authPath = `${base}__auth`;
  const isAuth = url.pathname === authPath || url.pathname === "/__auth";
  const expected = tokenFor(password);
  const cookie = readCookie(request.headers.get("cookie"), COOKIE_NAME);
  const authenticated = cookie !== undefined && safeEqual(cookie, expected);

  if (isAuth) {
    const target = safeNext(url.searchParams.get("next"), base);
    const action = `${authPath}?next=${encodeURIComponent(target)}`;

    if (request.method === "POST") {
      const body = await request.text();
      if (body.length > MAX_BODY_BYTES) {
        return new Response("Payload Too Large", { status: 413 });
      }
      let supplied = "";
      try {
        supplied = new URLSearchParams(body).get("password") ?? "";
      } catch {
        return new Response("Bad Request", { status: 400 });
      }
      if (!safeEqual(supplied, password)) {
        return htmlPage(
          renderLoginPage(action, "Incorrect password. Try again."),
          401,
        );
      }
      const secure = url.protocol === "https:" ? "; Secure" : "";
      return redirect(
        target,
        `${COOKIE_NAME}=${expected}; Path=${base}; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}${secure}`,
      );
    }

    if (authenticated) return redirect(target);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "GET, HEAD, POST" },
      });
    }
    return htmlPage(renderLoginPage(action), 200);
  }

  if (authenticated) return nextResponse();

  const wantsHtml = (request.headers.get("accept") || "").includes("text/html");
  if (!wantsHtml) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const back = `${url.pathname}${url.search}`;
  return htmlPage(
    renderLoginPage(`${authPath}?next=${encodeURIComponent(back)}`),
    401,
  );
}

export default async function middleware(request: Request): Promise<Response> {
  try {
    return await handle(request);
  } catch (error) {
    console.error("[password-gate]", error);
    return new Response("Password gate error", {
      status: 500,
      headers: { "Cache-Control": "no-store" },
    });
  }
}
