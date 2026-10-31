import { next } from "@vercel/functions";
import { renderLoginPage } from "./shared/login-page";

const COOKIE_NAME = "word_atlas_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const TOKEN_CONTEXT = "word-atlas-auth-v1";

let cachedPassword = "";
let cachedToken = "";

function basePath(): string {
  const base = process.env.ATLAS_BASE || "/";
  return base.endsWith("/") ? base : `${base}/`;
}

async function tokenFor(password: string): Promise<string> {
  if (password === cachedPassword && cachedToken) return cachedToken;
  const data = new TextEncoder().encode(`${TOKEN_CONTEXT}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const token = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  cachedPassword = password;
  cachedToken = token;
  return token;
}

function safeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left[index] ^ right[index];
  }
  return diff === 0;
}

function readCookie(header: string | null, name: string): string | undefined {
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

function safeNext(value: string | null, fallback: string): string {
  if (!value || !value.startsWith("/") || value.startsWith("//"))
    return fallback;
  return value;
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

export default async function middleware(request: Request): Promise<Response> {
  const password = process.env.PASSWORD;
  if (!password) return next();

  const url = new URL(request.url);
  const base = basePath();
  const authPath = `${base}__auth`;
  const isAuth = url.pathname === authPath || url.pathname === "/__auth";
  const expected = await tokenFor(password);
  const cookie = readCookie(request.headers.get("cookie"), COOKIE_NAME);
  const authenticated = cookie !== undefined && safeEqual(cookie, expected);

  if (isAuth) {
    const target = safeNext(url.searchParams.get("next"), base);
    const action = `${authPath}?next=${encodeURIComponent(target)}`;

    if (request.method === "POST") {
      let supplied = "";
      try {
        const form = await request.formData();
        const value = form.get("password");
        supplied = typeof value === "string" ? value : "";
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

  if (authenticated) return next();

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

export const config = {
  matcher: ["/((?!_vercel/).*)"],
};
