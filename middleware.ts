const COOKIE_NAME = "word_atlas_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const MAX_BODY_BYTES = 4096;
const TOKEN_CONTEXT = "word-atlas-auth-v1";

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits));
}

function sha256Hex(input: string): string {
  const data = new TextEncoder().encode(input);
  const length = data.length;
  const blocks = Math.ceil((length + 9) / 64);
  const buffer = new Uint8Array(blocks * 64);
  buffer.set(data);
  buffer[length] = 0x80;
  const view = new DataView(buffer.buffer);
  const bits = length * 8;
  view.setUint32(blocks * 64 - 4, bits >>> 0, false);
  view.setUint32(blocks * 64 - 8, Math.floor(bits / 0x100000000), false);

  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ]);
  const schedule = new Uint32Array(64);

  for (let block = 0; block < blocks; block += 1) {
    const offset = block * 64;
    for (let i = 0; i < 16; i += 1) {
      schedule[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 =
        rotr(schedule[i - 15], 7) ^
        rotr(schedule[i - 15], 18) ^
        (schedule[i - 15] >>> 3);
      const s1 =
        rotr(schedule[i - 2], 17) ^
        rotr(schedule[i - 2], 19) ^
        (schedule[i - 2] >>> 10);
      schedule[i] = (schedule[i - 16] + s0 + schedule[i - 7] + s1) >>> 0;
    }

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    let f = state[5];
    let g = state[6];
    let h = state[7];

    for (let i = 0; i < 64; i += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + choice + SHA256_K[i] + schedule[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }

  return Array.from(state, (value) => value.toString(16).padStart(8, "0")).join(
    "",
  );
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char] ?? char,
  );
}

function renderLoginPage(action: string, error?: string): string {
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

export const config = { runtime: "nodejs" };

console.log("[password-gate] middleware module loaded");

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
