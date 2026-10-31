export function escapeHtml(value: string): string {
  const entities: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return value.replace(/[&<>"']/g, (char) => entities[char] ?? char);
}

export function renderLoginPage(action: string, error?: string): string {
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
