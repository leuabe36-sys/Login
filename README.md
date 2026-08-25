# Simple login page (Cloudflare Workers + D1)

Files:
- `index.html` — the login/sign-up page (plain HTML/CSS/JS, no build step)
- `src/worker.js` — Cloudflare Worker backend (signup, login, session check, logout)
- `schema.sql` — database table definitions
- `wrangler.toml` — deploy config

## 1. Install Wrangler (Cloudflare's CLI)
```bash
npm install -g wrangler
wrangler login
```

## 2. Create the D1 database
```bash
wrangler d1 create simple_login_db
```
Copy the `database_id` it prints into `wrangler.toml` (replace `REPLACE_WITH_YOUR_DATABASE_ID`).

## 3. Create the tables
```bash
wrangler d1 execute simple_login_db --file=./schema.sql --remote
```

## 4. Deploy the Worker
```bash
wrangler deploy
```
This prints your Worker URL, e.g. `https://simple-login.<your-subdomain>.workers.dev`.

## 5. Connect the page to the Worker
- **Easiest:** open `index.html`, set `API_BASE` to your Worker URL (e.g. `"https://simple-login.you.workers.dev"`), then host `index.html` anywhere — Cloudflare Pages, another Worker, S3, etc.
- **All-in-one on Cloudflare:** put `index.html` in Cloudflare Pages and leave `API_BASE = ""`, then add a Pages route that proxies `/api/*` to the Worker (Pages Functions or a `_routes.json`) so both are served from the same domain — this avoids any cross-origin cookie complications.

## How it works
- Passwords are never stored in plain text — they're hashed with PBKDF2 (100,000 iterations, SHA-256) with a random salt per user, in `src/worker.js`.
- On sign-in, the Worker issues a random session token, stores it in the `sessions` table, and sets it as an `HttpOnly`, `Secure` cookie — JavaScript on the page never touches the token directly.
- `/api/me` is what the page calls on load to check whether the visitor already has a valid session.
- Sessions expire after 7 days (`SESSION_TTL_SECONDS` in `worker.js`).

## Local testing
```bash
wrangler dev
```
This runs the Worker locally (with a local D1 emulation). Point `index.html`'s `API_BASE` at `http://localhost:8787` while testing.
