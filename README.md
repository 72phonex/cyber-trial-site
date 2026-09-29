# CYBER // TRIAL

A selection-round CTF platform: crypto, steganography, and binary
exploitation, with server-side flag verification, real (non-fake)
crypto analysis, hints, and an admin standings view.

## Structure
- `server.js` — Express API + static file server
- `public/index.html` — the candidate-facing platform
- `public/admin.html` — organizer standings view (needs `ADMIN_KEY`)
- `challenges/` — the real challenge files served for download

## Environment variables (set these in Render, never commit them)
- `DATABASE_URL` — Postgres connection string
- `FLAG_CRYPTO`, `FLAG_STEGO`, `FLAG_PWN` — the exact flag strings
- `ADMIN_KEY` — a password for the `/admin.html` standings page

## Local dev
```
npm install
DATABASE_URL=... FLAG_CRYPTO=... FLAG_STEGO=... FLAG_PWN=... ADMIN_KEY=... npm start
```

## Deploying
Push this repo to GitHub, then deploy it as a Render web service:
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Set the five environment variables above in the Render dashboard
