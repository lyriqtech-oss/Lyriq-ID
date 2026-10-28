# Lyriq ID

Web app for a central Lyriq account. This repository contains a working account interface and security foundation, plus a separate visual preview of the reference design.

## Run locally

Requires Node.js 24 or later. Copy `.env.example` to `.env`, set `SUPABASE_SERVER_KEY` and a stable random `APP_ENCRYPTION_KEY` (32 bytes encoded as base64url), then run:

```sh
npm start
```

Open **http://127.0.0.1:3000**. The file `public/index.html` opened directly uses sample data; it is a visual preview and does not connect to the server.

The provided Supabase key is kept in the local ignored `.env` file. Never commit it, expose it in browser code, or ship it in a client app. Rotate a key if it has been disclosed.

## Current functionality

- Supabase Auth email/password signup and sign-in; confirmation email follows project settings.
- Server-side sessions in SQLite, with encrypted access and refresh tokens, HTTP-only SameSite cookies, seven-day maximum duration, session listing and revocation.
- Supabase Auth TOTP enrollment and challenge at sign-in. Other local sessions are revoked after adding a factor.
- Supabase Auth recovery-code generation after MFA enrollment, if enabled on the Supabase project. Codes appear once and are not stored by this app.
- Four first-party Lyriq verification-code cards. Secrets are encrypted at rest; codes rotate every 30 seconds.
- First-party code verification endpoint with a per-product server secret, one-time use, and rate limits.
- Security events, account and session views, responsive layout.

## Product integration

Each Lyriq product needs a distinct `LYRIQ_CLIENT_<PRODUCT>_SECRET` on the Lyriq ID server. A product verifies a user-supplied code with `POST /api/codes/verify`, sending its secret as `Authorization: Bearer <secret>` and a JSON body of `{ "client_id": "waterwolf", "user_id": "...", "code": "123456" }`. Verification returns `{ "valid": true, "user_id": "...", "client_id": "..." }` once. This is a server-to-server endpoint; never place client secrets in browser or mobile code. No Lyriq products are connected yet, so the codes do not currently sign users into them.

## Security and deployment limits

This is **not a production identity provider yet**. Passkey login, OAuth/OIDC authorization, trusted-device enrollment, agent approvals, push approvals, organization policies, and account recovery flows remain to be implemented and audited. The app uses local SQLite for session and code metadata; moving it to managed PostgreSQL with backups is necessary before multi-instance deployment. Configure HTTPS, a trusted reverse proxy, separate environment secrets, Supabase Auth rate limits, MFA enrollment settings, backups, monitoring, and external security testing before real users depend on it. The local visual preview contains illustrative information only.

Run `npm run check` for syntax and cryptographic unit tests.