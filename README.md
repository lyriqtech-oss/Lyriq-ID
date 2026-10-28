# Lyriq ID

Initial account and security center for the Lyriq ecosystem.

## Run

Copy `.env.example` to `.env`, add your Supabase publishable/anon key, then run `npm start` with Node.js 20 or later. Open http://localhost:3000.

## Current scope

Email and password account creation and sign in use Supabase Auth. The interface includes an account overview and clearly labels future security capabilities. Passkeys, OIDC, device/session inventory, approvals, and native mobile are not implemented yet. Do not use this prototype as a production identity provider.

The Supabase service-role key must never be committed or exposed to the browser.
