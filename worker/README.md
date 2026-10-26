# Equicloud on Cloudflare Workers + D1

This is a Cloudflare-native implementation of Equicloud's client-facing API, kept alongside the upstream Rust/ScyllaDB service. It implements the OAuth setup/callback, `/v1/settings`, `/v2/sync`, `/v2/manifest`, and `/v2/data/*` routes used by Equicord. D1 stores per-user auth secrets and metadata; R2 stores potentially large settings/sync payloads.

## Local setup

1. Install Node.js, then run `npm install` in this directory.
2. Create a D1 database with `npx wrangler d1 create equicloud` and an R2 bucket with `npx wrangler r2 bucket create equicloud-data`. Copy the D1 ID into `wrangler.toml`.
3. Apply the schema: `npx wrangler d1 migrations apply equicloud --local`.
4. Set secrets for local development in `.dev.vars` (never commit it):

   ```dotenv
   DISCORD_CLIENT_ID=...
   DISCORD_CLIENT_SECRET=...
   ```

5. Register `http://localhost:8787/v1/oauth/callback` as a Discord OAuth2 redirect and run `npm run dev`.

## Deploy

1. Authenticate Wrangler with `npx wrangler login`.
2. Create the production D1 database and R2 bucket, set their IDs/names in `wrangler.toml`, and configure the Worker URL as `DISCORD_REDIRECT_URI`.
3. Add the production Discord redirect URI in the Developer Portal.
4. Set `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET` as Worker secrets (`npx wrangler secret put ...`). Set access policy and allowed CORS origins in Worker vars. For a private service, keep `DISCORD_ALLOWED_USER_IDS` populated; only explicitly enable all-user registration if you mean to operate a public service.
5. Apply remote D1 migrations and deploy: `npx wrangler d1 migrations apply equicloud --remote`, then `npm run deploy`.

Do not paste Cloudflare API tokens, OAuth client secrets, or other credentials into chat or commit them. Wrangler's interactive login and local secret configuration are the safe path. Cloudflare Pages is not needed for this API-only service.

## Compatibility notes

This is a new D1-backed implementation, not a Rust-to-WASM build of the ScyllaDB service. Validate OAuth, CORS, sync conflict behavior, deletion, and account cleanup against a development Discord application before using it with real accounts. D1 and Worker request/row limits differ from the upstream service; this implementation deliberately rejects oversized sync batches and individual values. Review Cloudflare plan limits and add backups/monitoring before relying on it for long-term data storage.
