interface Env {
    DB: D1Database;
    BUCKET: R2Bucket;
    DISCORD_CLIENT_ID: string;
    DISCORD_CLIENT_SECRET: string;
    DISCORD_REDIRECT_URI: string;
    DISCORD_ALLOWED_USER_IDS?: string;
    DISCORD_ALLOW_ALL_USERS?: string;
    CORS_ALLOWED_ORIGINS?: string;
    MAX_BACKUP_SIZE_BYTES?: string;
    DATASTORE_ENABLED?: string;
    API_ROOT_REDIRECT_URL?: string;
}

type SyncManifest = { key: string; version: number; checksum: string };
type Upload = { key: string; value: string; checksum?: string };

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const error = (status: number, message: string) => Response.json({ error: message }, { status, headers: JSON_HEADERS });
const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
const randomSecret = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
};

async function checksum(value: string): Promise<string> {
    const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
    return hex(await crypto.subtle.digest("SHA-256", bytes)).slice(0, 16);
}

function userIdFromAuth(request: Request): string | null {
    const header = request.headers.get("authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : header;
    if (token.length > 256) return null;
    try {
        const [secret, userId] = atob(token).split(":", 2);
        return secret && /^\d{5,25}$/.test(userId || "") ? userId : null;
    } catch { return null; }
}

async function authorizedUser(request: Request, env: Env): Promise<string | Response> {
    const id = userIdFromAuth(request);
    if (!id) return error(401, "Unauthorized");
    const user = await env.DB.prepare("SELECT auth_secret FROM users WHERE discord_id = ?").bind(id).first<{ auth_secret: string }>();
    if (!user || user.auth_secret.length !== 64) return error(401, "Unauthorized");
    const a = new TextEncoder().encode(user.auth_secret);
    const b = new TextEncoder().encode(atob((request.headers.get("authorization") || "").replace(/^Bearer /, "")).split(":", 2)[0] || "");
    // Fixed-length secret compare with no data-dependent early exit.
    let diff = a.length ^ b.length;
    for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] || 0) ^ (b[i] || 0);
    if (diff) return error(401, "Unauthorized");
    return id;
}

function cors(request: Request, env: Env, response: Response): Response {
    const origin = request.headers.get("Origin");
    const allowed = (env.CORS_ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
    const headers = new Headers(response.headers);
    if (origin && allowed.includes(origin)) {
        headers.set("Access-Control-Allow-Origin", origin);
        headers.set("Vary", "Origin");
        headers.set("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,DELETE,OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Authorization,Content-Type,If-None-Match,If-Match,X-Checksum");
        headers.set("Access-Control-Expose-Headers", "ETag,X-Version");
    }
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("X-Frame-Options", "DENY");
    headers.set("Referrer-Policy", "no-referrer");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function oauth(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/v1/oauth/settings") {
        return Response.json({ clientId: env.DISCORD_CLIENT_ID, redirectUri: env.DISCORD_REDIRECT_URI }, { headers: JSON_HEADERS });
    }
    const code = url.searchParams.get("code");
    if (!code) return error(400, "Missing code");
    if (url.searchParams.has("error")) return error(400, "Authorization failed");

    const form = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: env.DISCORD_REDIRECT_URI
    });
    const tokenResponse = await fetch("https://discord.com/api/v10/oauth2/token", {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form
    });
    if (!tokenResponse.ok) return error(400, "Invalid OAuth code");
    const token = await tokenResponse.json<{ access_token: string; token_type: string; scope: string }>();
    if (token.token_type.toLowerCase() !== "bearer" || !token.scope.split(" ").includes("identify")) return error(400, "Invalid OAuth scopes");
    const profileResponse = await fetch("https://discord.com/api/v10/users/@me", { headers: { authorization: `Bearer ${token.access_token}` } });
    if (!profileResponse.ok) return error(502, "Could not retrieve Discord user");
    const profile = await profileResponse.json<{ id: string }>();
    const allowlist = (env.DISCORD_ALLOWED_USER_IDS || "").split(",").map(x => x.trim()).filter(Boolean);
    if (allowlist.length ? !allowlist.includes(profile.id) : env.DISCORD_ALLOW_ALL_USERS !== "true") return error(403, "User is not allowed");

    let row = await env.DB.prepare("SELECT auth_secret FROM users WHERE discord_id = ?").bind(profile.id).first<{ auth_secret: string }>();
    if (!row) {
        const secret = randomSecret();
        await env.DB.prepare("INSERT OR IGNORE INTO users (discord_id, auth_secret) VALUES (?, ?)").bind(profile.id, secret).run();
        row = await env.DB.prepare("SELECT auth_secret FROM users WHERE discord_id = ?").bind(profile.id).first<{ auth_secret: string }>();
    }
    // Revoke the short-lived Discord access token; the client receives only our per-user secret.
    await fetch("https://discord.com/api/v10/oauth2/token/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, token: token.access_token }) }).catch(() => {});
    return Response.json({ secret: row!.auth_secret }, { headers: JSON_HEADERS });
}

async function syncV2(request: Request, env: Env, userId: string): Promise<Response> {
    let payload: { client_manifest?: SyncManifest[]; uploads?: Upload[] };
    try { payload = await request.json(); } catch { return error(400, "Invalid JSON"); }
    const manifest = payload.client_manifest || [];
    const uploads = payload.uploads || [];
    if (!Array.isArray(manifest) || !Array.isArray(uploads) || manifest.length > 1000000 || uploads.length > 100000) return error(413, "Sync request too large");
    const maxTotal = Number(env.MAX_BACKUP_SIZE_BYTES || 62914560);
    const existing = await env.DB.prepare("SELECT key, object_key, version, checksum, size_bytes FROM sync_data WHERE discord_id = ?").bind(userId).all<{ key: string; object_key: string; version: number; checksum: string; size_bytes: number }>();
    const stored = new Map(existing.results.map(row => [row.key, row]));
    const client = new Map(manifest.map(e => [e.key, e]));
    const downloadRows = [...stored.values()].filter(row => !(row.key.startsWith("dataStore/") && env.DATASTORE_ENABLED !== "true") && (() => { const e = client.get(row.key); return !e || e.version < row.version || e.checksum !== row.checksum; })());
    const downloads = (await Promise.all(downloadRows.map(async ({ key, object_key, version, checksum }) => {
        const object = await env.BUCKET.get(object_key);
        if (!object) return null;
        const bytes = new Uint8Array(await object.arrayBuffer());
        let binary = "";
        for (let offset = 0; offset < bytes.length; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
        return { key, value: btoa(binary), version, checksum };
    }))).filter(Boolean);
    const uploaded: Array<{ key: string; version: number; checksum: string }> = [];
    const errors: Array<{ key: string; error: string }> = [];
    const seen = new Set<string>();
    let total = existing.results.reduce((sum, row) => sum + row.size_bytes, 0);
    const statements: D1PreparedStatement[] = [];
    for (const upload of uploads) {
        if (!upload || typeof upload.key !== "string" || typeof upload.value !== "string") continue;
        const key = upload.key;
        if (seen.has(key)) { errors.push({ key, error: "Duplicate key in same upload batch" }); continue; }
        seen.add(key);
        if (!/^[\w./-]{1,200}$/.test(key) || key.includes("..") || key.startsWith("/") || (key.startsWith("dataStore/") && env.DATASTORE_ENABLED !== "true")) { errors.push({ key, error: "Invalid or disabled key" }); continue; }
        const size = Math.floor(upload.value.length * 3 / 4);
        const keyLimit = key.startsWith("dataStore/") ? 10 * 1024 * 1024 : 1024 * 1024;
        if (size > keyLimit) { errors.push({ key, error: `Value exceeds ${keyLimit / 1024 / 1024}MB limit` }); continue; }
        const digest = await checksum(upload.value);
        if (upload.checksum && upload.checksum !== digest) { errors.push({ key, error: "Checksum mismatch" }); continue; }
        const old = stored.get(key);
        const clientEntry = client.get(key);
        if (old && (!clientEntry || clientEntry.version < old.version)) { errors.push({ key, error: "Server has newer version; pull before pushing" }); continue; }
        const newTotal = total - (old?.size_bytes || 0) + size;
        if (newTotal > maxTotal) { errors.push({ key, error: "Total storage limit exceeded" }); continue; }
        const version = (old?.version || 0) + 1;
        const objectKey = `sync/${userId}/${encodeURIComponent(key)}`;
        const raw = Uint8Array.from(atob(upload.value), c => c.charCodeAt(0));
        await env.BUCKET.put(objectKey, raw, { customMetadata: { discordId: userId, key, checksum: digest } });
        statements.push(env.DB.prepare("INSERT INTO sync_data (discord_id,key,object_key,version,checksum,size_bytes,updated_at) VALUES (?,?,?,?,?,?,unixepoch()) ON CONFLICT(discord_id,key) DO UPDATE SET object_key=excluded.object_key,version=excluded.version,checksum=excluded.checksum,size_bytes=excluded.size_bytes,updated_at=unixepoch()") .bind(userId, key, objectKey, version, digest, size));
        uploaded.push({ key, version, checksum: digest });
        total = newTotal;
    }
    for (let i = 0; i < statements.length; i += 100) await env.DB.batch(statements.slice(i, i + 100));
    const updated = await env.DB.prepare("SELECT key,version,checksum,size_bytes FROM sync_data WHERE discord_id = ?").bind(userId).all<{ key: string; version: number; checksum: string; size_bytes: number }>();
    return Response.json({ server_manifest: updated.results.map(({ key, version, checksum }) => ({ key, version, checksum })), downloads, uploaded, errors }, { headers: JSON_HEADERS });
}

async function handle(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204 });
    if (url.pathname === "/" && env.API_ROOT_REDIRECT_URL) return Response.redirect(env.API_ROOT_REDIRECT_URL, 302);
    if (url.pathname === "/health") return Response.json({ status: "ok", service: "equicloud-worker" });
    if ((url.pathname === "/v1" || url.pathname === "/v1/") && request.method === "GET") return Response.json({ status: "ok", service: "equicloud" });
    if (url.pathname === "/v1/oauth/settings" || url.pathname === "/v1/oauth/callback") return oauth(request, env);

    const userId = await authorizedUser(request, env);
    if (userId instanceof Response) return userId;
    if (url.pathname === "/v2/sync" && request.method === "POST") return syncV2(request, env, userId);

    if (url.pathname === "/v1/settings") {
        if (request.method === "GET" || request.method === "HEAD") {
            const record = await env.DB.prepare("SELECT object_key, etag FROM settings WHERE discord_id = ?").bind(userId).first<{ object_key: string; etag: string }>();
            if (!record) return new Response(null, { status: 404 });
            if (request.headers.get("if-none-match") === record.etag) return new Response(null, { status: 304, headers: { etag: record.etag } });
            if (request.method === "HEAD") return new Response(null, { status: 204, headers: { etag: record.etag } });
            const object = await env.BUCKET.get(record.object_key);
            return object ? new Response(object.body, { headers: { "content-type": "application/octet-stream", etag: record.etag, "cache-control": "no-store" } }) : new Response(null, { status: 404 });
        }
        if (request.method === "PUT") {
            const body = await request.arrayBuffer();
            if (body.byteLength > Number(env.MAX_BACKUP_SIZE_BYTES || 62914560)) return error(413, "Settings are too large");
            const etag = String(Date.now());
            const objectKey = `settings/${userId}`;
            await env.BUCKET.put(objectKey, body);
            await env.DB.prepare("INSERT INTO settings(discord_id,object_key,etag,updated_at) VALUES(?,?,?,unixepoch()) ON CONFLICT(discord_id) DO UPDATE SET object_key=excluded.object_key,etag=excluded.etag,updated_at=unixepoch()").bind(userId, objectKey, etag).run();
            return Response.json({ written: Number(etag) }, { headers: { ...JSON_HEADERS, etag } });
        }
        if (request.method === "DELETE") {
            const record = await env.DB.prepare("SELECT object_key FROM settings WHERE discord_id = ?").bind(userId).first<{ object_key: string }>();
            if (record) await env.BUCKET.delete(record.object_key);
            await env.DB.prepare("DELETE FROM settings WHERE discord_id = ?").bind(userId).run();
            return new Response(null, { status: 204 });
        }
    }
    if (url.pathname === "/v2/manifest" && request.method === "GET") {
        const result = await env.DB.prepare("SELECT key,version,checksum,size_bytes FROM sync_data WHERE discord_id = ? ORDER BY key").bind(userId).all<{ key: string; version: number; checksum: string; size_bytes: number }>();
        const entries = result.results.filter(row => env.DATASTORE_ENABLED === "true" || !row.key.startsWith("dataStore/")).map(({ key, version, checksum }) => ({ key, version, checksum }));
        return Response.json({ entries, total_size: result.results.reduce((total, row) => total + row.size_bytes, 0) }, { headers: JSON_HEADERS });
    }
    if (url.pathname.startsWith("/v2/data/")) {
        const key = decodeURIComponent(url.pathname.slice("/v2/data/".length));
        if (!/^[\w./-]{1,200}$/.test(key) || key.includes("..") || key.startsWith("/") || (key.startsWith("dataStore/") && env.DATASTORE_ENABLED !== "true")) return error(400, "Invalid or disabled key");
        if (request.method === "DELETE") {
            const record = await env.DB.prepare("SELECT object_key FROM sync_data WHERE discord_id = ? AND key = ?").bind(userId, key).first<{ object_key: string }>();
            if (record) await env.BUCKET.delete(record.object_key);
            await env.DB.prepare("DELETE FROM sync_data WHERE discord_id = ? AND key = ?").bind(userId, key).run();
            return new Response(null, { status: 204 });
        }
        if (request.method === "GET") {
            const row = await env.DB.prepare("SELECT object_key,version,checksum FROM sync_data WHERE discord_id = ? AND key = ?").bind(userId, key).first<{ object_key: string; version: number; checksum: string }>();
            if (!row) return new Response(null, { status: 404 });
            if (request.headers.get("if-none-match") === row.checksum) return new Response(null, { status: 304, headers: { etag: row.checksum, "x-version": String(row.version) } });
            const object = await env.BUCKET.get(row.object_key);
            return object ? new Response(object.body, { headers: { "content-type": "application/octet-stream", etag: row.checksum, "x-version": String(row.version), "cache-control": "no-store" } }) : new Response(null, { status: 404 });
        }
        if (request.method === "PUT") {
            const bytes = new Uint8Array(await request.arrayBuffer());
            const max = key.startsWith("dataStore/") ? 10 * 1024 * 1024 : 1024 * 1024;
            if (bytes.length > max) return error(413, "Value too large");
            const sum = hex(await crypto.subtle.digest("SHA-256", bytes)).slice(0, 16);
            const row = await env.DB.prepare("SELECT version FROM sync_data WHERE discord_id = ? AND key = ?").bind(userId, key).first<{ version: number }>();
            const version = (row?.version || 0) + 1;
            const objectKey = `sync/${userId}/${encodeURIComponent(key)}`;
            await env.BUCKET.put(objectKey, bytes, { customMetadata: { discordId: userId, key, checksum: sum } });
            await env.DB.prepare("INSERT INTO sync_data (discord_id,key,object_key,version,checksum,size_bytes,updated_at) VALUES (?,?,?,?,?,?,unixepoch()) ON CONFLICT(discord_id,key) DO UPDATE SET object_key=excluded.object_key,version=excluded.version,checksum=excluded.checksum,size_bytes=excluded.size_bytes,updated_at=unixepoch()").bind(userId, key, objectKey, version, sum, bytes.length).run();
            return Response.json({ version, checksum: sum, updated_at: Date.now() }, { headers: JSON_HEADERS });
        }
    }
    if ((url.pathname === "/v1" || url.pathname === "/v1/") && request.method === "DELETE") {
        const objects = await env.DB.prepare("SELECT object_key FROM sync_data WHERE discord_id = ? UNION SELECT object_key FROM settings WHERE discord_id = ?").bind(userId, userId).all<{ object_key: string }>();
        await Promise.all(objects.results.map(row => env.BUCKET.delete(row.object_key)));
        await env.DB.batch([env.DB.prepare("DELETE FROM settings WHERE discord_id = ?").bind(userId), env.DB.prepare("DELETE FROM sync_data WHERE discord_id = ?").bind(userId), env.DB.prepare("DELETE FROM users WHERE discord_id = ?").bind(userId)]);
        return new Response(null, { status: 204 });
    }
    return error(404, "Not found");
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        if (request.method === "OPTIONS") return cors(request, env, new Response(null, { status: 204 }));
        try { return cors(request, env, await handle(request, env)); }
        catch (e) { console.error("Equicloud Worker request failed", e); return cors(request, env, error(500, "Internal server error")); }
    }
};
