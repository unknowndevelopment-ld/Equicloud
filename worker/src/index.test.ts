import { describe, expect, it } from "vitest";
import worker from "./index";

const env = {
    DISCORD_CLIENT_ID: "client-id",
    DISCORD_CLIENT_SECRET: "client-secret",
    DISCORD_REDIRECT_URI: "https://cloud.example.test/v1/oauth/callback",
    CORS_ALLOWED_ORIGINS: "https://discord.com"
} as any;

describe("Equicloud Worker", () => {
    it("serves an unauthenticated health check", async () => {
        const response = await worker.fetch(new Request("https://cloud.example.test/health"), env);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ status: "ok", service: "equicloud-worker" });
    });

    it("answers allowed CORS preflight requests", async () => {
        const response = await worker.fetch(new Request("https://cloud.example.test/v2/sync", {
            method: "OPTIONS",
            headers: { origin: "https://discord.com" }
        }), env);
        expect(response.status).toBe(204);
        expect(response.headers.get("access-control-allow-origin")).toBe("https://discord.com");
    });

    it("rejects requests from unconfigured origins", async () => {
        const response = await worker.fetch(new Request("https://cloud.example.test/v2/sync", {
            method: "OPTIONS",
            headers: { origin: "https://evil.example" }
        }), env);
        expect(response.status).toBe(204);
        expect(response.headers.has("access-control-allow-origin")).toBe(false);
    });

    it("requires authentication before accessing user data", async () => {
        const response = await worker.fetch(new Request("https://cloud.example.test/v2/manifest"), env);
        expect(response.status).toBe(401);
        expect(await response.json()).toEqual({ error: "Unauthorized" });
    });

    it("returns the Discord OAuth client configuration", async () => {
        const response = await worker.fetch(new Request("https://cloud.example.test/v1/oauth/settings"), env);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({
            clientId: "client-id",
            redirectUri: "https://cloud.example.test/v1/oauth/callback"
        });
    });
});
