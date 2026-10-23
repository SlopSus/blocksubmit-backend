import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { Server } from "node:http";
import jwt from "jsonwebtoken";
import { app } from "../src/app";
import { requireRole } from "../src/middleware/auth";

describe("API Route Integration & Security Tests", () => {
  let server: Server;
  let baseUrl: string;
  const testSecret = "test-jwt-secret-for-routes-must-be-long-enough";
  const testInviteCode = "valid-test-professor-invite-code";

  before(() => {
    process.env.JWT_SECRET = testSecret;
    process.env.PROFESSOR_INVITE_CODE = testInviteCode;

    return new Promise((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(() => {
    return new Promise((resolve) => {
      server.close(() => resolve());
    });
  });

  it("GET /api/health returns 200 with service health info", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, "ok");
    assert.strictEqual(body.service, "blocksubmit-backend");
  });

  describe("Registration Security & Privilege Escalation Prevention", () => {
    it("POST /api/auth/register rejects role 'professor' without invite code (403)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Attacker User",
          email: "attacker@blocksubmit.edu",
          password: "password123",
          role: "professor", // Privilege escalation attempt
        }),
      });

      assert.strictEqual(res.status, 403);
      const body = await res.json();
      assert.match(body.message, /professor invite code is required/i);
    });

    it("POST /api/auth/register rejects role 'professor' with incorrect invite code (403)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Attacker User",
          email: "attacker2@blocksubmit.edu",
          password: "password123",
          role: "professor",
          inviteCode: "wrong-invite-code",
        }),
      });

      assert.strictEqual(res.status, 403);
      const body = await res.json();
      assert.match(body.message, /professor invite code is required/i);
    });

    it("POST /api/auth/register rejects password exceeding 72 chars (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Test Student",
          email: "student@blocksubmit.edu",
          password: "A".repeat(73),
          role: "student",
        }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.match(body.message, /between 4 and 72 characters/i);
    });

    it("POST /api/auth/register rejects invalid email (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Test User",
          email: "not-an-email",
          password: "password123",
          role: "student",
        }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.match(body.message, /valid email/i);
    });

    it("POST /api/auth/register rejects password shorter than 4 chars (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Test User",
          email: "valid@blocksubmit.edu",
          password: "12",
          role: "student",
        }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.match(body.message, /between 4 and 72 characters/i);
    });

    it("POST /api/auth/register rejects invalid role (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Test User",
          email: "valid@blocksubmit.edu",
          password: "password123",
          role: "admin",
        }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.match(body.message, /role must be either/i);
    });
  });

  describe("Authentication & Route Protection", () => {
    it("POST /api/auth/login rejects invalid input without querying database (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "bademail",
          password: "short",
        }),
      });

      assert.strictEqual(res.status, 400);
    });

    it("GET /api/auth/me rejects unauthenticated request with 401", async () => {
      const res = await fetch(`${baseUrl}/api/auth/me`);
      assert.strictEqual(res.status, 401);

      const body = await res.json();
      assert.match(body.message, /unauthorized/i);
    });

    it("GET /api/auth/me rejects malformed or tampered token with 401", async () => {
      const res = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: "Bearer malformed.invalid.token" },
      });
      assert.strictEqual(res.status, 401);

      const body = await res.json();
      assert.match(body.message, /token expired or invalid/i);
    });

    it("GET /api/assignments rejects unauthenticated request with 401", async () => {
      const res = await fetch(`${baseUrl}/api/assignments`);
      assert.strictEqual(res.status, 401);
    });

    it("POST /api/assignments rejects unauthenticated request with 401", async () => {
      const res = await fetch(`${baseUrl}/api/assignments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "Test Assignment",
          description: "Valid description",
          deadline: new Date(Date.now() + 86400000).toISOString(),
        }),
      });

      assert.strictEqual(res.status, 401);
    });

    it("404 handler responds for unknown api route", async () => {
      const res = await fetch(`${baseUrl}/api/some/unknown/route`);
      assert.strictEqual(res.status, 404);
    });
  });

  describe("Role Authorization Guard (requireRole)", () => {
    it("requireRole('professor') rejects student user with 403 Forbidden", () => {
      let statusCode = 0;
      let jsonBody: any = null;
      let nextCalled = false;

      const req = { user: { role: "student" } } as any;
      const res = {
        status: (code: number) => {
          statusCode = code;
          return {
            json: (body: any) => {
              jsonBody = body;
            },
          };
        },
      } as any;
      const next = () => {
        nextCalled = true;
      };

      requireRole("professor")(req, res, next);
      assert.strictEqual(statusCode, 403);
      assert.match(jsonBody.message, /requires the professor role/i);
      assert.strictEqual(nextCalled, false);
    });

    it("requireRole('professor') allows professor user to proceed", () => {
      let nextCalled = false;
      const req = { user: { role: "professor" } } as any;
      const res = {} as any;
      const next = () => {
        nextCalled = true;
      };

      requireRole("professor")(req, res, next);
      assert.strictEqual(nextCalled, true);
    });

    it("requireRole('student') rejects professor user with 403 Forbidden", () => {
      let statusCode = 0;
      const req = { user: { role: "professor" } } as any;
      const res = {
        status: (code: number) => {
          statusCode = code;
          return { json: () => {} };
        },
      } as any;

      requireRole("student")(req, res, () => {});
      assert.strictEqual(statusCode, 403);
    });

    it("requireRole rejects unauthenticated user with 401", () => {
      let statusCode = 0;
      const req = {} as any;
      const res = {
        status: (code: number) => {
          statusCode = code;
          return { json: () => {} };
        },
      } as any;

      requireRole("professor")(req, res, () => {});
      assert.strictEqual(statusCode, 401);
    });
  });

  describe("CORS Security & Preflight Configuration", () => {
    it("handles preflight OPTIONS request for frontend origin http://localhost:8080", async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "OPTIONS",
        headers: {
          "Origin": "http://localhost:8080",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "Content-Type",
        },
      });

      assert.strictEqual(res.status, 204);
      assert.strictEqual(res.headers.get("access-control-allow-origin"), "http://localhost:8080");
      assert.strictEqual(res.headers.get("access-control-allow-credentials"), "true");
      assert.match(res.headers.get("access-control-allow-methods") || "", /POST/);
    });

    it("handles preflight OPTIONS request for legacy frontend origin http://localhost:3000", async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "OPTIONS",
        headers: {
          "Origin": "http://localhost:3000",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "Content-Type",
        },
      });

      assert.strictEqual(res.status, 204);
      assert.strictEqual(res.headers.get("access-control-allow-origin"), "http://localhost:3000");
      assert.strictEqual(res.headers.get("access-control-allow-credentials"), "true");
    });

    it("dynamically respects FRONTEND_URL environment variable", async () => {
      const original = process.env.FRONTEND_URL;
      try {
        process.env.FRONTEND_URL = "http://custom-frontend.internal:9000";
        const res = await fetch(`${baseUrl}/api/auth/login`, {
          method: "OPTIONS",
          headers: {
            "Origin": "http://custom-frontend.internal:9000",
            "Access-Control-Request-Method": "POST",
          },
        });

        assert.strictEqual(res.status, 204);
        assert.strictEqual(
          res.headers.get("access-control-allow-origin"),
          "http://custom-frontend.internal:9000"
        );
        assert.strictEqual(res.headers.get("access-control-allow-credentials"), "true");
      } finally {
        if (original === undefined) {
          delete process.env.FRONTEND_URL;
        } else {
          process.env.FRONTEND_URL = original;
        }
      }
    });

    it("rejects unauthorized origins by omitting Access-Control-Allow-Origin", async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "OPTIONS",
        headers: {
          "Origin": "http://malicious-site.evil",
          "Access-Control-Request-Method": "POST",
        },
      });

      assert.strictEqual(res.headers.get("access-control-allow-origin"), null);
    });
  });
});
