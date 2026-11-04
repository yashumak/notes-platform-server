import assert from "node:assert/strict";
import express from "express";
import test, { after } from "node:test";

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-only-rate-limit-secret-long-enough";
process.env.REDIS_URL = "";
process.env.RATE_LIMIT_LOGIN_IP_WINDOW_MS = "60000";
process.env.RATE_LIMIT_LOGIN_IP_MAX = "2";
process.env.RATE_LIMIT_LOGIN_ACCOUNT_WINDOW_MS = "1500";
process.env.RATE_LIMIT_LOGIN_ACCOUNT_MAX = "2";
process.env.RATE_LIMIT_SIGNUP_WINDOW_MS = "60000";
process.env.RATE_LIMIT_SIGNUP_MAX = "2";
process.env.RATE_LIMIT_PASSWORD_CHANGE_WINDOW_MS = "60000";
process.env.RATE_LIMIT_PASSWORD_CHANGE_MAX = "2";
process.env.RATE_LIMIT_NOTES_UPLOAD_WINDOW_MS = "60000";
process.env.RATE_LIMIT_NOTES_UPLOAD_MAX = "2";
process.env.RATE_LIMIT_NOTES_SEARCH_WINDOW_MS = "60000";
process.env.RATE_LIMIT_NOTES_SEARCH_MAX = "2";
process.env.RATE_LIMIT_PUBLIC_NOTES_LIST_WINDOW_MS = "60000";
process.env.RATE_LIMIT_PUBLIC_NOTES_LIST_MAX = "2";
process.env.RATE_LIMIT_GENERAL_WINDOW_MS = "60000";
process.env.RATE_LIMIT_GENERAL_MAX = "2";
process.env.RATE_LIMIT_FORGOT_PASSWORD_WINDOW_MS = "900000";
process.env.RATE_LIMIT_FORGOT_PASSWORD_MAX = "3";
process.env.RATE_LIMIT_OTP_VERIFICATION_WINDOW_MS = "600000";
process.env.RATE_LIMIT_OTP_VERIFICATION_MAX = "5";

const {
  generalApiLimiter,
  loginAccountLimiter,
  loginIpLimiter,
  initializeRateLimitStore,
  notesSearchLimiter,
  notesUploadLimiter,
  passwordChangeLimiter,
  publicNotesListLimiter,
  rateLimitPolicies,
  signupLimiter,
} = await import("../middlewares/rateLimiters.js");
const { isDedicatedRateLimitRequest } = await import("../utils/rateLimitPolicy.js");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use("/api", generalApiLimiter);
app.post("/api/auth/login", loginIpLimiter, loginAccountLimiter, (req, res) =>
  res.status(req.body.status || 401).json({ message: "login result" })
);
app.post("/api/auth/register", signupLimiter, (_req, res) => res.status(201).json({ success: true }));
app.post("/api/auth/change-password", passwordChangeLimiter, (_req, res) =>
  res.json({ success: true })
);
app.post("/api/notes/upload/presign", notesUploadLimiter, (_req, res) =>
  res.status(201).json({ success: true })
);
app.get("/api/notes", notesSearchLimiter, publicNotesListLimiter, (_req, res) =>
  res.json({ success: true })
);
app.get("/api/notes/stats", (_req, res) => res.json({ success: true }));

const server = app.listen(0);
after(() => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
}));

const request = async (path, { ip, method = "GET", body } = {}) => {
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return fetch(`http://127.0.0.1:${address.port}${path}`, {
    method,
    headers: {
      "x-forwarded-for": ip,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
};

test("login limits are isolated by IP and normalized account, and successes do not count", async () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await request("/api/auth/login", {
      ip: "198.51.100.10",
      method: "POST",
      body: { email: `ip-attempt-${attempt}@example.com` },
    });
    assert.equal(response.status, 401);
  }
  const blockedIp = await request("/api/auth/login", {
    ip: "198.51.100.10",
    method: "POST",
    body: { email: "another-account@example.com" },
  });
  assert.equal(blockedIp.status, 429);
  assert.ok(Number(blockedIp.headers.get("retry-after")) > 0);

  const otherIp = await request("/api/auth/login", {
    ip: "198.51.100.11",
    method: "POST",
    body: { email: "another-account@example.com" },
  });
  assert.equal(otherIp.status, 401);

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const response = await request("/api/auth/login", {
      ip: `198.51.100.${20 + attempt}`,
      method: "POST",
      body: { email: "Success@example.com", status: 200 },
    });
    assert.equal(response.status, 200);
  }
  for (const email of ["Success@example.com", " success@example.com "]) {
    const response = await request("/api/auth/login", {
      ip: `198.51.100.${30 + (email.startsWith(" ") ? 1 : 0)}`,
      method: "POST",
      body: { email },
    });
    assert.equal(response.status, 401);
  }
  const blockedAccount = await request("/api/auth/login", {
    ip: "198.51.100.32",
    method: "POST",
    body: { email: "SUCCESS@example.com" },
  });
  assert.equal(blockedAccount.status, 429);
  const payload = await blockedAccount.json();
  assert.equal(payload.retryAfterSeconds, Number(blockedAccount.headers.get("retry-after")));
  assert.match(payload.message, /try again in/i);

  await new Promise((resolve) => setTimeout(resolve, 1550));
  const resetAccount = await request("/api/auth/login", {
    ip: "198.51.100.32",
    method: "POST",
    body: { email: "success@example.com" },
  });
  assert.equal(resetAccount.status, 401);
});

test("signup, uploads, notes search, listing, and general APIs have independent limits", async () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assert.equal(
      (await request("/api/auth/register", {
        ip: "198.51.100.40",
        method: "POST",
      })).status,
      201
    );
    assert.equal(
      (await request("/api/notes/upload/presign", {
        ip: "198.51.100.41",
        method: "POST",
      })).status,
      201
    );
    assert.equal(
      (await request("/api/auth/change-password", {
        ip: "198.51.100.45",
        method: "POST",
      })).status,
      200
    );
    assert.equal((await request("/api/notes?q=course", { ip: "198.51.100.42" })).status, 200);
    assert.equal((await request("/api/notes", { ip: "198.51.100.43" })).status, 200);
    assert.equal((await request("/api/notes/stats", { ip: "198.51.100.44" })).status, 200);
  }

  for (const [path, ip] of [
    ["/api/auth/register", "198.51.100.40"],
    ["/api/auth/change-password", "198.51.100.45"],
    ["/api/notes/upload/presign", "198.51.100.41"],
    ["/api/notes?q=course", "198.51.100.42"],
    ["/api/notes", "198.51.100.43"],
    ["/api/notes/stats", "198.51.100.44"],
  ]) {
    const response = await request(path, {
      ip,
      method:
        path.includes("/register") ||
        path.includes("/presign") ||
        path.includes("/change-password")
          ? "POST"
          : "GET",
    });
    assert.equal(response.status, 429, `${path} should enforce its limit`);
  }

  assert.equal((await request("/api/notes?q=course", { ip: "198.51.100.43" })).status, 200);
  assert.equal((await request("/api/notes", { ip: "198.51.100.42" })).status, 200);
  assert.equal((await request("/api/notes/stats", { ip: "198.51.100.46" })).status, 200);
});

test("configured future reset policies and API exemptions are explicit", () => {
  assert.deepEqual(rateLimitPolicies.forgotPassword, { windowMs: 900000, limit: 3 });
  assert.deepEqual(rateLimitPolicies.otpVerification, { windowMs: 600000, limit: 5 });
  assert.equal(isDedicatedRateLimitRequest({
    method: "POST",
    originalUrl: "/api/auth/login",
  }), true);
  assert.equal(isDedicatedRateLimitRequest({
    method: "GET",
    originalUrl: "/api/notes/stats",
  }), false);
  assert.equal(isDedicatedRateLimitRequest({
    method: "GET",
    originalUrl: "/api/notes",
  }), true);
});

test("production refuses to run per-instance memory limits when Redis is missing", async () => {
  process.env.NODE_ENV = "production";
  await assert.rejects(
    initializeRateLimitStore(),
    /REDIS_URL is required in production/
  );
  process.env.NODE_ENV = "test";
});
