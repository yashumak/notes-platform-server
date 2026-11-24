import assert from "node:assert/strict";
import test from "node:test";
import { mapSecrets } from "../config/secrets.js";

test("local REDIS_URL can explicitly disable remote shared Redis", () => {
  const config = mapSecrets(
    { REDIS_URL: "redis://remote.example.test" },
    { NODE_ENV: "development", REDIS_URL: "" }
  );
  assert.equal(config.redisUrl, undefined);
});

test("local memory rate limiting ignores Redis configured in the secret", () => {
  const config = mapSecrets(
    { REDIS_URL: "redis://remote.example.test" },
    { NODE_ENV: "development", RATE_LIMIT_STORAGE: "memory" }
  );
  assert.equal(config.redisUrl, undefined);
});

test("production Redis URL always comes from the secret", () => {
  const config = mapSecrets(
    { REDIS_URL: "redis://production.example.test" },
    { NODE_ENV: "production", REDIS_URL: "", RATE_LIMIT_STORAGE: "memory" }
  );
  assert.equal(config.redisUrl, "redis://production.example.test");
});
