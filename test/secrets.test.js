import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  MAIN_BACKEND_REQUIRED_PRODUCTION_KEYS,
  PRODUCTION_SECRET_ID,
  SecretsLoadError,
  createSecretsLoader,
} from "../config/secrets.js";

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const productionSecret = {
  MONGO_URI: "mongodb://user:secret-password@db.example.test/noteshub",
  JWT_SECRET: "test-jwt-secret-that-is-long-enough-for-tests",
  AUTH_ENCRYPTION_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----",
  REDIS_URL: "rediss://default:redis-password@redis.example.test:6379",
  AWS_S3_BUCKET: "notes-test-bucket",
  MAX_NOTE_FILE_SIZE_BYTES: 5242880,
  AWS_ACCESS_KEY_ID: "secret-store-access-key",
  AWS_SECRET_ACCESS_KEY: "secret-store-secret-key",
  ADMIN_PASSWORD: "unrelated-admin-password",
  UNRELATED_SERVICE_TOKEN: "unrelated-token",
};

const NO_SECRET_STRING = Symbol("no SecretString");

const createFakeClient = (secretString = JSON.stringify(productionSecret)) => {
  const calls = [];
  return {
    calls,
    send: async (command) => {
      calls.push(command.input);
      if (secretString instanceof Error) throw secretString;
      return secretString === NO_SECRET_STRING ? {} : { SecretString: secretString };
    },
  };
};

const createLoader = (client, options = {}) => {
  const regions = [];
  const logs = [];
  const loader = createSecretsLoader({
    createClient: (region) => {
      regions.push(region);
      return client;
    },
    log: (event, context) => logs.push({ event, context }),
    ...options,
  });
  return { loader, regions, logs };
};

test("non-production startup uses local environment values without contacting AWS", async () => {
  const client = createFakeClient();
  const { loader, regions } = createLoader(client);
  const env = { NODE_ENV: "development", JWT_SECRET: "local-value" };

  const result = await loader.load({ env });

  assert.equal(result.source, "environment");
  assert.equal(client.calls.length, 0);
  assert.deepEqual(regions, []);
  assert.deepEqual(env, { NODE_ENV: "development", JWT_SECRET: "local-value" });
});

test("production loads only Main Backend keys from noteshub/production in ap-south-1", async () => {
  const client = createFakeClient();
  const { loader, regions, logs } = createLoader(client);
  const env = { NODE_ENV: "production" };

  const result = await loader.load({ env });

  assert.deepEqual(client.calls, [{ SecretId: PRODUCTION_SECRET_ID }]);
  assert.equal(PRODUCTION_SECRET_ID, "noteshub/production");
  assert.deepEqual(regions, ["ap-south-1"]);
  assert.equal(env.MONGO_URI, productionSecret.MONGO_URI);
  assert.equal(env.JWT_SECRET, productionSecret.JWT_SECRET);
  assert.equal(env.MAX_NOTE_FILE_SIZE_BYTES, "5242880");
  assert.equal(env.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.ADMIN_PASSWORD, undefined);
  assert.equal(env.UNRELATED_SERVICE_TOKEN, undefined);
  assert.ok(result.loadedKeys.includes("JWT_SECRET"));

  const serializedLogs = JSON.stringify(logs);
  for (const value of Object.values(productionSecret)) {
    assert.equal(serializedLogs.includes(String(value)), false);
  }
});

test("already supplied environment values are not overwritten", async () => {
  const client = createFakeClient();
  const { loader } = createLoader(client);
  const env = {
    NODE_ENV: "production",
    AWS_REGION: "eu-west-1",
    AWS_S3_BUCKET: "deployment-bucket",
  };

  const result = await loader.load({ env });

  assert.equal(env.AWS_S3_BUCKET, "deployment-bucket");
  assert.deepEqual(result.skippedKeys, ["AWS_S3_BUCKET"]);
});

test("the configured AWS_REGION selects the Secrets Manager region", async () => {
  const client = createFakeClient();
  const { loader, regions } = createLoader(client);

  await loader.load({ env: { NODE_ENV: "production", AWS_REGION: "eu-west-1" } });

  assert.deepEqual(regions, ["eu-west-1"]);
});

test("secrets are retrieved once and cached, including concurrent loads", async () => {
  const client = createFakeClient();
  const { loader, regions } = createLoader(client);

  await Promise.all([
    loader.load({ env: { NODE_ENV: "production" } }),
    loader.load({ env: { NODE_ENV: "production" } }),
  ]);
  await loader.load({ env: { NODE_ENV: "production" } });

  assert.equal(client.calls.length, 1);
  assert.equal(regions.length, 1);
});

test("missing required production keys fail safely without exposing values", async () => {
  const { MONGO_URI: _omitted, ...partialSecret } = productionSecret;
  const client = createFakeClient(JSON.stringify(partialSecret));
  const { loader } = createLoader(client);

  await assert.rejects(loader.load({ env: { NODE_ENV: "production" } }), (error) => {
    assert.ok(error instanceof SecretsLoadError);
    assert.equal(error.code, "SECRETS_REQUIRED_MISSING");
    assert.deepEqual(error.missingKeys, ["MONGO_URI"]);
    assert.equal(JSON.stringify(error).includes(productionSecret.JWT_SECRET), false);
    return true;
  });
  assert.ok(MAIN_BACKEND_REQUIRED_PRODUCTION_KEYS.includes("MONGO_URI"));
});

test("invalid JSON and empty secrets fail without echoing the secret value", async () => {
  const invalidSecret = "{\"JWT_SECRET\": \"leaked-value\"";
  for (const [secretString, code] of [
    [invalidSecret, "SECRETS_INVALID_JSON"],
    ["[\"not-an-object\"]", "SECRETS_INVALID_JSON"],
    ["", "SECRETS_EMPTY"],
    [NO_SECRET_STRING, "SECRETS_EMPTY"],
  ]) {
    const { loader } = createLoader(createFakeClient(secretString));
    await assert.rejects(loader.load({ env: { NODE_ENV: "production" } }), (error) => {
      assert.equal(error.code, code);
      assert.equal(`${error.message} ${JSON.stringify(error)}`.includes("leaked-value"), false);
      return true;
    });
  }
});

test("non-scalar secret values are rejected by key name only", async () => {
  const client = createFakeClient(JSON.stringify({ ...productionSecret, REDIS_URL: { url: "x" } }));
  const { loader } = createLoader(client);

  await assert.rejects(loader.load({ env: { NODE_ENV: "production" } }), (error) => {
    assert.equal(error.code, "SECRETS_INVALID_VALUE");
    assert.deepEqual(error.invalidKeys, ["REDIS_URL"]);
    return true;
  });
});

test("AWS errors are reduced to their error name and can be retried", async () => {
  const awsError = Object.assign(
    new Error("User arn:aws:iam::123456789012:user/x is not authorized"),
    { name: "AccessDeniedException" }
  );
  const failingClient = createFakeClient(awsError);
  const { loader } = createLoader(failingClient);

  await assert.rejects(loader.load({ env: { NODE_ENV: "production" } }), (error) => {
    assert.equal(error.code, "SECRETS_FETCH_FAILED");
    assert.equal(error.errorName, "AccessDeniedException");
    assert.equal(`${error.message} ${JSON.stringify(error)}`.includes("123456789012"), false);
    return true;
  });
  assert.equal(failingClient.calls.length, 1);

  await assert.rejects(loader.load({ env: { NODE_ENV: "production" } }));
  assert.equal(failingClient.calls.length, 2);
});

test("production startup exits before initializing services when secrets cannot be loaded", () => {
  const result = spawnSync(process.execPath, ["index.js"], {
    cwd: backendRoot,
    env: {
      PATH: process.env.PATH,
      NODE_ENV: "production",
      DOTENV_CONFIG_PATH: path.join(backendRoot, "test", "nonexistent.env"),
      AWS_EC2_METADATA_DISABLED: "true",
      AWS_CONFIG_FILE: path.join(backendRoot, "test", "nonexistent-aws-config"),
      AWS_SHARED_CREDENTIALS_FILE: path.join(backendRoot, "test", "nonexistent-aws-credentials"),
      JWT_SECRET: "startup-test-jwt-secret-value-long-enough",
    },
    encoding: "utf8",
    timeout: 30_000,
  });

  assert.equal(result.status, 1);
  const output = `${result.stdout}${result.stderr}`;
  assert.match(output, /startup\.secrets_load_failed/);
  assert.match(output, /SECRETS_FETCH_FAILED/);
  assert.doesNotMatch(output, /server\.started|database\.connected/);
  assert.equal(output.includes("startup-test-jwt-secret-value-long-enough"), false);
});
