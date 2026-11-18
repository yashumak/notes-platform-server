import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { logError, logInfo } from "../utils/logger.js";

export const PRODUCTION_SECRET_ID = "noteshub/production";
export const DEFAULT_SECRETS_REGION = "ap-south-1";

const RATE_LIMIT_POLICIES = [
  "GENERAL",
  "LOGIN_IP",
  "LOGIN_ACCOUNT",
  "SIGNUP",
  "PASSWORD_CHANGE",
  "FORGOT_PASSWORD",
  "OTP_VERIFICATION",
  "NOTES_UPLOAD",
  "NOTES_SEARCH",
  "PUBLIC_NOTES_LIST",
];

// Only variables the Main Backend reads at runtime are copied from the shared secret.
// AWS credentials are intentionally excluded: they are needed to read the secret itself.
export const MAIN_BACKEND_SECRET_KEYS = Object.freeze([
  "MONGO_URI",
  "JWT_SECRET",
  "AUTH_ENCRYPTION_PRIVATE_KEY",
  "REDIS_URL",
  "AWS_S3_BUCKET",
  "AWS_REGION",
  "FRONTEND_URL",
  "TRUST_PROXY_HOPS",
  "MAX_NOTE_FILE_SIZE_BYTES",
  ...RATE_LIMIT_POLICIES.flatMap((name) => [
    `RATE_LIMIT_${name}_WINDOW_MS`,
    `RATE_LIMIT_${name}_MAX`,
  ]),
]);

export const MAIN_BACKEND_REQUIRED_PRODUCTION_KEYS = Object.freeze([
  "MONGO_URI",
  "JWT_SECRET",
  "AUTH_ENCRYPTION_PRIVATE_KEY",
  "REDIS_URL",
  "AWS_S3_BUCKET",
]);

export class SecretsLoadError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SecretsLoadError";
    this.code = code;
    Object.assign(this, details);
  }
}

const hasValue = (value) => typeof value === "string" && value.trim() !== "";

const toEnvironmentValue = (value) => {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return String(value);
  return undefined;
};

const parseSecretString = (secretString) => {
  if (!hasValue(secretString)) {
    throw new SecretsLoadError("SECRETS_EMPTY", "The secret has no SecretString value");
  }
  let parsed;
  try {
    parsed = JSON.parse(secretString);
  } catch {
    throw new SecretsLoadError("SECRETS_INVALID_JSON", "The secret value is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SecretsLoadError(
      "SECRETS_INVALID_JSON",
      "The secret value must be a JSON object of key/value pairs"
    );
  }
  return parsed;
};

export const createSecretsLoader = ({
  secretId = PRODUCTION_SECRET_ID,
  allowedKeys = MAIN_BACKEND_SECRET_KEYS,
  requiredKeys = MAIN_BACKEND_REQUIRED_PRODUCTION_KEYS,
  createClient = (region) => new SecretsManagerClient({ region }),
  log = logInfo,
} = {}) => {
  let client;
  let cachedValues;
  let pendingFetch;

  const fetchSecretValues = async (region) => {
    if (cachedValues) return cachedValues;
    if (!pendingFetch) {
      pendingFetch = (async () => {
        client ??= createClient(region);
        let response;
        try {
          response = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
        } catch (cause) {
          throw new SecretsLoadError(
            "SECRETS_FETCH_FAILED",
            "Could not retrieve the configured secret from AWS Secrets Manager",
            { errorName: typeof cause?.name === "string" ? cause.name : "UnknownError" }
          );
        }
        const parsed = parseSecretString(response?.SecretString);
        const values = {};
        const invalidKeys = [];
        for (const key of allowedKeys) {
          if (!Object.hasOwn(parsed, key)) continue;
          const value = toEnvironmentValue(parsed[key]);
          if (value === undefined) invalidKeys.push(key);
          else values[key] = value;
        }
        if (invalidKeys.length > 0) {
          throw new SecretsLoadError(
            "SECRETS_INVALID_VALUE",
            "Some secret keys do not contain string, number, or boolean values",
            { invalidKeys }
          );
        }
        cachedValues = Object.freeze(values);
        return cachedValues;
      })().finally(() => {
        pendingFetch = undefined;
      });
    }
    return pendingFetch;
  };

  const load = async ({ env = process.env, enabled = env.NODE_ENV === "production" } = {}) => {
    if (!enabled) return { source: "environment", loadedKeys: [], skippedKeys: [] };

    const region = env.AWS_REGION?.trim() || DEFAULT_SECRETS_REGION;
    const values = await fetchSecretValues(region);
    const loadedKeys = [];
    const skippedKeys = [];
    for (const [key, value] of Object.entries(values)) {
      if (hasValue(env[key])) {
        skippedKeys.push(key);
        continue;
      }
      env[key] = value;
      loadedKeys.push(key);
    }

    const missingKeys = requiredKeys.filter((key) => !hasValue(env[key]));
    if (missingKeys.length > 0) {
      throw new SecretsLoadError(
        "SECRETS_REQUIRED_MISSING",
        "Required production configuration is missing",
        { missingKeys }
      );
    }

    log("secrets.loaded", { source: "aws-secrets-manager", loadedKeys, skippedKeys });
    return { source: "aws-secrets-manager", loadedKeys, skippedKeys };
  };

  return { load };
};

const defaultLoader = createSecretsLoader();

export const loadRuntimeSecrets = (options) => defaultLoader.load(options);

export const loadRuntimeSecretsOrExit = async (options) => {
  try {
    return await loadRuntimeSecrets(options);
  } catch (error) {
    logError("startup.secrets_load_failed", {
      code: error?.code || "SECRETS_LOAD_FAILED",
      ...(error?.errorName ? { errorName: error.errorName } : {}),
      ...(error?.missingKeys ? { missingKeys: error.missingKeys } : {}),
      ...(error?.invalidKeys ? { invalidKeys: error.invalidKeys } : {}),
    });
    process.exit(1);
  }
};
