import dotenv from "dotenv";
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

dotenv.config();

const SECRET_NAME_ENV = "AWS_SECRETS_MANAGER_SECRET_NAME";
const DEFAULT_SECRET_NAME = "noteshub/production";

let cachedConfig;
let cachedSecretPromise;

const firstDefined = (source, names) => {
  for (const name of names) {
    const value = source[name];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return undefined;
};

const safeSecretError = (error) => {
  const code = error?.name || error?.code;
  if (code === "ResourceNotFoundException") {
    return new Error("The configured AWS Secrets Manager secret was not found");
  }
  if (code === "AccessDeniedException" || code === "UnauthorizedOperation") {
    return new Error("AWS Secrets Manager access was denied");
  }
  if (code === "InvalidRequestException") {
    return new Error("AWS Secrets Manager rejected the secret request");
  }
  if (code === "DecryptionFailure") {
    return new Error("AWS Secrets Manager could not decrypt the secret");
  }
  if (error?.code === "ABORT_ERR" || code === "TimeoutError") {
    return new Error("AWS Secrets Manager request timed out");
  }
  return new Error("Could not load application secrets from AWS Secrets Manager");
};

const validateRequired = (config) => {
  if (!config.mongoUri) throw new Error("Required secret MONGO_URI is missing");
  if (!config.jwtSecret || Buffer.byteLength(config.jwtSecret) < 32) {
    throw new Error("Required secret JWT_SECRET is missing or too short");
  }
};

export const mapSecrets = (stored, env = process.env) => {
  const mongoUri = firstDefined(stored, ["MONGO_URI", "mongo_uri", "mongodbUri", "MONGODB_URI"]);
  const jwtSecret = firstDefined(stored, ["JWT_SECRET", "jwtSecret", "jwt_secret"]);
  const frontendUrl = firstDefined(stored, ["FRONTEND_URL", "frontendUrl", "frontend_url"]);
  const useInMemoryRateLimit =
    env.NODE_ENV !== "production" &&
    env.RATE_LIMIT_STORAGE?.trim().toLowerCase() === "memory";
  const redisUrl = useInMemoryRateLimit
    ? undefined
    : env.NODE_ENV !== "production" && env.REDIS_URL !== undefined
      ? env.REDIS_URL.trim() || undefined
      : firstDefined(stored, ["REDIS_URL", "redisUrl", "redis_url"]);
  const awsRegion = firstDefined(stored, ["AWS_REGION", "awsRegion", "region"]) ||
    process.env.AWS_REGION?.trim() || "ap-south-1";
  const s3Bucket = firstDefined(stored, ["AWS_S3_BUCKET", "awsS3Bucket", "s3Bucket"]);
  const awsAccessKeyId = firstDefined(stored, ["AWS_ACCESS_KEY_ID", "awsAccessKeyId"]);
  const awsSecretAccessKey = firstDefined(stored, ["AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey"]);
  const awsSessionToken = firstDefined(stored, ["AWS_SESSION_TOKEN", "awsSessionToken"]);
  const authEncryptionPrivateKey = firstDefined(stored, [
    "AUTH_ENCRYPTION_PRIVATE_KEY",
    "authEncryptionPrivateKey",
    "AUTH_PAYLOAD_ENCRYPTION_PRIVATE_KEY",
    "authPayloadEncryptionPrivateKey",
    "AUTH_PAYLOAD_PRIVATE_KEY",
    "authPayloadPrivateKey",
    "AUTH_ENCRYPTION_KEY",
    "authEncryptionKey",
    "AUTH_PRIVATE_KEY",
    "authPrivateKey",
    "ENCRYPTION_PRIVATE_KEY",
    "encryptionPrivateKey",
  ]);

  return {
    mongoUri,
    jwtSecret,
    frontendUrl,
    redisUrl,
    awsRegion,
    s3Bucket,
    awsAccessKeyId,
    awsSecretAccessKey,
    awsSessionToken,
    authEncryptionPrivateKey,
    admin: {
      name: firstDefined(stored, ["ADMIN_NAME", "adminName"]),
      email: firstDefined(stored, ["ADMIN_EMAIL", "adminEmail"]),
      password: firstDefined(stored, ["ADMIN_PASSWORD", "adminPassword"]),
      university: firstDefined(stored, ["ADMIN_UNIVERSITY", "adminUniversity"]),
      course: firstDefined(stored, ["ADMIN_COURSE", "adminCourse"]),
      year: firstDefined(stored, ["ADMIN_YEAR", "adminYear"]),
    },
  };
};

const syncCompatibilityEnvironment = (config) => {
  const values = {
    MONGO_URI: config.mongoUri,
    JWT_SECRET: config.jwtSecret,
    FRONTEND_URL: config.frontendUrl,
    REDIS_URL: config.redisUrl,
    AWS_REGION: config.awsRegion,
    AWS_S3_BUCKET: config.s3Bucket,
    AUTH_ENCRYPTION_PRIVATE_KEY: config.authEncryptionPrivateKey,
  };
  for (const [name, value] of Object.entries(values)) {
    if (value !== undefined) process.env[name] = value;
  }
};

export const loadAppSecrets = async () => {
  if (cachedConfig) return cachedConfig;
  if (cachedSecretPromise) return cachedSecretPromise;

  cachedSecretPromise = (async () => {
    const hasLocalRequiredSecrets =
      process.env.NODE_ENV !== "production" &&
      firstDefined(process.env, ["MONGO_URI", "mongoUri", "MONGODB_URI"]) &&
      firstDefined(process.env, ["JWT_SECRET", "jwtSecret", "jwt_secret"]);

    if (hasLocalRequiredSecrets) {
      cachedConfig = mapSecrets(process.env);
      validateRequired(cachedConfig);
      syncCompatibilityEnvironment(cachedConfig);
      return cachedConfig;
    }

    const secretName = process.env[SECRET_NAME_ENV]?.trim() || DEFAULT_SECRET_NAME;
    const region = process.env.AWS_REGION?.trim() || "ap-south-1";
    const client = new SecretsManagerClient({ region, maxAttempts: 3 });
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 10_000);

    try {
      const response = await client.send(
        new GetSecretValueCommand({ SecretId: secretName }),
        { abortSignal: abortController.signal }
      );
      if (!response.SecretString) {
        throw new Error("The configured secret does not contain a text value");
      }
      let stored;
      try {
        stored = JSON.parse(response.SecretString);
      } catch {
        throw new Error("The configured secret contains invalid JSON");
      }
      if (!stored || typeof stored !== "object" || Array.isArray(stored)) {
        throw new Error("The configured secret must contain a JSON object");
      }

      cachedConfig = mapSecrets(stored);
      validateRequired(cachedConfig);
      syncCompatibilityEnvironment(cachedConfig);
      return cachedConfig;
    } catch (error) {
      throw safeSecretError(error);
    } finally {
      clearTimeout(timeout);
      client.destroy();
    }
  })();

  try {
    return await cachedSecretPromise;
  } catch (error) {
    cachedSecretPromise = undefined;
    throw error;
  }
};

export const getAppSecrets = () => {
  if (cachedConfig) return cachedConfig;
  return mapSecrets(process.env);
};
