import { createHmac } from "node:crypto";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { createClient } from "redis";
import { logError, logInfo } from "../utils/logger.js";
import {
  hasNoteSearchCriteria,
  isDedicatedRateLimitRequest,
  isPublicNotesListRequest,
} from "../utils/rateLimitPolicy.js";

dotenv.config();

const readPositiveInteger = (name, fallback) => {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") return fallback;
  if (!/^\d+$/.test(value.trim())) {
    throw new Error(`${name} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
};

const policy = (name, defaultWindowMs, defaultLimit) => ({
  windowMs: readPositiveInteger(`RATE_LIMIT_${name}_WINDOW_MS`, defaultWindowMs),
  limit: readPositiveInteger(`RATE_LIMIT_${name}_MAX`, defaultLimit),
});

export const rateLimitPolicies = Object.freeze({
  generalApi: policy("GENERAL", 60_000, 100),
  loginIp: policy("LOGIN_IP", 60_000, 5),
  loginAccount: policy("LOGIN_ACCOUNT", 15 * 60_000, 5),
  signup: policy("SIGNUP", 60_000, 5),
  passwordChange: policy("PASSWORD_CHANGE", 15 * 60_000, 3),
  forgotPassword: policy("FORGOT_PASSWORD", 15 * 60_000, 3),
  otpVerification: policy("OTP_VERIFICATION", 10 * 60_000, 5),
  notesUpload: policy("NOTES_UPLOAD", 10 * 60_000, 10),
  notesSearch: policy("NOTES_SEARCH", 60_000, 30),
  publicNotesList: policy("PUBLIC_NOTES_LIST", 60_000, 60),
});

const redisUrl = process.env.REDIS_URL?.trim();
const redisClient = redisUrl ? createClient({ url: redisUrl }) : undefined;
if (redisClient) {
  redisClient.on("error", () => {
    logError("rate_limit.redis_connection_error");
  });
}

const sendRedisCommand = async (...args) => {
  try {
    return await redisClient.sendCommand(args);
  } catch (cause) {
    const error = new Error("Shared rate-limit storage is unavailable", { cause });
    error.code = "RATE_LIMIT_STORE_UNAVAILABLE";
    throw error;
  }
};

export const initializeRateLimitStore = async () => {
  if (process.env.NODE_ENV === "production" && !redisClient) {
    const error = new Error("REDIS_URL is required in production for shared rate limits");
    error.code = "RATE_LIMIT_REDIS_URL_MISSING";
    throw error;
  }
  if (redisClient && !redisClient.isOpen) {
    try {
      await redisClient.connect();
    } catch (cause) {
      const error = new Error("Could not connect to the configured shared rate-limit store", {
        cause,
      });
      error.code = "RATE_LIMIT_REDIS_CONNECTION_FAILED";
      throw error;
    }
    logInfo("rate_limit.redis_connected");
  }
};

const retryAfterSeconds = (req, windowMs) => {
  const resetTime = req.rateLimit?.resetTime;
  if (resetTime instanceof Date) {
    return Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
  }
  return Math.max(1, Math.ceil(windowMs / 1000));
};

const createRateLimiter = (name, settings, options = {}) =>
  rateLimit({
    windowMs: settings.windowMs,
    limit: settings.limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    passOnStoreError: false,
    ...(redisClient
      ? {
          store: new RedisStore({
            prefix: `noteshub:rate-limit:${name}:`,
            sendCommand: sendRedisCommand,
          }),
        }
      : {}),
    ...options,
    handler: (req, res) => {
      const seconds = retryAfterSeconds(req, settings.windowMs);
      const unit = seconds === 1 ? "second" : "seconds";
      logInfo(`rate_limit.exceeded.${name}`);
      res.setHeader("Retry-After", String(seconds));
      res.status(429).json({
        message: `Too many requests. Please try again in ${seconds} ${unit}.`,
        retryAfterSeconds: seconds,
      });
    },
  });

const getNormalizedAccountIdentifier = (value) =>
  typeof value === "string" ? value.trim().toLowerCase() : "";

export const loginAccountKey = (req) => {
  const identifier = getNormalizedAccountIdentifier(req.body?.email);
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is required to derive the login rate-limit key");
  }
  return `account:${createHmac("sha256", process.env.JWT_SECRET).update(identifier).digest("hex")}`;
};

export const generalApiLimiter = createRateLimiter("general", rateLimitPolicies.generalApi, {
  skip: isDedicatedRateLimitRequest,
});

export const loginIpLimiter = createRateLimiter("login-ip", rateLimitPolicies.loginIp);
export const loginAccountLimiter = createRateLimiter(
  "login-account",
  rateLimitPolicies.loginAccount,
  {
    keyGenerator: loginAccountKey,
    skip: (req) => !getNormalizedAccountIdentifier(req.body?.email),
    skipSuccessfulRequests: true,
    requestWasSuccessful: (_req, res) => res.statusCode !== 401,
  }
);
export const signupLimiter = createRateLimiter("signup", rateLimitPolicies.signup);
export const passwordChangeLimiter = createRateLimiter(
  "password-change",
  rateLimitPolicies.passwordChange
);
export const forgotPasswordLimiter = createRateLimiter(
  "forgot-password",
  rateLimitPolicies.forgotPassword
);
export const otpVerificationLimiter = createRateLimiter(
  "otp-verification",
  rateLimitPolicies.otpVerification
);
export const notesUploadLimiter = createRateLimiter(
  "notes-upload",
  rateLimitPolicies.notesUpload
);
export const notesSearchLimiter = createRateLimiter(
  "notes-search",
  rateLimitPolicies.notesSearch,
  { skip: (req) => !hasNoteSearchCriteria(req) }
);
export const publicNotesListLimiter = createRateLimiter(
  "public-notes-list",
  rateLimitPolicies.publicNotesList,
  { skip: (req) => hasNoteSearchCriteria(req) }
);
