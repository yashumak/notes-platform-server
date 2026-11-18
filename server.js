// Loaded by index.js after local .env values and production secrets are applied.
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import { logError, logInfo } from "./utils/logger.js";
import { initializeAuthPayloadEncryption } from "./utils/authPayloadEncryption.js";
import { apiRequestLogger } from "./middlewares/apiRequestLogger.js";
import { requireHttps } from "./middlewares/requireHttps.js";
import {
  generalApiLimiter,
  initializeRateLimitStore,
} from "./middlewares/rateLimiters.js";

// Routes
import authRoutes from "./routes/auth.routes.js";
import notesRoutes from "./routes/notes.routes.js";
import adminRoutes from "./routes/admin.routes.js";

// DB
import connectDB from "./config/db.js";

const app = express();
const PORT = process.env.PORT || 5000;

const configuredProxyHops = process.env.TRUST_PROXY_HOPS?.trim();
const trustedProxyHops = configuredProxyHops ? Number(configuredProxyHops) : 1;
if (!Number.isSafeInteger(trustedProxyHops) || trustedProxyHops < 0) {
  logError("startup.trust_proxy_hops_invalid");
  process.exit(1);
}
app.set("trust proxy", trustedProxyHops);

app.use(requireHttps);

if (!process.env.JWT_SECRET || Buffer.byteLength(process.env.JWT_SECRET) < 32) {
  logError("startup.jwt_secret_missing_or_weak");
  process.exit(1);
}

try {
  initializeAuthPayloadEncryption();
} catch {
  logError("startup.auth_encryption_key_invalid_or_missing");
  process.exit(1);
}

// ------------------ DATABASE ------------------
connectDB();

// ------------------ MIDDLEWARE ------------------
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(helmet());
app.use("/api", apiRequestLogger);
app.use("/api", generalApiLimiter);
app.use(express.json());
app.use(cookieParser());

// ------------------ ROUTES ------------------
app.use("/api/auth", authRoutes);
app.use("/api/notes", notesRoutes);
app.use("/api/admin", adminRoutes);

app.use((_req, res) => {
  res.status(404).json({ message: "Not found" });
});

// ------------------ ERROR HANDLER ------------------
app.use((err, _req, res, _next) => {
  if (err.code === "RATE_LIMIT_STORE_UNAVAILABLE") {
    logError("rate_limit.store_request_failed");
    return res.status(503).json({
      message: "Rate limiting is temporarily unavailable. Please try again later.",
    });
  }
  const isBodyParserError = [
    "entity.parse.failed",
    "entity.too.large",
    "encoding.unsupported",
    "charset.unsupported",
  ].includes(err.type);
  const parserStatus = isBodyParserError && [400, 413, 415].includes(err.status)
    ? err.status
    : undefined;
  const status = err.code === "LIMIT_FILE_SIZE" || parserStatus === 413 ? 413 : 500;
  const isUploadInputError =
    err.code === "LIMIT_FILE_SIZE" ||
    err.code === "LIMIT_FIELD_VALUE" ||
    err.message === "Unsupported file type";
  const responseStatus = isUploadInputError
    ? (status === 413 ? 413 : 400)
    : parserStatus || status;
  logError(
    responseStatus === 413
      ? "request.upload_too_large"
      : isUploadInputError
        ? "request.upload_rejected"
        : responseStatus === 400
          ? "request.invalid_body"
          : responseStatus === 415
            ? "request.unsupported_content_type"
            : "request.failed"
  );
  res.status(responseStatus).json({
    message: responseStatus === 413
      ? "Uploaded file or request exceeds the allowed size"
      : responseStatus === 400
        ? isUploadInputError
          ? "Upload request was rejected"
          : "Request body is invalid"
        : responseStatus === 415
          ? "Unsupported request content type"
          : "Request failed",
  });
});

// ------------------ SERVER ------------------
const startServer = async () => {
  try {
    await initializeRateLimitStore();
    app.listen(PORT, () => {
      logInfo("server.started");
    });
  } catch (error) {
    if (error.code === "RATE_LIMIT_REDIS_URL_MISSING") {
      logError("startup.rate_limit_redis_url_missing.configure_render_key_value");
    } else if (error.code === "RATE_LIMIT_REDIS_CONNECTION_FAILED") {
      logError("startup.rate_limit_redis_connection_failed.check_private_url_and_network");
    } else {
      logError("startup.rate_limit_store_failed");
    }
    process.exit(1);
  }
};

startServer();
