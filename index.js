// 🔥 LOAD ENV FIRST (VERY IMPORTANT)
import dotenv from "dotenv";
dotenv.config(); // loads backend/.env automatically

// ❌ DO NOT IMPORT ANYTHING ABOVE THIS LINE

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { logError, logInfo } from "./utils/logger.js";
import { isPublicNotesReadRequest } from "./utils/rateLimitPolicy.js";

// Routes
import authRoutes from "./routes/auth.routes.js";
import notesRoutes from "./routes/notes.routes.js";

// DB
import connectDB from "./config/db.js";

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET || Buffer.byteLength(process.env.JWT_SECRET) < 32) {
  logError("startup.jwt_secret_missing_or_weak");
  process.exit(1);
}

// ------------------ DATABASE ------------------
connectDB();

// ------------------ MIDDLEWARE ------------------
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(helmet());

// ------------------ RATE LIMIT ------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  skip: isPublicNotesReadRequest,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later",
});
app.use(limiter);

// ------------------ ROUTES ------------------
app.use("/api/auth", authRoutes);
app.use("/api/notes", notesRoutes);

app.use((_req, res) => {
  res.status(404).json({ message: "Not found" });
});

// ------------------ ERROR HANDLER ------------------
app.use((err, _req, res, _next) => {
  const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 500;
  const isUploadInputError =
    err.code === "LIMIT_FILE_SIZE" ||
    err.code === "LIMIT_FIELD_VALUE" ||
    err.message === "Unsupported file type";
  const responseStatus = isUploadInputError ? (status === 413 ? 413 : 400) : status;
  logError(
    responseStatus === 413
      ? "request.upload_too_large"
      : responseStatus === 400
        ? "request.upload_rejected"
        : "request.failed"
  );
  res.status(responseStatus).json({
    message: responseStatus === 413
      ? "Uploaded file or request exceeds the allowed size"
      : responseStatus === 400
        ? "Upload request was rejected"
        : "Request failed",
  });
});

// ------------------ SERVER ------------------
app.listen(PORT, () => {
  logInfo("server.started");
});
