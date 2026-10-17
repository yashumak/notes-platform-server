// 🔥 LOAD ENV FIRST (VERY IMPORTANT)
import dotenv from "dotenv";
dotenv.config(); // loads backend/.env automatically

// ❌ DO NOT IMPORT ANYTHING ABOVE THIS LINE

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// Routes
import authRoutes from "./routes/auth.routes.js";
import notesRoutes from "./routes/notes.routes.js";

// DB
import connectDB from "./config/db.js";

const app = express();
const PORT = process.env.PORT || 5000;

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
  max: 100,
  message: "Too many requests from this IP, please try again later",
});
app.use(limiter);

// ------------------ ROUTES ------------------
app.use("/api/auth", authRoutes);
app.use("/api/notes", notesRoutes);

// ------------------ ERROR HANDLER ------------------
app.use((err, req, res, next) => {
  console.error("Backend Error:", err.message);
  console.error("Stack:", err.stack);

  res.status(500).json({
    message: "Upload failed",
    error: err.message,
  });
});

// ------------------ SERVER ------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
