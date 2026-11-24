import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { getAppSecrets } from "../config/secrets.js";
import { AUTH_SESSION_SECONDS } from "../config/auth.js";
import User from "../models/User.js";
import { logError } from "../utils/logger.js";

export const protect = async (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, getAppSecrets().jwtSecret, {
      algorithms: ["HS256"],
    });
    if (
      typeof decoded === "string" ||
      typeof decoded.iat !== "number" ||
      typeof decoded.exp !== "number" ||
      Date.now() >= (decoded.iat + AUTH_SESSION_SECONDS) * 1000
    ) {
      return res.status(401).json({ message: "Session expired. Please log in again." });
    }
    if (typeof decoded.id !== "string") {
      return res.status(401).json({ message: "Invalid Token" });
    }
  } catch (err) {
    return res.status(401).json({ message: "Invalid Token" });
  }

  let user;
  try {
    user = await User.findById(decoded.id).select("role accountStatus deletedAt");
  } catch {
    logError("auth.account_status_check_failed");
    return res.status(503).json({ message: "Could not verify account status" });
  }
  if (!user || user.deletedAt) {
    return res.status(401).json({ message: "User session is invalid" });
  }
  if (user.accountStatus && user.accountStatus !== "active") {
    return res.status(403).json({ message: "Account is not active" });
  }
  req.user = decoded;
  req.authenticatedUser = user;
  return next();
};

export const optionalProtect = async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return next();

  let decoded;
  try {
    decoded = jwt.verify(token, getAppSecrets().jwtSecret, {
      algorithms: ["HS256"],
    });
    if (
      typeof decoded === "string" ||
      typeof decoded.iat !== "number" ||
      typeof decoded.exp !== "number" ||
      Date.now() >= (decoded.iat + AUTH_SESSION_SECONDS) * 1000 ||
      typeof decoded.id !== "string" ||
      !mongoose.isValidObjectId(decoded.id)
    ) {
      return next();
    }
  } catch {
    return next();
  }

  let user;
  try {
    user = await User.findById(decoded.id).select("name email role accountStatus deletedAt");
  } catch {
    logError("auth.optional_account_check_failed");
    return res.status(503).json({ message: "Could not verify session" });
  }

  if (!user || user.deletedAt || (user.accountStatus && user.accountStatus !== "active")) {
    return next();
  }

  req.user = decoded;
  req.authenticatedUser = user;
  return next();
};
