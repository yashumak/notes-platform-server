import User from "../models/User.js";
import { protect } from "./authMiddleware.js";
import { logError } from "../utils/logger.js";

const requireAdminRole = async (req, res, next) => {
  try {
    const user = req.authenticatedUser ||
      await User.findById(req.user.id).select("role accountStatus deletedAt");
    if (
      !user ||
      user.deletedAt ||
      (user.accountStatus && user.accountStatus !== "active") ||
      user.role !== "ADMIN"
    ) {
      return res.status(403).json({ message: "Administrator access is required" });
    }

    req.admin = { id: user._id };
    return next();
  } catch {
    logError("admin.authorization_check_failed");
    return res.status(503).json({ message: "Could not verify administrator access" });
  }
};

export const requireAdmin = [protect, requireAdminRole];
