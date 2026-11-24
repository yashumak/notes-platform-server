import express from "express";
import { body, validationResult } from "express-validator";
import {
  adminLogin,
  adminLogout,
  adminVerify,
  deleteNote,
  deleteProfilePhoto,
  downloadMedia,
  getAdminNote,
  getDashboard,
  getAnalytics,
  getSettings,
  getUser,
  listFeedback,
  listActivity,
  listAuditLogs,
  listMedia,
  listNotes,
  listUsers,
  setUserStatus,
  softDeleteUser,
  restoreUser,
  updateNote,
  updateUser,
} from "../controllers/admin.controller.js";
import { requireAdmin } from "../middlewares/requireAdmin.js";
import { optionalProtect } from "../middlewares/authMiddleware.js";
import { loginAccountLimiter, loginIpLimiter } from "../middlewares/rateLimiters.js";
import { decryptAuthPayload } from "../utils/authPayloadEncryption.js";

const router = express.Router();
const noStore = (_req, res, next) => {
  res.setHeader("Cache-Control", "private, no-store");
  next();
};
const validateLogin = [
  body("email").isEmail().withMessage("Invalid email format"),
  body("password").notEmpty().withMessage("Password is required"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array().map(({ path, msg }) => ({ field: path, message: msg })),
      });
    }
    return next();
  },
];

router.use(noStore);
router.post("/auth/login", loginIpLimiter, decryptAuthPayload, validateLogin, loginAccountLimiter, adminLogin);
router.post("/auth/logout", optionalProtect, adminLogout);
router.get("/auth/verify", ...requireAdmin, adminVerify);

router.get("/dashboard/stats", ...requireAdmin, getDashboard);
router.get("/dashboard/recent-activity", ...requireAdmin, listActivity);

router.get("/users", ...requireAdmin, listUsers);
router.get("/users/:id", ...requireAdmin, getUser);
router.patch("/users/:id", ...requireAdmin, updateUser);
router.patch("/users/:id/status", ...requireAdmin, setUserStatus);
router.post("/users/:id/restore", ...requireAdmin, restoreUser);
router.delete("/users/:id", ...requireAdmin, softDeleteUser);
router.get("/registrations", ...requireAdmin, listUsers);

router.get("/notes", ...requireAdmin, listNotes);
router.get("/feedback", ...requireAdmin, listFeedback);
router.get("/notes/:id", ...requireAdmin, getAdminNote);
router.patch("/notes/:id", ...requireAdmin, updateNote);
router.delete("/notes/:id", ...requireAdmin, deleteNote);

router.get("/media", ...requireAdmin, listMedia);
router.get("/media/:kind/:id/download", ...requireAdmin, downloadMedia);
router.delete("/media/profile/:id", ...requireAdmin, deleteProfilePhoto);

router.get("/activity", ...requireAdmin, listActivity);
router.get("/activity/login-history", ...requireAdmin, listActivity);
router.get("/audit-logs", ...requireAdmin, listAuditLogs);
router.get("/analytics", ...requireAdmin, getAnalytics);
router.get("/analytics/users", ...requireAdmin, getAnalytics);
router.get("/analytics/notes", ...requireAdmin, getAnalytics);
router.get("/analytics/storage", ...requireAdmin, getAnalytics);
router.get("/settings", ...requireAdmin, getSettings);

export default router;
