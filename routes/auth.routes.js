import express from "express";
import multer from "multer";
import { body, validationResult } from "express-validator";
import {
  getProfilePhoto,
  registerUser,
  loginUser,
  logoutUser,
  verifyUser,
  updateProfile,
  updateProfilePhoto,
  changePassword,
} from "../controllers/auth.controller.js";
import { protect } from "../middlewares/authMiddleware.js";
import {
  loginAccountLimiter,
  loginIpLimiter,
  passwordChangeLimiter,
  signupLimiter,
} from "../middlewares/rateLimiters.js";
import { decryptAuthPayload, getAuthPayloadPublicKey } from "../utils/authPayloadEncryption.js";

const router = express.Router();
const allowedPhotoTypes = new Set(["image/jpeg", "image/png", "image/webp"]);
const profilePhotoUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    fieldSize: 64 * 1024,
    fields: 8,
    parts: 9,
  },
  fileFilter: (_req, file, callback) => {
    if (allowedPhotoTypes.has(file.mimetype)) return callback(null, true);
    callback(new Error("Use a JPEG, PNG, or WebP image"));
  },
});

const parseProfilePhoto = (req, res, next) => {
  profilePhotoUpload.single("photo")(req, res, (error) => {
    if (!error) return next();
    const status =
      error.code === "LIMIT_FILE_SIZE" || error.code === "LIMIT_FIELD_VALUE" ? 413 : 400;
    res.status(status).json({
      message: error.code === "LIMIT_FILE_SIZE"
        ? "Profile photo exceeds the 5 MB limit"
        : status === 413
          ? "Profile photo request is too large"
          : "Could not process profile photo upload",
    });
  });
};

// Validation middleware for registration
const registerValidation = [
  body("name").notEmpty().withMessage("Name is required"),
  body("email").isEmail().withMessage("Invalid email format"),
  body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long"),
  body("university").notEmpty().withMessage("University is required"),
  body("course").notEmpty().withMessage("Course is required"),
  body("year").notEmpty().withMessage("Year is required"),
];

// Validation middleware for login
const loginValidation = [
  body("email").isEmail().withMessage("Invalid email format"),
  body("password").notEmpty().withMessage("Password is required"),
];

const passwordChangeValidation = [
  body("currentPassword").notEmpty().withMessage("Current password is required"),
  body("newPassword").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long"),
];

const profileValidation = [
  body("name").trim().notEmpty().isLength({ max: 100 }).withMessage("Name is required and must be at most 100 characters"),
  body("email").trim().isEmail().withMessage("Enter a valid email address"),
  body("university").trim().notEmpty().isLength({ max: 200 }).withMessage("College or university is required and must be at most 200 characters"),
  body("course").trim().notEmpty().isLength({ max: 100 }).withMessage("Branch or course is required and must be at most 100 characters"),
  body("year").trim().notEmpty().isLength({ max: 50 }).withMessage("Year is required and must be at most 50 characters"),
];

// Middleware to handle validation results
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array().map(({ path, msg }) => ({ field: path, message: msg })),
    });
  }
  next();
};

router.get("/encryption-key", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ publicKey: getAuthPayloadPublicKey() });
});
router.post("/register", signupLimiter, decryptAuthPayload, registerValidation, handleValidationErrors, registerUser);
router.post(
  "/login",
  loginIpLimiter,
  decryptAuthPayload,
  loginValidation,
  handleValidationErrors,
  loginAccountLimiter,
  loginUser
);
router.post("/logout", logoutUser);
router.get("/verify", protect, verifyUser);
router.get("/profile/photo", protect, getProfilePhoto);
router.put("/profile", protect, parseProfilePhoto, profileValidation, handleValidationErrors, updateProfile);
router.put("/profile/photo", protect, parseProfilePhoto, updateProfilePhoto);
router.post(
  "/change-password",
  protect,
  passwordChangeLimiter,
  passwordChangeValidation,
  handleValidationErrors,
  changePassword
);

export default router;
