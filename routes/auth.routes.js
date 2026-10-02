import express from "express";
import multer from "multer";
import { body, validationResult } from "express-validator";
import {
  getProfilePhoto,
  registerUser,
  loginUser,
  logoutUser,
  verifyUser,
  updateProfilePhoto,
  forgotPassword,
} from "../controllers/auth.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();
const allowedPhotoTypes = new Set(["image/jpeg", "image/png", "image/webp"]);
const profilePhotoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, callback) => {
    if (allowedPhotoTypes.has(file.mimetype)) return callback(null, true);
    callback(new Error("Use a JPEG, PNG, or WebP image"));
  },
});

const parseProfilePhoto = (req, res, next) => {
  profilePhotoUpload.single("photo")(req, res, (error) => {
    if (!error) return next();
    const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    res.status(status).json({ message: error.message });
  });
};

// Validation middleware for registration
const registerValidation = [
  body("name").notEmpty().withMessage("Name is required"),
  body("email").isEmail().withMessage("Invalid email format"),
  body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
  body("university").notEmpty().withMessage("University is required"),
  body("course").notEmpty().withMessage("Course is required"),
  body("year").notEmpty().withMessage("Year is required"),
];

// Validation middleware for login
const loginValidation = [
  body("email").isEmail().withMessage("Invalid email format"),
  body("password").notEmpty().withMessage("Password is required"),
];

// Middleware to handle validation results
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post("/register", registerValidation, handleValidationErrors, registerUser);
router.post("/login", loginValidation, handleValidationErrors, loginUser);
router.post("/logout", logoutUser);
router.get("/verify", protect, verifyUser);
router.get("/profile/photo", protect, getProfilePhoto);
router.put("/profile/photo", protect, parseProfilePhoto, updateProfilePhoto);
router.post("/forgot-password", forgotPassword);

export default router;
