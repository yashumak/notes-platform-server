import express from "express";
import { body, validationResult } from "express-validator";
import { registerUser, loginUser, logoutUser, verifyUser, forgotPassword } from "../controllers/auth.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

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
router.post("/forgot-password", forgotPassword);

export default router;
