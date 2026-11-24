import express from "express";
import { body, validationResult } from "express-validator";
import { submitFeedback } from "../controllers/feedback.controller.js";
import { optionalProtect } from "../middlewares/authMiddleware.js";
import { feedbackLimiter } from "../middlewares/rateLimiters.js";
import { MAX_FEEDBACK_LENGTH } from "../models/Feedback.js";

const router = express.Router();

const feedbackValidation = [
  body("feedback")
    .isString()
    .withMessage("Feedback must be text")
    .bail()
    .trim()
    .notEmpty()
    .withMessage("Please enter your feedback")
    .isLength({ max: MAX_FEEDBACK_LENGTH })
    .withMessage("Feedback must be 2,000 characters or fewer"),
];

router.post("/", feedbackLimiter, optionalProtect, feedbackValidation, (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }
  return next();
}, submitFeedback);

export default router;
