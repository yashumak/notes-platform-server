import mongoose from "mongoose";
import Feedback, { MAX_FEEDBACK_LENGTH } from "../models/Feedback.js";
import { logError } from "../utils/logger.js";

const formatFeedbackLines = (feedback) => {
  const lines = [];
  for (const [index, word] of feedback.split(/\s+/).entries()) {
    if (index % 15 === 0) lines.push([]);
    lines[lines.length - 1].push(word);
  }
  return lines.map((words) => words.join(" ")).join("\n");
};

export const submitFeedback = async (req, res) => {
  const feedback = typeof req.body?.feedback === "string"
    ? req.body.feedback.trim()
    : "";
  if (!feedback || feedback.length > MAX_FEEDBACK_LENGTH) {
    return res.status(400).json({
      message: feedback
        ? "Feedback must be 2,000 characters or fewer"
        : "Please enter your feedback",
    });
  }

  const authenticatedUser = req.authenticatedUser;
  const userId = mongoose.isValidObjectId(authenticatedUser?._id)
    ? authenticatedUser._id
    : null;
  const userInfo = userId
    ? {
        user_Id: String(userId),
        name: authenticatedUser.name,
        email: authenticatedUser.email,
      }
    : undefined;
  const formattedFeedback = formatFeedbackLines(feedback);

  try {
    await Feedback.create({
      feedback: formattedFeedback,
      ...(userInfo ? { user_info: userInfo } : {}),
      isAuthenticated: Boolean(userId),
    });
    return res.status(201).json({
      success: true,
      message: "Feedback submitted successfully",
    });
  } catch {
    logError("feedback.submit_failed");
    return res.status(500).json({ message: "Could not submit feedback" });
  }
};
