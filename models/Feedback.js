import mongoose from "mongoose";

export const MAX_FEEDBACK_LENGTH = 2000;

const userInfoSchema = new mongoose.Schema(
  {
    user_Id: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
  },
  { _id: false }
);

const feedbackSchema = new mongoose.Schema(
  {
    feedback: {
      type: String,
      required: true,
      trim: true,
      maxlength: MAX_FEEDBACK_LENGTH,
    },
    user_info: {
      type: userInfoSchema,
      default: null,
    },
    isAuthenticated: {
      type: Boolean,
      default: false,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "feedback",
    versionKey: false,
  }
);

const Feedback = mongoose.model("Feedback", feedbackSchema, "feedback");
export default Feedback;
