import mongoose from "mongoose";

const userActivitySchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    eventType: { type: String, required: true, maxlength: 80, index: true },
    success: { type: Boolean, required: true },
    resourceId: { type: String, maxlength: 120 },
  },
  { timestamps: { createdAt: "occurredAt", updatedAt: false } }
);

userActivitySchema.index({ occurredAt: -1 });

const UserActivity = mongoose.model("UserActivity", userActivitySchema);
export default UserActivity;
