import mongoose from "mongoose";

const adminAuditLogSchema = new mongoose.Schema(
  {
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    action: { type: String, required: true, maxlength: 80 },
    targetType: { type: String, required: true, maxlength: 40 },
    targetId: { type: String, maxlength: 250 },
    changedFields: [{ type: String, maxlength: 80 }],
    status: { type: String, enum: ["PENDING", "SUCCESS", "FAILURE"], required: true },
  },
  { timestamps: { createdAt: "timestamp", updatedAt: false } }
);

adminAuditLogSchema.index({ timestamp: -1 });
adminAuditLogSchema.index({ action: 1, timestamp: -1 });

const AdminAuditLog = mongoose.model("AdminAuditLog", adminAuditLogSchema);
export default AdminAuditLog;
