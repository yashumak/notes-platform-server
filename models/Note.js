import mongoose from "mongoose";

const noteSchema = new mongoose.Schema(
  {
    user_id: { type: String, match: /^\d{10}$/ },
    title: { type: String, required: true },
    description: { type: String },
    fileId: { type: mongoose.Schema.Types.ObjectId },
    s3Key: { type: String },
    storageProvider: { type: String, enum: ["gridfs", "s3"], default: "gridfs" },
    uploadStatus: { type: String, enum: ["active", "deleting"], default: "active" },
    visibility: { type: String, enum: ["public", "private"], default: "public" },
    fileName: { type: String, required: true },
    contentType: { type: String, required: true },
    fileSize: { type: Number, required: true },
    university: { type: String },
    course: { type: String },
    subject: { type: String },
    category: { type: String },
    studyType: { type: String }, // Notes, Assignments, Papers, Que Banks, PPT...
    year: { type: Number },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    tags: [{ type: String }],
  },
  { timestamps: true }
);

noteSchema.index({ s3Key: 1 }, { unique: true, sparse: true });

const Note = mongoose.model("Note", noteSchema);
export default Note;
