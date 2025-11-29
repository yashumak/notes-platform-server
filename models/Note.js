import mongoose from "mongoose";

const noteSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    fileUrl: { type: String }, // Cloudflare / Backblaze URL
    university: { type: String },
    course: { type: String },
    studyType: { type: String }, // Notes, Assignments, Papers, Que Banks, PPT...
    year: { type: Number },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
);

const Note = mongoose.model("Note", noteSchema);
export default Note;
