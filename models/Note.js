import mongoose from "mongoose";

const noteSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    fileId: { type: mongoose.Schema.Types.ObjectId, required: true },
    fileName: { type: String, required: true },
    contentType: { type: String, required: true },
    fileSize: { type: Number, required: true },
    university: { type: String },
    course: { type: String },
    studyType: { type: String }, // Notes, Assignments, Papers, Que Banks, PPT...
    year: { type: Number },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    tags: [{ type: String }],
  },
  { timestamps: true }
);

const Note = mongoose.model("Note", noteSchema);
export default Note;
