import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    user_id: {
      type: String,
      match: /^\d{10}$/,
    },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    university: { type: String, required: true },
    course: { type: String, required: true },
    year: { type: String, required: true },
    profilePhotoS3Key: { type: String },
    profilePhotoFileId: { type: mongoose.Schema.Types.ObjectId },
    profilePhotoContentType: { type: String },
    notesIndexInitialized: { type: Boolean, default: false },
  },
  { timestamps: true }
);

userSchema.index(
  { user_id: 1 },
  { unique: true, partialFilterExpression: { user_id: { $type: "string" } } }
);

const User = mongoose.model("User", userSchema);
export default User;
