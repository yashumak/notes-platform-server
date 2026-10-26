import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    university: { type: String, required: true },
    course: { type: String, required: true },
    year: { type: String, required: true },
    profilePhotoFileId: { type: mongoose.Schema.Types.ObjectId },
    profilePhotoContentType: { type: String },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
export default User;
