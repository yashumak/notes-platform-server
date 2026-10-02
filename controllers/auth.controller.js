import User from "../models/User.js";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const getProfilePhotosBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "profilePhotos",
  });

// Register
export const registerUser = async (req, res) => {
  try {
    const { name, email, password, university, course, year } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      university,
      course,
      year
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }).status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Registration error in auth.controller.js:", error.stack || error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Incorrect password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }).json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error in auth.controller.js:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Logout
export const logoutUser = (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    expires: new Date(0)
  }).json({ message: "Logged out successfully" });
};

// Verify the session and return the minimal user details needed by the UI.
export const verifyUser = async (req, res) => {
  const user = await User.findById(req.user.id).select(
    "name email university course year profilePhotoFileId"
  );

  if (!user) {
    return res.status(401).json({ isAuthenticated: false, message: "Not authenticated" });
  }

  res.json({
    isAuthenticated: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      university: user.university,
      course: user.course,
      year: user.year,
      profilePhotoUrl: user.profilePhotoFileId
        ? `/api/auth/profile/photo?v=${user.profilePhotoFileId}`
        : null,
    },
  });
};

export const getProfilePhoto = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("profilePhotoFileId profilePhotoContentType");
    if (!user?.profilePhotoFileId) {
      return res.status(404).json({ message: "Profile photo not found" });
    }

    const downloadStream = getProfilePhotosBucket().openDownloadStream(user.profilePhotoFileId);
    res.setHeader("Content-Type", user.profilePhotoContentType || "application/octet-stream");
    res.setHeader("Cache-Control", "private, no-cache");
    downloadStream.on("error", (error) => {
      if (res.headersSent) {
        res.destroy(error);
      } else {
        res.status(404).json({ message: "Profile photo not found" });
      }
    });
    downloadStream.pipe(res);
  } catch (error) {
    console.error("Get profile photo error:", error);
    res.status(500).json({ message: "Could not load profile photo" });
  }
};

export const updateProfilePhoto = async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "Choose an image to upload" });
  }

  const allowedTypes = new Set(["image/jpeg", "image/png", "image/webp"]);
  if (!allowedTypes.has(req.file.mimetype)) {
    return res.status(400).json({ message: "Use a JPEG, PNG, or WebP image" });
  }

  let bucket;
  let newFileId;

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    bucket = getProfilePhotosBucket();
    const oldFileId = user.profilePhotoFileId;
    const uploadStream = bucket.openUploadStream(`profile-${user.id}`, {
      metadata: { contentType: req.file.mimetype },
    });
    newFileId = uploadStream.id;

    await new Promise((resolve, reject) => {
      uploadStream.once("finish", resolve);
      uploadStream.once("error", reject);
      uploadStream.end(req.file.buffer);
    });

    user.profilePhotoFileId = newFileId;
    user.profilePhotoContentType = req.file.mimetype;
    await user.save();

    if (oldFileId) await bucket.delete(oldFileId).catch(() => { });

    res.json({
      success: true,
      profilePhotoUrl: `/api/auth/profile/photo?v=${newFileId}`,
    });
  } catch (error) {
    if (bucket && newFileId) await bucket.delete(newFileId).catch(() => { });
    console.error("Update profile photo error:", error);
    res.status(500).json({ message: "Could not update profile photo" });
  }
};

// Forgot Password (placeholder)
export const forgotPassword = (req, res) => {
  // In a real application, this would send a password reset email
  console.log("Forgot password request for:", req.body.email);
  res.status(200).json({ message: "If an account with that email exists, a password reset link has been sent." });
};
