import User from "../models/User.js";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { AUTH_SESSION_SECONDS } from "../config/auth.js";

const getProfilePhotosBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "profilePhotos",
  });

const authCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",
};

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
      expiresIn: AUTH_SESSION_SECONDS,
    });

    res.cookie("token", token, {
      ...authCookieOptions,
      maxAge: AUTH_SESSION_SECONDS * 1000,
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
      expiresIn: AUTH_SESSION_SECONDS,
    });

    res.cookie("token", token, {
      ...authCookieOptions,
      maxAge: AUTH_SESSION_SECONDS * 1000,
    }).json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error in auth.controller.js:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Logout
export const logoutUser = (req, res) => {
  res.clearCookie("token", authCookieOptions);
  res.clearCookie("token", { ...authCookieOptions, path: "/api/auth" });
  res.json({ message: "Logged out successfully" });
};

// Verify the session and return the minimal user details needed by the UI.
export const verifyUser = async (req, res) => {
  const expiresAt = Math.min(
    req.user.exp,
    req.user.iat + AUTH_SESSION_SECONDS
  ) * 1000;
  const user = await User.findById(req.user.id).select(
    "name email university course year profilePhotoFileId"
  );

  if (!user) {
    return res.status(401).json({ isAuthenticated: false, message: "Not authenticated" });
  }

  res.json({
    isAuthenticated: true,
    expiresAt,
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

export const updateProfile = async (req, res) => {
  let bucket;
  let newFileId;

  try {
    const { name, email, university, course, year } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const existingUser = await User.findOne({ email, _id: { $ne: user._id } });
    if (existingUser) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }

    const oldFileId = user.profilePhotoFileId;
    if (req.file) {
      bucket = getProfilePhotosBucket();
      const uploadStream = bucket.openUploadStream(`profile-${user.id}`, {
        metadata: { contentType: req.file.mimetype },
      });
      newFileId = uploadStream.id;

      await new Promise((resolve, reject) => {
        uploadStream.once("finish", resolve);
        uploadStream.once("error", reject);
        uploadStream.end(req.file.buffer);
      });
    }

    user.name = name;
    user.email = email;
    user.university = university;
    user.course = course;
    user.year = year;
    if (req.file && newFileId) {
      user.profilePhotoFileId = newFileId;
      user.profilePhotoContentType = req.file.mimetype;
    }
    await user.save();

    if (req.file && oldFileId && bucket) {
      await bucket.delete(oldFileId).catch((error) => {
        console.error("Could not remove previous profile photo:", error);
      });
    }

    return res.json({
      success: true,
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
  } catch (error) {
    if (bucket && newFileId) {
      await bucket.delete(newFileId).catch((cleanupError) => {
        console.error("Could not remove incomplete profile photo:", cleanupError);
      });
    }
    if (error.code === 11000) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }
    console.error("Update profile error:", error);
    return res.status(500).json({ message: "Could not update your profile" });
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

// Forgot Password
export const forgotPassword = async (req, res) => {
  try {
    const body = req.body ?? {};
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

    if (!email || !newPassword) {
      return res.status(400).json({ message: "Email and new password are required." });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found." });

    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({ message: "Your new password must be different from your current password." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.json({ message: "Password updated successfully. Please login with your new password." });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({ message: "Could not update your password." });
  }
};
