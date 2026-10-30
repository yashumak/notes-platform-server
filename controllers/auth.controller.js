import User from "../models/User.js";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { AUTH_SESSION_SECONDS } from "../config/auth.js";
import { logError } from "../utils/logger.js";
import { hasValidFileSignature } from "../utils/fileValidation.js";
import { ensureUserId, generateUserId } from "../utils/userId.js";
import { s3Storage } from "../services/s3Storage.js";

const BCRYPT_ROUNDS = 12;
const PROFILE_PHOTO_PREFIX = "photos/";
const LEGACY_PROFILE_PHOTO_PREFIX = "profile-photo/";

const toS3PathSegment = (value, fallback, maxLength) => {
  const segment = String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLength)
    .replace(/-+$/g, "");
  return segment || fallback;
};

const getProfilePhotosBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "profilePhotos",
  });

const getProfilePhotoUrl = (user) => {
  const version = user.profilePhotoS3Key || user.profilePhotoFileId;
  return version
    ? `/api/auth/profile/photo?v=${encodeURIComponent(version)}`
    : null;
};

const storeProfilePhoto = async (user, file) => {
  const userId = await ensureUserId(user);
  const username = toS3PathSegment(user.name, "user", 60);
  const key = `${PROFILE_PHOTO_PREFIX}${username}-${userId}`;
  const oldS3Key = user.profilePhotoS3Key;
  const oldFileId = user.profilePhotoFileId;

  await s3Storage.putProfilePhoto({
    key,
    body: file.buffer,
    contentType: file.mimetype,
  });

  user.profilePhotoS3Key = key;
  user.profilePhotoFileId = undefined;
  user.profilePhotoContentType = file.mimetype;
  try {
    await user.save();
  } catch (error) {
    if (key !== oldS3Key) {
      await s3Storage.deleteObject(key).catch(() => {
        logError("profile_photo.incomplete_file_cleanup_failed");
      });
    }
    throw error;
  }

  if (oldS3Key && oldS3Key !== key) {
    await s3Storage.deleteObject(oldS3Key).catch(() => {
      logError("profile_photo.previous_file_cleanup_failed");
    });
  }
  if (oldFileId) {
    await getProfilePhotosBucket().delete(oldFileId).catch(() => {
      logError("profile_photo.previous_file_cleanup_failed");
    });
  }
  return key;
};

const migrateLegacyProfilePhoto = async (user) => {
  let buffer;
  let contentType = user.profilePhotoContentType;

  if (user.profilePhotoFileId) {
    const bucket = getProfilePhotosBucket();
    const chunks = [];
    const downloadStream = bucket.openDownloadStream(user.profilePhotoFileId);
    for await (const chunk of downloadStream) {
      chunks.push(chunk);
    }
    buffer = Buffer.concat(chunks);
  } else if (user.profilePhotoS3Key?.startsWith(LEGACY_PROFILE_PHOTO_PREFIX)) {
    const legacyPhoto = await s3Storage.getProfilePhoto({ key: user.profilePhotoS3Key });
    buffer = legacyPhoto.body;
    contentType ||= legacyPhoto.contentType;
  } else {
    throw new Error("Legacy profile photo location is invalid");
  }

  if (!hasValidFileSignature({ buffer, contentType })) {
    throw new Error("Legacy profile photo contents are invalid");
  }

  return storeProfilePhoto(user, { buffer, mimetype: contentType });
};

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

    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let user;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        user = await User.create({
          user_id: generateUserId(),
          name,
          email,
          password: hashed,
          university,
          course,
          year
        });
        break;
      } catch (error) {
        const duplicateUserId =
          error.code === 11000 &&
          (error.keyPattern?.user_id || error.keyValue?.user_id !== undefined);
        if (!duplicateUserId || attempt === 4) throw error;
      }
    }

    const token = jwt.sign({ id: user._id, user_id: user.user_id }, process.env.JWT_SECRET, {
      expiresIn: AUTH_SESSION_SECONDS,
      algorithm: "HS256",
    });

    res.cookie("token", token, {
      ...authCookieOptions,
      maxAge: AUTH_SESSION_SECONDS * 1000,
    }).status(201).json({ message: "Registration successful" });
  } catch {
    logError("auth.registration_failed");
    res.status(500).json({ message: "Internal server error" });
  }
};

// Login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");
    if (!user) return res.status(401).json({ message: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid email or password" });

    const userId = await ensureUserId(user);
    const token = jwt.sign({ id: user._id, user_id: userId }, process.env.JWT_SECRET, {
      expiresIn: AUTH_SESSION_SECONDS,
      algorithm: "HS256",
    });

    res.cookie("token", token, {
      ...authCookieOptions,
      maxAge: AUTH_SESSION_SECONDS * 1000,
    }).json({ message: "Login successful" });
  } catch {
    logError("auth.login_failed");
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
    "name user_id email university course year profilePhotoS3Key profilePhotoFileId profilePhotoContentType"
  );

  if (!user) {
    return res.status(401).json({ isAuthenticated: false, message: "Not authenticated" });
  }

  if (
    user.profilePhotoFileId ||
    user.profilePhotoS3Key?.startsWith(LEGACY_PROFILE_PHOTO_PREFIX)
  ) {
    try {
      await migrateLegacyProfilePhoto(user);
    } catch {
      logError("profile_photo.migration_failed");
    }
  }

  res.json({
    isAuthenticated: true,
    expiresAt,
    user: {
      name: user.name,
      email: user.email,
      university: user.university,
      course: user.course,
      year: user.year,
      profilePhotoUrl: getProfilePhotoUrl(user),
    },
  });
};

export const getProfilePhoto = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "name user_id profilePhotoS3Key profilePhotoFileId profilePhotoContentType"
    );
    if (!user?.profilePhotoS3Key && !user?.profilePhotoFileId) {
      return res.status(404).json({ message: "Profile photo not found" });
    }

    if (
      user.profilePhotoS3Key &&
      !user.profilePhotoS3Key.startsWith(LEGACY_PROFILE_PHOTO_PREFIX)
    ) {
      const url = await s3Storage.createProfilePhotoUrl({
        key: user.profilePhotoS3Key,
        contentType: user.profilePhotoContentType || "application/octet-stream",
      });
      res.setHeader("Cache-Control", "private, no-store");
      return res.redirect(302, url);
    }

    await migrateLegacyProfilePhoto(user);
    const url = await s3Storage.createProfilePhotoUrl({
      key: user.profilePhotoS3Key,
      contentType: user.profilePhotoContentType,
    });
    res.setHeader("Cache-Control", "private, no-store");
    return res.redirect(302, url);
  } catch (error) {
    logError("profile_photo.load_failed");
    res.status(500).json({ message: "Could not load profile photo" });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { name, email, university, course, year } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const existingUser = await User.findOne({ email, _id: { $ne: user._id } });
    if (existingUser) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }

    if (req.file) {
      if (!hasValidFileSignature(req.file)) {
        return res.status(400).json({ message: "Profile photo contents are invalid" });
      }
    }

    user.name = name;
    user.email = email;
    user.university = university;
    user.course = course;
    user.year = year;
    if (req.file) {
      await storeProfilePhoto(user, req.file);
    } else {
      await user.save();
    }

    return res.json({
      success: true,
      user: {
        name: user.name,
        email: user.email,
        university: user.university,
        course: user.course,
        year: user.year,
        profilePhotoUrl: getProfilePhotoUrl(user),
      },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }
    logError("profile.update_failed");
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
  if (!hasValidFileSignature(req.file)) {
    return res.status(400).json({ message: "Profile photo contents are invalid" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const key = await storeProfilePhoto(user, req.file);

    return res.json({
      success: true,
      profilePhotoUrl: getProfilePhotoUrl({ profilePhotoS3Key: key }),
    });
  } catch {
    logError("profile_photo.update_failed");
    res.status(500).json({ message: "Could not update profile photo" });
  }
};

export const changePassword = async (req, res) => {
  try {
    const body = req.body ?? {};
    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current and new passwords are required." });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters." });
    }

    const user = await User.findById(req.user.id).select("+password");
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ message: "Current password is incorrect." });
    }

    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({ message: "Choose a password different from your current password." });
    }

    user.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await user.save();

    res.clearCookie("token", authCookieOptions);
    return res.json({ message: "Password updated. Please log in again." });
  } catch {
    logError("auth.password_change_failed");
    return res.status(500).json({ message: "Could not update your password." });
  }
};
