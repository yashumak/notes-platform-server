import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import User from "../models/User.js";
import { generateUserId } from "../utils/userId.js";

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const seedAdmin = async () => {
  const email = required("ADMIN_EMAIL");
  await mongoose.connect(required("MONGO_URI"), {
    ...(process.env.NODE_ENV === "production" ? { tls: true } : {}),
  });

  const existing = await User.findOne({ email }).select("role accountStatus deletedAt");
  if (existing) {
    if (existing.role === "ADMIN") {
      throw new Error("This account is already an administrator; no changes were made");
    }
    if (process.env.ADMIN_PROMOTE_EXISTING !== "true") {
      throw new Error("Set ADMIN_PROMOTE_EXISTING=true to explicitly promote this existing user");
    }
    existing.role = "ADMIN";
    existing.accountStatus = "active";
    existing.deletedAt = null;
    await existing.save();
    console.info("Existing user promoted to ADMIN.");
    return;
  }

  const password = required("ADMIN_PASSWORD");
  if (password.length < 16) {
    throw new Error("ADMIN_PASSWORD must contain at least 16 characters");
  }
  await User.create({
    user_id: generateUserId(),
    name: required("ADMIN_NAME"),
    email,
    password: await bcrypt.hash(password, 12),
    university: required("ADMIN_UNIVERSITY"),
    course: required("ADMIN_COURSE"),
    year: required("ADMIN_YEAR"),
    role: "ADMIN",
    accountStatus: "active",
  });
  console.info("Administrator account created.");
};

seedAdmin()
  .catch((error) => {
    console.error(`Admin seed failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
