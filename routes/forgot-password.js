import express from "express";
import bcrypt from "bcrypt";
import User from "../models/User.js";

const router = express.Router();

router.post("/forgot-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ message: "Email and new password are required" });
    }

    // Check user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found!" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Replace old password
    user.password = hashedPassword;
    await user.save();

    return res.json({
      success: true,
      message: "Password updated successfully. Please login with the new password.",
    });
  } catch (error) {
    console.log("Forgot password error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

export default router;
