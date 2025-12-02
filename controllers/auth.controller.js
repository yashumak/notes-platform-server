import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Register
export const registerUser = async (req, res) => {
  try {
    const { fullName, email, password, university, course, year } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      fullName,
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

// Verify (check if user is authenticated)
export const verifyUser = (req, res) => {
  // If protect middleware has run, req.user will be populated
  if (req.user) {
    return res.json({ isAuthenticated: true, user: req.user });
  }
  res.status(401).json({ isAuthenticated: false, message: "Not authenticated" });
};

// Forgot Password (placeholder)
export const forgotPassword = (req, res) => {
  // In a real application, this would send a password reset email
  console.log("Forgot password request for:", req.body.email);
  res.status(200).json({ message: "If an account with that email exists, a password reset link has been sent." });
};
