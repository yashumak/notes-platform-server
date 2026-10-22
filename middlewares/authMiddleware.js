import jwt from "jsonwebtoken";
import { AUTH_SESSION_SECONDS } from "../config/auth.js";

export const protect = (req, res, next) => {
  console.log("Request cookies:", req.cookies);
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (
      typeof decoded === "string" ||
      typeof decoded.iat !== "number" ||
      typeof decoded.exp !== "number" ||
      Date.now() >= (decoded.iat + AUTH_SESSION_SECONDS) * 1000
    ) {
      return res.status(401).json({ message: "Session expired. Please log in again." });
    }
    req.user = decoded; // user id
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid Token" });
  }
};
