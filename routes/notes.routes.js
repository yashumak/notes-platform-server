import express from "express";
import upload from "../middlewares/upload.middleware.js";
import { uploadNote } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Upload Route
router.post("/upload", protect, upload.single("file"), uploadNote);

export default router;
