import express from "express";
import rateLimit from "express-rate-limit";
import upload from "../middlewares/upload.middleware.js";
import { deleteMyNote, downloadNoteFile, getNoteStats, listMyNotes, listNotes, uploadNote } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();
const publicReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many note requests from this IP, please try again later",
});

// Upload Route
router.post("/upload", protect, upload.single("file"), uploadNote);
router.get("/mine", protect, listMyNotes);
router.delete("/:id", protect, deleteMyNote);
router.get("/stats", publicReadLimiter, getNoteStats);
router.get("/", publicReadLimiter, listNotes);
router.get("/:id/file", downloadNoteFile);
export default router;
