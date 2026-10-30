import express from "express";
import rateLimit from "express-rate-limit";
import {
  completeNoteUpload,
  createNoteUploadUrl,
  deleteMyNote,
  downloadNoteFile,
  getNoteStats,
  listMyNotes,
  listNotes,
} from "../controllers/notes.controller.js";
import { optionalProtect, protect } from "../middlewares/authMiddleware.js";

const router = express.Router();
const publicReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many note requests from this IP, please try again later",
});

const uploadPresignLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many upload attempts. Please try again later.",
});
const uploadCompleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many upload attempts. Please try again later.",
});

router.post("/upload/presign", protect, uploadPresignLimiter, createNoteUploadUrl);
router.post("/upload/complete", protect, uploadCompleteLimiter, completeNoteUpload);
router.post("/upload", protect, (_req, res) =>
  res.status(410).json({ message: "Use the presigned upload endpoints for note files" })
);
router.get("/mine", protect, listMyNotes);
router.delete("/:id", protect, deleteMyNote);
router.get("/stats", publicReadLimiter, getNoteStats);
router.get("/", publicReadLimiter, listNotes);
router.get("/:id/file", optionalProtect, downloadNoteFile);
export default router;
