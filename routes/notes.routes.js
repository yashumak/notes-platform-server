import express from "express";
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
import {
  notesSearchLimiter,
  notesUploadLimiter,
  publicNotesListLimiter,
} from "../middlewares/rateLimiters.js";

const router = express.Router();
router.post("/upload/presign", protect, notesUploadLimiter, createNoteUploadUrl);
router.post("/upload/complete", protect, completeNoteUpload);
router.post("/upload", protect, notesUploadLimiter, (_req, res) =>
  res.status(410).json({ message: "Use the presigned upload endpoints for note files" })
);
router.get("/mine", protect, listMyNotes);
router.delete("/:id", protect, deleteMyNote);
router.get("/stats", getNoteStats);
router.get("/", notesSearchLimiter, publicNotesListLimiter, listNotes);
router.get("/:id/file", optionalProtect, downloadNoteFile);
export default router;
