import express from "express";
import upload from "../middlewares/upload.middleware.js";
import { deleteMyNote, downloadNoteFile, getNoteStats, listMyNotes, listNotes, uploadNote } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Upload Route
router.post("/upload", protect, upload.single("file"), uploadNote);
router.get("/mine", protect, listMyNotes);
router.delete("/:id", protect, deleteMyNote);
router.get("/stats", getNoteStats);
router.get("/", protect, listNotes);
router.get("/:id/file", protect, downloadNoteFile);
export default router;
