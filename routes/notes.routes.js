import express from "express";
import upload from "../middlewares/upload.middleware.js";
import { downloadNoteFile, listMyNotes, listNotes, uploadNote } from "../controllers/notes.controller.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Upload Route
router.post("/upload", protect, upload.single("file"), uploadNote);
router.get("/mine", protect, listMyNotes);
router.get("/", listNotes);
router.get("/:id/file", downloadNoteFile);
export default router;
