// controllers/notes.controller.js
import Note from "../models/Note.js";
import { uploadBufferToS3 } from "../services/storage.service.js";

/**
 * Upload note (multipart/form-data with "file" field)
 * Expects auth middleware to set req.user.id
 */
export const uploadNote = async (req, res) => {
  try {
    // file will be available thanks to multer memoryStorage
    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });

    // Build key: e.g. notes/{userId}/{timestamp}_{originalname}
    const userId = req.user?.id || "anonymous";
    const timestamp = Date.now();
    // sanitize file original name if needed
    const safeName = file.originalname.replace(/\s+/g, "_");
    const key = `notes/${userId}/${timestamp}_${safeName}`;

    // Upload buffer to Backblaze (S3-compatible)
    const url = await uploadBufferToS3(file.buffer, key, file.mimetype);

    // Create note document in MongoDB
    const { title, description, university, course, studyType, year, tags } = req.body;

    const note = await Note.create({
      title: title || safeName,
      description: description || "",
      fileUrl: url,
      university,
      course,
      studyType,
      year: year ? Number(year) : undefined,
      uploadedBy: req.user.id,
      tags: tags ? (Array.isArray(tags) ? tags : String(tags).split(",").map(t => t.trim())) : []
    });

    res.status(201).json({ message: "Note uploaded", note });
  } catch (err) {
    console.error("Upload note error:", err);
    res.status(500).json({ message: "Upload failed", error: err.message });
  }
};
