// controllers/notes.controller.js
import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import { logError } from "../utils/logger.js";
import { hasValidFileSignature } from "../utils/fileValidation.js";
import Note from "../models/Note.js";
import User from "../models/User.js";
import { setGridFsFileUserId } from "../utils/gridFsOwnership.js";
import { ensureUserId } from "../utils/userId.js";

const getNoteFilesBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "noteFiles",
  });

export const getNoteStats = async (_req, res) => {
  try {
    const [total, universities, studyTypes] = await Promise.all([
      Note.countDocuments(),
      Note.distinct("university"),
      Note.distinct("studyType"),
    ]);

    res.json({
      success: true,
      stats: {
        total,
        universities: universities.filter((value) => typeof value === "string" && value.trim()).length,
        studyTypes: studyTypes.filter((value) => typeof value === "string" && value.trim()).length,
      },
    });
  } catch {
    logError("notes.stats_failed");
    res.status(500).json({ message: "Could not load note statistics" });
  }
};

/**
 * Upload note (multipart/form-data with "file" field)
 * Expects auth middleware to set req.user.id
 */
export const uploadNote = async (req, res) => {
  let bucket;
  let fileId;

  try {
    const file = req.file;
    if (!file) return res.status(400).json({ message: "No file uploaded" });
    if (!hasValidFileSignature(file)) {
      return res.status(400).json({ message: "File contents do not match a supported file type" });
    }

    const safeName = (file.originalname.split(/[\\/]/).pop() || "upload")
      .replace(/[\u0000-\u001f\u007f]/g, "")
      .slice(0, 200) || "upload";
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ message: "User not found" });
    const userId = await ensureUserId(user);
    bucket = getNoteFilesBucket();
    const uploadStream = bucket.openUploadStream(`${randomUUID()}`, {
      metadata: { contentType: file.mimetype },
    });
    fileId = uploadStream.id;

    await new Promise((resolve, reject) => {
      uploadStream.once("finish", resolve);
      uploadStream.once("error", reject);
      uploadStream.end(file.buffer);
    });
    await setGridFsFileUserId("noteFiles", fileId, userId);

    const { title, description, university, course, studyType, year, tags } = req.body;

    const note = await Note.create({
      title: title || safeName,
      description: description || "",
      fileId,
      fileName: safeName,
      contentType: file.mimetype,
      fileSize: file.size,
      university,
      course: course || req.body.branch,
      studyType,
      year: year ? Number(year) : undefined,
      user_id: userId,
      uploadedBy: user._id,
      tags: tags ? (Array.isArray(tags) ? tags : String(tags).split(",").map((tag) => tag.trim())) : [],
    });

    const fileUrl = `/api/notes/${note.id}/file`;
    res.status(201).json({ success: true, message: "Note uploaded", url: fileUrl, fileUrl });
  } catch {
    if (bucket && fileId) {
      await bucket.delete(fileId).catch(() => {
        logError("notes.upload_cleanup_failed");
      });
    }
    logError("notes.upload_failed");
    res.status(500).json({ message: "Upload failed" });
  }
};

export const listNotes = async (req, res) => {
  try {
    const notes = await Note.find()
      .sort({ createdAt: -1 })
      .select("title description fileName fileSize university course studyType year tags createdAt");

    res.json({
      success: true,
      notes: notes.map((note) => serializeNote(note)),
    });
  } catch {
    logError("notes.list_failed");
    res.status(500).json({ message: "Could not load notes" });
  }
};

export const listMyNotes = async (req, res) => {
  try {
    const notes = await Note.find({ uploadedBy: req.user.id })
      .sort({ createdAt: -1 })
      .select("title description fileName fileSize university course studyType year tags createdAt");

    res.json({
      success: true,
      notes: notes.map((note) => serializeNote(note)),
    });
  } catch {
    logError("notes.user_list_failed");
    res.status(500).json({ message: "Could not load your notes" });
  }
};

export const deleteMyNote = async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid note ID" });
    }

    const note = await Note.findOne({
      _id: req.params.id,
      uploadedBy: req.user.id,
    }).select("fileId");

    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }

    await getNoteFilesBucket().delete(note.fileId);
    await note.deleteOne();

    return res.json({ success: true, message: "Note deleted successfully" });
  } catch {
    logError("notes.delete_failed");
    return res.status(500).json({ message: "Could not delete note" });
  }
};

export const downloadNoteFile = async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid note ID" });
    }

    const note = await Note.findById(req.params.id).select("fileId fileName contentType");
    if (!note?.fileId) {
      return res.status(404).json({ message: "Note file not found" });
    }

    const downloadStream = getNoteFilesBucket().openDownloadStream(note.fileId);
    res.setHeader("Content-Type", note.contentType || "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodeURIComponent(note.fileName || "download")}`
    );
    downloadStream.on("error", () => {
      if (res.headersSent) {
        logError("notes.download_stream_failed");
        res.destroy();
      } else {
        res.status(404).json({ message: "Note file not found" });
      }
    });
    downloadStream.pipe(res);
  } catch {
    logError("notes.download_failed");
    res.status(500).json({ message: "Download failed" });
  }
};

const serializeNote = (note) => ({
  _id: note.id,
  title: note.title,
  description: note.description,
  fileName: note.fileName,
  fileSize: note.fileSize,
  university: note.university,
  course: note.course,
  studyType: note.studyType,
  year: note.year,
  tags: note.tags,
  createdAt: note.createdAt,
  fileUrl: `/api/notes/${note.id}/file`,
});
