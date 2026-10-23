// controllers/notes.controller.js
import mongoose from "mongoose";
import Note from "../models/Note.js";

const getNoteFilesBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "noteFiles",
  });

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

    const safeName = file.originalname.split(/[\\/]/).pop() || "upload";
    bucket = getNoteFilesBucket();
    const uploadStream = bucket.openUploadStream(safeName, {
      metadata: { contentType: file.mimetype },
    });
    fileId = uploadStream.id;

    await new Promise((resolve, reject) => {
      uploadStream.once("finish", resolve);
      uploadStream.once("error", reject);
      uploadStream.end(file.buffer);
    });

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
      uploadedBy: req.user.id,
      tags: tags ? (Array.isArray(tags) ? tags : String(tags).split(",").map((tag) => tag.trim())) : [],
    });

    const fileUrl = `/api/notes/${note.id}/file`;
    res.status(201).json({ success: true, message: "Note uploaded", url: fileUrl, fileUrl, note });
  } catch (err) {
    if (bucket && fileId) {
      await bucket.delete(fileId).catch(() => { });
    }
    console.error("Upload note error:", err);
    res.status(500).json({ message: "Upload failed", error: err.message });
  }
};

export const listNotes = async (req, res) => {
  try {
    const notes = await Note.find()
      .sort({ createdAt: -1 })
      .select("title description fileName fileSize university course studyType year tags createdAt");

    res.json({
      success: true,
      notes: notes.map((note) => ({
        ...note.toObject(),
        fileUrl: `/api/notes/${note.id}/file`,
      })),
    });
  } catch (err) {
    console.error("List notes error:", err);
    res.status(500).json({ message: "Could not load notes", error: err.message });
  }
};

export const listMyNotes = async (req, res) => {
  try {
    const notes = await Note.find({ uploadedBy: req.user.id })
      .sort({ createdAt: -1 })
      .select("title description fileName fileSize university course studyType year tags createdAt");

    res.json({
      success: true,
      notes: notes.map((note) => ({
        ...note.toObject(),
        fileUrl: `/api/notes/${note.id}/file`,
      })),
    });
  } catch (err) {
    console.error("List user notes error:", err);
    res.status(500).json({ message: "Could not load your notes", error: err.message });
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
  } catch (err) {
    console.error("Delete note error:", err);
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
    downloadStream.on("error", (err) => {
      if (res.headersSent) {
        res.destroy(err);
      } else {
        res.status(404).json({ message: "Note file not found" });
      }
    });
    downloadStream.pipe(res);
  } catch (err) {
    console.error("Download note error:", err);
    res.status(500).json({ message: "Download failed", error: err.message });
  }
};
