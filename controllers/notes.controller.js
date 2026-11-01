// controllers/notes.controller.js
import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { logError } from "../utils/logger.js";
import {
  getMaxNoteFileSizeBytes,
  sanitizeFileName,
  validateFileMetadata,
} from "../utils/fileValidation.js";
import { s3Storage, UPLOAD_URL_TTL_SECONDS } from "../services/s3Storage.js";
import Note from "../models/Note.js";
import User from "../models/User.js";

const getNoteFilesBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: "noteFiles",
  });

const UPLOAD_TOKEN_TTL_SECONDS = 15 * 60;
const UPLOAD_TOKEN_ISSUER = "noteshub-s3-upload";
const UPLOAD_TOKEN_AUDIENCE = "noteshub-s3-upload";
const NOTE_RECORD_ID_PATTERN =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[a-z0-9-]{1,220})$/i;

const cleanText = (value, maxLength) =>
  typeof value === "string" ? value.trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, maxLength) : "";

const toS3PathSegment = (value, fallback, maxLength) => {
  const segment = String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLength)
    .replace(/-+$/g, "");
  return segment || fallback;
};

const makeUploadMetadata = (body, safeName) => {
  const visibility = body.visibility === undefined ? "public" : body.visibility;
  if (visibility !== "public" && visibility !== "private") return null;
  const year = body.year === "" || body.year === undefined ? undefined : Number(body.year);
  if (year !== undefined && (!Number.isInteger(year) || year < 1900 || year > 2100)) {
    return null;
  }
  const tags = Array.isArray(body.tags)
    ? body.tags
        .filter((tag) => typeof tag === "string")
        .slice(0, 20)
        .map((tag) => cleanText(tag, 50))
        .filter(Boolean)
    : [];
  return {
    title: cleanText(body.title, 200) || safeName,
    description: cleanText(body.description, 2000),
    university: cleanText(body.university, 200),
    course: cleanText(body.course || body.branch, 200),
    subject: cleanText(body.subject, 200),
    category: cleanText(body.category || body.studyType, 100),
    studyType: cleanText(body.studyType, 100),
    visibility,
    year,
    tags,
  };
};

const verifyUploadToken = (token, userId) => {
  try {
    const claims = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: UPLOAD_TOKEN_ISSUER,
      audience: UPLOAD_TOKEN_AUDIENCE,
    });
    if (
      typeof claims === "string" ||
      claims.sub !== String(userId) ||
      typeof claims.key !== "string" ||
      typeof claims.noteId !== "string" ||
      !NOTE_RECORD_ID_PATTERN.test(claims.noteId) ||
      !/^notes\/[a-z0-9-]+\/[a-z0-9-]+$/i.test(claims.key)
    ) {
      return null;
    }
    return claims;
  } catch {
    return null;
  }
};

const isStorageConfigurationError = (error) => error?.code === "S3_CONFIGURATION_MISSING";

const logNotesOperationFailure = (operation, error) => {
  const errorName =
    typeof error?.name === "string" && /^[a-zA-Z0-9_-]{1,60}$/.test(error.name)
      ? error.name
      : "UnknownError";
  const errorCode =
    (typeof error?.code === "string" || typeof error?.code === "number") &&
    /^[a-zA-Z0-9_-]{1,60}$/.test(String(error.code))
      ? String(error.code)
      : "NoCode";
  const status = Number.isInteger(error?.$metadata?.httpStatusCode)
    ? `.${error.$metadata.httpStatusCode}`
    : "";
  logError(`${operation}.${errorName}.${errorCode}${status}`);
};

const observeNotesOperation = (operation, promise) =>
  promise.catch((error) => {
    logNotesOperationFailure(operation, error);
    throw error;
  });

export const getNoteStats = async (_req, res) => {
  try {
    const s3Notes = (await observeNotesOperation(
      "notes.stats_s3_list_failed",
      s3Storage.listNoteRecords()
    )).filter((note) => note.visibility !== "private" && note.uploadStatus !== "deleting");
    const sharedNotes = {
      visibility: { $ne: "private" },
      uploadStatus: { $ne: "deleting" },
    };
    const [legacyTotal, universities, studyTypes] = await Promise.all([
      observeNotesOperation("notes.stats_mongo_count_failed", Note.countDocuments(sharedNotes)),
      observeNotesOperation("notes.stats_mongo_universities_failed", Note.distinct("university", sharedNotes)),
      observeNotesOperation("notes.stats_mongo_study_types_failed", Note.distinct("studyType", sharedNotes)),
    ]);

    res.json({
      success: true,
      stats: {
        total: legacyTotal + s3Notes.length,
        universities: new Set([
          ...universities.filter((value) => typeof value === "string" && value.trim()),
          ...s3Notes.map((note) => note.university).filter((value) => typeof value === "string" && value.trim()),
        ]).size,
        studyTypes: new Set([
          ...studyTypes.filter((value) => typeof value === "string" && value.trim()),
          ...s3Notes.map((note) => note.studyType).filter((value) => typeof value === "string" && value.trim()),
        ]).size,
      },
    });
  } catch (error) {
    logNotesOperationFailure("notes.stats_failed", error);
    res.status(isStorageConfigurationError(error) ? 503 : 500).json({
      message: isStorageConfigurationError(error)
        ? "Notes storage is not configured"
        : "Could not load note statistics",
    });
  }
};

export const createNoteUploadUrl = async (req, res) => {
  try {
    const body = req.body || {};
    const file = validateFileMetadata({
      fileName: body.fileName,
      contentType: body.contentType,
      fileSize: body.fileSize,
    });
    if (!file.valid) {
      return res.status(file.tooLarge ? 413 : 400).json({ message: file.message });
    }

    const metadata = makeUploadMetadata(body, file.safeName);
    if (!metadata) {
      return res.status(400).json({ message: "Academic year must be a valid year" });
    }
    const userId = req.user.user_id;
    if (typeof userId !== "string" || !/^\d{10}$/.test(userId)) {
      return res.status(401).json({ message: "User identity is invalid. Please log in again." });
    }
    const account = await User.findById(req.user.id).select("name");
    if (!account) {
      return res.status(401).json({ message: "User account was not found. Please log in again." });
    }
    const usernameSegment = toS3PathSegment(account.name, "user", 60);
    const titleSegment = toS3PathSegment(metadata.title, "note", 80);
    const noteId = `${titleSegment}-${userId}-${randomUUID()}`;
    const key = `notes/${usernameSegment}-${userId}/${noteId}`;
    const uploadToken = jwt.sign(
      {
        sub: String(req.user.id),
        userId,
        key,
        noteId,
        fileName: file.safeName,
        contentType: file.contentType,
        fileSize: file.fileSize,
        ...metadata,
      },
      process.env.JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: UPLOAD_TOKEN_TTL_SECONDS,
        issuer: UPLOAD_TOKEN_ISSUER,
        audience: UPLOAD_TOKEN_AUDIENCE,
      }
    );
    const uploadUrl = await s3Storage.createUploadUrl({
      key,
      contentType: file.contentType,
      fileSize: file.fileSize,
    });
    return res.status(201).json({
      success: true,
      uploadUrl,
      uploadToken,
      headers: {
        "Content-Type": file.contentType,
        "x-amz-server-side-encryption": "AES256",
      },
      expiresIn: UPLOAD_URL_TTL_SECONDS,
      maxFileSizeBytes: getMaxNoteFileSizeBytes(),
    });
  } catch (error) {
    if (isStorageConfigurationError(error)) {
      logError("notes.storage_not_configured");
      return res.status(503).json({ message: "File storage is not configured" });
    }
    logError("notes.upload_presign_failed");
    return res.status(500).json({ message: "Could not prepare file upload" });
  }
};

export const completeNoteUpload = async (req, res) => {
  const claims = verifyUploadToken(req.body?.uploadToken, req.user.id);
  if (!claims) {
    return res.status(400).json({ message: "Upload authorization is invalid or expired" });
  }

  let objectVerified = false;
  try {
    const existingNote = await s3Storage.getNoteRecord(claims.noteId);
    if (existingNote) {
      if (
        String(existingNote.uploadedBy) !== String(req.user.id) ||
        existingNote.s3Key !== claims.key
      ) {
        return res.status(404).json({ message: "Note not found" });
      }
      return res.status(200).json({
        success: true,
        message: "Note upload was already completed",
        note: serializeNote(existingNote),
      });
    }

    const conflictingLegacyNote = await Note.findOne({ s3Key: claims.key });
    if (conflictingLegacyNote) {
      return res.status(409).json({ message: "This upload has already been associated with a note" });
    }

    await s3Storage.verifyUploadedObject({
      key: claims.key,
      contentType: claims.contentType,
      fileSize: claims.fileSize,
    });
    objectVerified = true;

    const note = {
      _id: claims.noteId,
      title: claims.title,
      description: claims.description,
      university: claims.university || undefined,
      course: claims.course || undefined,
      subject: claims.subject || undefined,
      category: claims.category || undefined,
      studyType: claims.studyType || undefined,
      year: claims.year,
      tags: claims.tags,
      fileName: sanitizeFileName(claims.fileName),
      s3Key: claims.key,
      storageProvider: "s3",
      contentType: claims.contentType,
      fileSize: claims.fileSize,
      uploadedBy: claims.sub,
      visibility: claims.visibility,
      uploadStatus: "active",
      createdAt: new Date().toISOString(),
    };
    await s3Storage.putNoteRecord(note);
    return res.status(201).json({
      success: true,
      message: "Note uploaded",
      note: serializeNote(note),
    });
  } catch (error) {
    if (error?.code === "INVALID_S3_UPLOAD") {
      await s3Storage.deleteObject(claims.key).catch(() => {
        logError("notes.invalid_upload_cleanup_failed");
      });
      return res.status(400).json({ message: "Uploaded file did not match its validated metadata" });
    }
    if (isStorageConfigurationError(error)) {
      logError("notes.storage_not_configured");
      return res.status(503).json({ message: "File storage is not configured" });
    }

    if (objectVerified) {
      try {
        const savedNote = await s3Storage.getNoteRecord(claims.noteId);
        if (!savedNote) await s3Storage.deleteObject(claims.key);
      } catch {
        logError("notes.upload_cleanup_deferred");
      }
    }
    logError("notes.upload_complete_failed");
    return res.status(500).json({ message: "Could not save uploaded note" });
  }
};

const noteMatchesFilters = (note, filters) => {
  const searchText = [
    note.title,
    note.description,
    note.fileName,
    note.university,
    note.subject,
    note.course,
    note.studyType,
    note.year,
    ...(note.tags || []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  const searchTerms = filters.q.toLowerCase().split(/\s+/).filter(Boolean);
  const subjectTerms = filters.subject.toLowerCase().split(/\s+/).filter(Boolean);

  return (
    searchTerms.every((term) => searchText.includes(term)) &&
    (!filters.university || note.university?.toLowerCase().includes(filters.university.toLowerCase())) &&
    (!filters.course || note.course?.toLowerCase().includes(filters.course.toLowerCase())) &&
    subjectTerms.every((term) => searchText.includes(term)) &&
    (!filters.studyType || note.studyType === filters.studyType) &&
    (!filters.year || String(note.year || "") === filters.year)
  );
};

const compareNotesByCreatedAt = (first, second) =>
  new Date(second.createdAt).getTime() - new Date(first.createdAt).getTime();

export const listNotes = async (req, res) => {
  try {
    const requestedPage = Number.parseInt(req.query?.page, 10);
    const requestedLimit = Number.parseInt(req.query?.limit, 10);
    const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
    const limit = Number.isSafeInteger(requestedLimit) && requestedLimit > 0
      ? Math.min(requestedLimit, 30)
      : 30;
    const offset = (page - 1) * limit;
    const filters = {
      q: typeof req.query?.q === "string" ? req.query.q.trim() : "",
      university: typeof req.query?.university === "string" ? req.query.university.trim() : "",
      course: typeof req.query?.course === "string" ? req.query.course.trim() : "",
      subject: typeof req.query?.subject === "string" ? req.query.subject.trim() : "",
      studyType: typeof req.query?.studyType === "string" ? req.query.studyType.trim() : "",
      year: typeof req.query?.year === "string" ? req.query.year.trim() : "",
    };
    const hasFilters = Object.values(filters).some(Boolean);
    const publicNotesQuery = {
      visibility: { $ne: "private" },
      uploadStatus: { $ne: "deleting" },
    };

    let notes;
    let total;
    if (hasFilters) {
      const [s3Notes, legacyNotes] = await Promise.all([
        observeNotesOperation("notes.list_s3_failed", s3Storage.listNoteRecords()),
        observeNotesOperation("notes.list_mongo_failed", Note.find(publicNotesQuery)
          .select("title description fileName fileSize university course subject category studyType year tags visibility createdAt"),
        ),
      ]);
      const matchingNotes = [
        ...s3Notes.filter(
          (note) => note.visibility !== "private" &&
            note.uploadStatus !== "deleting" &&
            noteMatchesFilters(note, filters)
        ),
        ...legacyNotes.filter((note) => noteMatchesFilters(note, filters)),
      ].sort(compareNotesByCreatedAt);
      total = matchingNotes.length;
      notes = matchingNotes.slice(offset, offset + limit);
    } else {
      const [s3Page, legacyNotes, legacyTotal] = await Promise.all([
        observeNotesOperation("notes.list_s3_failed", s3Storage.listNoteRecordPage({ offset, limit })),
        observeNotesOperation("notes.list_mongo_page_failed", Note.find(publicNotesQuery)
          .sort({ createdAt: -1 })
          .skip(offset)
          .limit(limit)
          .select("title description fileName fileSize university course subject category studyType year tags visibility createdAt")),
        observeNotesOperation("notes.list_mongo_count_failed", Note.countDocuments(publicNotesQuery)),
      ]);
      notes = [
        ...s3Page.records.filter(
          (note) => note.visibility !== "private" && note.uploadStatus !== "deleting"
        ),
        ...legacyNotes,
      ].sort(compareNotesByCreatedAt).slice(0, limit);
      total = s3Page.total + legacyTotal;
    }

    res.json({
      success: true,
      notes: notes.map((note) => serializeNote(note)),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logNotesOperationFailure("notes.list_failed", error);
    res.status(isStorageConfigurationError(error) ? 503 : 500).json({
      message: isStorageConfigurationError(error)
        ? "Notes storage is not configured"
        : "Could not load notes",
    });
  }
};

export const listMyNotes = async (req, res) => {
  try {
    const [s3Notes, legacyNotes] = await Promise.all([
      s3Storage.listNoteRecords(),
      Note.find({ uploadedBy: req.user.id })
        .sort({ createdAt: -1 })
        .select("title description fileName fileSize university course subject category studyType year tags visibility createdAt"),
    ]);
    const notes = [
      ...s3Notes.filter((note) => String(note.uploadedBy) === String(req.user.id)),
      ...legacyNotes,
    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

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
    const s3Note = await s3Storage.getNoteRecord(req.params.id);
    if (s3Note) {
      if (String(s3Note.uploadedBy) !== String(req.user.id)) {
        return res.status(404).json({ message: "Note not found" });
      }
      if (!s3Note.s3Key || !s3Note._id) {
        logError("notes.s3_metadata_invalid");
        return res.status(500).json({ message: "Could not delete note" });
      }
      await s3Storage.putNoteRecord({ ...s3Note, uploadStatus: "deleting" });
      await s3Storage.deleteObject(s3Note.s3Key);
      await s3Storage.deleteNoteRecord(s3Note._id);
      return res.json({ success: true, message: "Note deleted successfully" });
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid note ID" });
    }

    const note = await Note.findOne({
      _id: req.params.id,
      uploadedBy: req.user.id,
    }).select("fileId s3Key storageProvider");

    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }

    if (note.s3Key) {
      await Note.updateOne(
        { _id: req.params.id, uploadedBy: req.user.id },
        { $set: { uploadStatus: "deleting" } }
      );
      await s3Storage.deleteObject(note.s3Key);
      await Note.deleteOne({ _id: req.params.id, uploadedBy: req.user.id });
    } else {
      await Note.updateOne(
        { _id: req.params.id, uploadedBy: req.user.id },
        { $set: { uploadStatus: "deleting" } }
      );
      await getNoteFilesBucket().delete(note.fileId);
      await Note.deleteOne({ _id: req.params.id, uploadedBy: req.user.id });
    }

    return res.json({ success: true, message: "Note deleted successfully" });
  } catch {
    logError("notes.delete_failed");
    return res.status(500).json({ message: "Could not delete note" });
  }
};

export const downloadNoteFile = async (req, res) => {
  try {
    const s3Note = await s3Storage.getNoteRecord(req.params.id);
    if (s3Note) {
      if (
        s3Note.uploadStatus === "deleting" ||
        (s3Note.visibility === "private" &&
          (!req.user || String(s3Note.uploadedBy) !== String(req.user.id)))
      ) {
        return res.status(404).json({ message: "Note file not found" });
      }
      const downloadUrl = await s3Storage.createDownloadUrl({
        key: s3Note.s3Key,
        fileName: s3Note.fileName,
        contentType: s3Note.contentType,
      });
      res.set("Cache-Control", "private, no-store");
      return res.redirect(302, downloadUrl);
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid note ID" });
    }

    const note = await Note.findById(req.params.id).select(
      "fileId s3Key fileName contentType uploadedBy visibility uploadStatus"
    );
    if (!note || note.uploadStatus === "deleting") {
      return res.status(404).json({ message: "Note file not found" });
    }
    if (
      note.visibility === "private" &&
      (!req.user || String(note.uploadedBy) !== String(req.user.id))
    ) {
      return res.status(404).json({ message: "Note file not found" });
    }

    if (note.s3Key) {
      const downloadUrl = await s3Storage.createDownloadUrl({
        key: note.s3Key,
        fileName: note.fileName,
        contentType: note.contentType,
      });
      res.set("Cache-Control", "private, no-store");
      return res.redirect(302, downloadUrl);
    }
    if (!note.fileId) return res.status(404).json({ message: "Note file not found" });

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

const serializeNote = (note) => {
  const id = note._id || note.id;
  return {
    _id: id,
    title: note.title,
    description: note.description,
    fileName: note.fileName,
    fileSize: note.fileSize,
    university: note.university,
    course: note.course,
    subject: note.subject,
    category: note.category,
    visibility: note.visibility || "public",
    studyType: note.studyType,
    year: note.year,
    tags: note.tags,
    createdAt: note.createdAt,
    fileUrl: `/api/notes/${encodeURIComponent(String(id))}/file`,
  };
};
