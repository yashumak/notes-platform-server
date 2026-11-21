import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import AdminAuditLog from "../models/AdminAuditLog.js";
import Note from "../models/Note.js";
import User from "../models/User.js";
import UserActivity from "../models/UserActivity.js";
import { AUTH_SESSION_SECONDS } from "../config/auth.js";
import { authCookieOptions } from "./auth.controller.js";
import { logError } from "../utils/logger.js";
import { getMaxNoteFileSizeBytes } from "../utils/fileValidation.js";
import { s3Storage } from "../services/s3Storage.js";
import { getAppSecrets } from "../config/secrets.js";

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const cleanQuery = (value, maxLength = 100) =>
  typeof value === "string" ? value.trim().slice(0, maxLength) : "";

const pagination = (query) => {
  const requestedPage = Number.parseInt(query.page, 10);
  const requestedLimit = Number.parseInt(query.limit, 10);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0
    ? Math.min(requestedPage, 100_000)
    : 1;
  const limit = Number.isSafeInteger(requestedLimit) && requestedLimit > 0
    ? Math.min(requestedLimit, 100)
    : 25;
  return { page, limit, skip: (page - 1) * limit };
};

const sendPage = (res, records, total, page, limit) =>
  res.json({
    records,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });

const auditedOperation = async (adminId, action, targetType, targetId, changedFields, operation) => {
  const entry = await AdminAuditLog.create({
    adminId,
    action,
    targetType,
    targetId: targetId ? String(targetId) : undefined,
    changedFields,
    status: "PENDING",
  });
  let result;
  try {
    result = await operation();
  } catch (error) {
    await AdminAuditLog.updateOne(
      { _id: entry._id, status: "PENDING" },
      { $set: { status: "FAILURE" } }
    ).catch(() => logError("admin.audit_finalize_failed"));
    throw error;
  }
  const completion = await AdminAuditLog.updateOne(
    { _id: entry._id, status: "PENDING" },
    { $set: { status: "SUCCESS" } }
  );
  if (completion.modifiedCount !== 1) {
    logError("admin.audit_finalize_failed");
    const error = new Error("Administrator action audit could not be finalized");
    error.code = "ADMIN_AUDIT_FAILED";
    throw error;
  }
  return result;
};

const audit = (req, action, targetType, targetId, changedFields, operation) =>
  auditedOperation(req.admin.id, action, targetType, targetId, changedFields, operation);

const trackActivity = async (userId, eventType, success, resourceId) => {
  try {
    await UserActivity.create({ userId, eventType, success, resourceId });
  } catch {
    logError("activity.record_failed");
  }
};

const userDto = (user) => ({
  id: String(user._id),
  userId: user.user_id,
  name: user.name,
  email: user.email,
  university: user.university,
  course: user.course,
  year: user.year,
  role: user.role || "USER",
  status: user.deletedAt ? "deleted" : user.accountStatus || "active",
  hasProfilePhoto: Boolean(user.profilePhotoS3Key || user.profilePhotoFileId),
  profilePhotoUrl: user.profilePhotoS3Key || user.profilePhotoFileId
    ? `/api/admin/media/profile/${user._id}/download`
    : null,
  registeredAt: user.createdAt,
  lastLoginAt: user.lastLoginAt || null,
});

const noteDto = (note, uploader) => ({
  id: String(note._id || note.id),
  title: note.title,
  description: note.description || "",
  fileName: note.fileName,
  contentType: note.contentType,
  fileSize: note.fileSize,
  university: note.university || "",
  course: note.course || "",
  subject: note.subject || "",
  category: note.category || note.studyType || "",
  year: note.year,
  tags: Array.isArray(note.tags) ? note.tags : [],
  visibility: note.visibility || "public",
  status: note.uploadStatus || "active",
  uploadedAt: note.createdAt,
  uploader: uploader
    ? { id: String(uploader._id), name: uploader.name, email: uploader.email }
    : null,
  downloadUrl: `/api/admin/media/note/${encodeURIComponent(String(note._id || note.id))}/download`,
});

const userSearchQuery = (query, { registrationOnly = false } = {}) => {
  const conditions = query.status === "deleted"
    ? [{ deletedAt: { $ne: null } }]
    : [{ deletedAt: null }];
  const search = cleanQuery(query.q);
  if (search) {
    const matcher = new RegExp(escapeRegex(search), "i");
    conditions.push({
      $or: [
        { name: matcher },
        { email: matcher },
        { university: matcher },
        { course: matcher },
      ],
    });
  }
  for (const [parameter, field] of [
    ["university", "university"],
    ["course", "course"],
    ["year", "year"],
  ]) {
    const value = cleanQuery(query[parameter]);
    if (value) conditions.push({ [field]: new RegExp(escapeRegex(value), "i") });
  }
  if (query.status === "active" || query.status === "suspended") {
    conditions.push({ accountStatus: query.status });
  }
  if (query.from || query.to) {
    const createdAt = {};
    if (query.from) {
      const start = new Date(query.from);
      if (Number.isNaN(start.getTime())) return null;
      createdAt.$gte = start;
    }
    if (query.to) {
      const end = new Date(query.to);
      if (Number.isNaN(end.getTime())) return null;
      end.setUTCHours(23, 59, 59, 999);
      createdAt.$lte = end;
    }
    if (createdAt.$gte && createdAt.$lte && createdAt.$gte > createdAt.$lte) return null;
    conditions.push({ createdAt });
  }
  if (registrationOnly) conditions.push({ createdAt: { $exists: true } });
  return conditions.length === 1 ? conditions[0] : { $and: conditions };
};

export const adminLogin = async (req, res) => {
  try {
    const email = cleanQuery(req.body?.email, 254);
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const user = await User.findOne({ email }).select("+password role accountStatus deletedAt");
    if (!user || !(await bcrypt.compare(password, user.password))) {
      await trackActivity(user?._id, "ADMIN_LOGIN", false);
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (user.role !== "ADMIN" || (user.accountStatus && user.accountStatus !== "active") || user.deletedAt) {
      await trackActivity(user._id, "ADMIN_LOGIN", false);
      return res.status(403).json({ message: "Administrator access is required" });
    }

    await auditedOperation(user._id, "ADMIN_LOGIN", "ADMIN", user._id, [], async () => {
      user.lastLoginAt = new Date();
      await user.save();
    });
    await trackActivity(user._id, "ADMIN_LOGIN", true);
    const token = jwt.sign(
      { id: user._id, user_id: user.user_id },
      getAppSecrets().jwtSecret,
      { expiresIn: AUTH_SESSION_SECONDS, algorithm: "HS256" }
    );
    return res.cookie("token", token, {
      ...authCookieOptions,
      maxAge: AUTH_SESSION_SECONDS * 1000,
    }).json({ message: "Administrator login successful" });
  } catch {
    logError("admin.login_failed");
    return res.status(500).json({ message: "Could not complete administrator login" });
  }
};

export const adminLogout = async (req, res) => {
  if (req.user?.id) {
    try {
      const user = await User.findById(req.user.id).select("role");
      if (user?.role === "ADMIN") {
        await auditedOperation(user._id, "ADMIN_LOGOUT", "ADMIN", user._id, [], async () => {});
        await trackActivity(user._id, "ADMIN_LOGOUT", true);
      }
    } catch {
      logError("admin.logout_audit_failed");
    }
  }
  res.clearCookie("token", authCookieOptions);
  res.clearCookie("token", { ...authCookieOptions, path: "/api/auth" });
  return res.json({ message: "Logged out successfully" });
};

export const adminVerify = async (req, res) => {
  try {
    const user = await User.findById(req.admin.id).select(
      "name email role accountStatus deletedAt"
    );
    if (!user) return res.status(401).json({ message: "Administrator session is invalid" });
    res.setHeader("Cache-Control", "private, no-store");
    return res.json({
      isAuthenticated: true,
      admin: { id: String(user._id), name: user.name, email: user.email, role: user.role },
    });
  } catch {
    logError("admin.session_verification_failed");
    return res.status(503).json({ message: "Could not verify administrator session" });
  }
};

export const listUsers = async (req, res) => {
  const filter = userSearchQuery(req.query, { registrationOnly: req.path.includes("registrations") });
  if (!filter) return res.status(400).json({ message: "Invalid date filter" });
  const { page, limit, skip } = pagination(req.query);
  const sortBy = ["name", "email", "createdAt", "university", "course", "year"].includes(req.query.sort)
    ? req.query.sort
    : "createdAt";
  const direction = req.query.order === "asc" ? 1 : -1;
  try {
    if (req.query.format === "csv") {
      const csvCell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="registrations.csv"');
      res.write("Name,Email,University,Course,Year,Status,Registered At\r\n");
      const cursor = User.find(filter)
        .select("name email university course year role accountStatus deletedAt createdAt")
        .sort({ [sortBy]: direction })
        .cursor();
      for await (const user of cursor) {
        const row = [
          user.name,
          user.email,
          user.university,
          user.course,
          user.year,
          user.deletedAt ? "deleted" : user.accountStatus || "active",
          user.createdAt?.toISOString?.() || "",
        ];
        if (!res.write(`${row.map(csvCell).join(",")}\r\n`)) {
          await new Promise((resolve) => res.once("drain", resolve));
        }
      }
      return res.end();
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .select("user_id name email university course year role accountStatus deletedAt profilePhotoS3Key profilePhotoFileId createdAt lastLoginAt")
        .sort({ [sortBy]: direction })
        .skip(skip)
        .limit(limit),
      User.countDocuments(filter),
    ]);
    const records = users.map(userDto);
    res.setHeader("Cache-Control", "private, no-store");
    return sendPage(res, records, total, page, limit);
  } catch {
    logError("admin.users_list_failed");
    if (res.headersSent) return res.destroy();
    return res.status(500).json({ message: "Could not load users" });
  }
};

export const getUser = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID" });
  }
  try {
    const user = await User.findById(req.params.id).select(
      "user_id name email university course year role accountStatus deletedAt profilePhotoS3Key profilePhotoFileId profilePhotoContentType createdAt lastLoginAt"
    );
    if (!user || user.deletedAt) return res.status(404).json({ message: "User not found" });
    const [notes, s3Notes, activity] = await Promise.all([
      Note.find({ uploadedBy: user._id, uploadStatus: { $ne: "deleting" } })
        .select("title fileName fileSize visibility createdAt")
        .sort({ createdAt: -1 })
        .limit(50),
      s3Storage.listNoteRecordsForUser({ uploadedBy: user._id }),
      UserActivity.find({ userId: user._id }).sort({ occurredAt: -1 }).limit(20)
        .select("eventType success occurredAt resourceId"),
    ]);
    return res.json({
      user: userDto(user),
      notes: [
        ...notes.map((note) => noteDto(note, user)),
        ...s3Notes.filter((note) => note.uploadStatus !== "deleting").map((note) => noteDto(note, user)),
      ].sort((a, b) => new Date(b.uploadedAt).getTime() - new Date(a.uploadedAt).getTime()),
      activity,
    });
  } catch {
    logError("admin.user_detail_failed");
    return res.status(503).json({ message: "Could not load user details" });
  }
};

const PROFILE_FIELDS = ["name", "university", "course", "year"];
export const updateUser = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID" });
  }
  const changedFields = Object.keys(req.body || {});
  if (!changedFields.length || changedFields.some((field) => !PROFILE_FIELDS.includes(field))) {
    return res.status(400).json({ message: "Only name and academic profile fields may be updated" });
  }
  const updates = {};
  for (const field of changedFields) {
    const value = req.body[field];
    if (typeof value !== "string" || !value.trim() || value.trim().length > 200) {
      return res.status(400).json({ message: `Invalid ${field}` });
    }
    updates[field] = value.trim();
  }
  try {
    const existing = await User.findById(req.params.id).select("deletedAt");
    if (!existing || existing.deletedAt) return res.status(404).json({ message: "User not found" });
    const user = await audit(req, "UPDATE_USER", "USER", req.params.id, changedFields, async () => {
      const updated = await User.findByIdAndUpdate(
        req.params.id,
        { $set: updates },
        { new: true, runValidators: true, select: "user_id name email university course year role accountStatus deletedAt profilePhotoS3Key profilePhotoFileId createdAt lastLoginAt" }
      );
      if (!updated || updated.deletedAt) throw new Error("User no longer exists");
      return updated;
    });
    return res.json({ user: userDto(user) });
  } catch {
    logError("admin.user_update_failed");
    return res.status(500).json({ message: "Could not update user" });
  }
};

export const setUserStatus = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID" });
  }
  const status = req.body?.status;
  if (status !== "active" && status !== "suspended") {
    return res.status(400).json({ message: "Status must be active or suspended" });
  }
  if (String(req.params.id) === String(req.admin.id) && status !== "active") {
    return res.status(400).json({ message: "You cannot suspend your own administrator account" });
  }
  try {
    const target = await User.findById(req.params.id).select("role accountStatus deletedAt");
    if (!target || target.deletedAt) return res.status(404).json({ message: "User not found" });
    if (status === "suspended" && target.role === "ADMIN" && (!target.accountStatus || target.accountStatus === "active")) {
      const activeAdmins = await User.countDocuments({
        role: "ADMIN",
        deletedAt: null,
        $or: [{ accountStatus: "active" }, { accountStatus: { $exists: false } }],
      });
      if (activeAdmins <= 1) {
        return res.status(409).json({ message: "The last active administrator cannot be suspended" });
      }
    }
    await audit(
      req,
      status === "active" ? "ACTIVATE_USER" : "SUSPEND_USER",
      "USER",
      target._id,
      ["accountStatus"],
      async () => {
        target.accountStatus = status;
        await target.save();
      }
    );
    return res.json({ status });
  } catch {
    logError("admin.user_status_update_failed");
    return res.status(500).json({ message: "Could not update user status" });
  }
};

export const softDeleteUser = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID" });
  }
  if (String(req.params.id) === String(req.admin.id)) {
    return res.status(400).json({ message: "You cannot delete your own administrator account" });
  }
  try {
    const target = await User.findById(req.params.id).select("role accountStatus deletedAt");
    if (!target || target.deletedAt) return res.status(404).json({ message: "User not found" });
    if (target.role === "ADMIN" && (!target.accountStatus || target.accountStatus === "active")) {
      const activeAdmins = await User.countDocuments({
        role: "ADMIN",
        deletedAt: null,
        $or: [{ accountStatus: "active" }, { accountStatus: { $exists: false } }],
      });
      if (activeAdmins <= 1) {
        return res.status(409).json({ message: "The last active administrator cannot be deleted" });
      }
    }
    await audit(req, "SOFT_DELETE_USER", "USER", target._id, ["deletedAt", "accountStatus"], async () => {
      target.deletedAt = new Date();
      target.accountStatus = "suspended";
      await target.save();
    });
    return res.json({ message: "User was deactivated and marked for recoverable deletion" });
  } catch {
    logError("admin.user_delete_failed");
    return res.status(500).json({ message: "Could not mark user for deletion" });
  }
};

export const restoreUser = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid user ID" });
  }
  try {
    const target = await User.findById(req.params.id).select("deletedAt");
    if (!target || !target.deletedAt) return res.status(404).json({ message: "Deleted user not found" });
    await audit(req, "RESTORE_USER", "USER", target._id, ["deletedAt", "accountStatus"], async () => {
      target.deletedAt = null;
      target.accountStatus = "active";
      await target.save();
    });
    return res.json({ message: "User account restored" });
  } catch {
    logError("admin.user_restore_failed");
    return res.status(500).json({ message: "Could not restore user" });
  }
};

const noteQuery = (query, uploaderIds = []) => {
  const conditions = [
    query.status === "deleting"
      ? { uploadStatus: "deleting" }
      : { uploadStatus: { $ne: "deleting" } },
  ];
  const search = cleanQuery(query.q);
  if (search) {
    const matcher = new RegExp(escapeRegex(search), "i");
    const searchConditions = [
      { title: matcher },
      { description: matcher },
      { fileName: matcher },
      { university: matcher },
      { course: matcher },
      { subject: matcher },
    ];
    if (uploaderIds.length) searchConditions.push({ uploadedBy: { $in: uploaderIds } });
    conditions.push({
      $or: searchConditions,
    });
  }
  for (const [param, field] of [
    ["university", "university"],
    ["course", "course"],
    ["subject", "subject"],
    ["year", "year"],
    ["visibility", "visibility"],
    ["contentType", "contentType"],
  ]) {
    const value = cleanQuery(query[param]);
    if (value) conditions.push({ [field]: new RegExp(escapeRegex(value), "i") });
  }
  const category = cleanQuery(query.category);
  if (category) {
    const matcher = new RegExp(escapeRegex(category), "i");
    conditions.push({ $or: [{ category: matcher }, { studyType: matcher }] });
  }
  if (query.from || query.to) {
    const createdAt = {};
    if (query.from) {
      createdAt.$gte = new Date(query.from);
      if (Number.isNaN(createdAt.$gte.getTime())) return null;
    }
    if (query.to) {
      createdAt.$lte = new Date(query.to);
      if (Number.isNaN(createdAt.$lte.getTime())) return null;
      createdAt.$lte.setUTCHours(23, 59, 59, 999);
    }
    if (createdAt.$gte && createdAt.$lte && createdAt.$gte > createdAt.$lte) return null;
    conditions.push({ createdAt });
  }
  return conditions.length === 1 ? conditions[0] : { $and: conditions };
};

const matchesS3Note = (note, query, uploader) => {
  const q = cleanQuery(query.q).toLowerCase();
  const searchable = [
    note.title, note.description, note.fileName, note.university,
    note.course, note.subject, note.category, note.studyType,
    uploader?.name, uploader?.email,
  ].filter(Boolean).join(" ").toLowerCase();
  if (q && !searchable.includes(q)) return false;
  for (const field of ["university", "course", "subject", "category", "year", "visibility"]) {
    const value = cleanQuery(query[field]).toLowerCase();
    const actual = String(note[field] || (field === "category" ? note.studyType : "") || "").toLowerCase();
    if (value && !actual.includes(value)) return false;
  }
  const contentType = cleanQuery(query.contentType).toLowerCase();
  if (contentType && !String(note.contentType || "").toLowerCase().includes(contentType)) return false;
  if (query.from) {
    const from = new Date(query.from);
    if (Number.isNaN(from.getTime()) || new Date(note.createdAt).getTime() < from.getTime()) return false;
  }
  if (query.to) {
    const to = new Date(query.to);
    if (Number.isNaN(to.getTime())) return false;
    to.setUTCHours(23, 59, 59, 999);
    if (new Date(note.createdAt).getTime() > to.getTime()) return false;
  }
  return query.status === "deleting"
    ? note.uploadStatus === "deleting"
    : note.uploadStatus !== "deleting";
};

export const listNotes = async (req, res) => {
  const { page, limit, skip } = pagination(req.query);
  const search = cleanQuery(req.query.q);
  const sortBy = ["createdAt", "title", "fileSize"].includes(req.query.sort) ? req.query.sort : "createdAt";
  const direction = req.query.order === "asc" ? 1 : -1;
  try {
    let uploaderIds = [];
    if (search) {
      const matcher = new RegExp(escapeRegex(search), "i");
      const users = await User.find({ $or: [{ name: matcher }, { email: matcher }] }).select("_id");
      uploaderIds = users.map((user) => user._id);
    }
    const filter = noteQuery(req.query, uploaderIds);
    if (!filter) return res.status(400).json({ message: "Invalid note date filter" });
    const [mongoNotes, mongoTotal] = await Promise.all([
      Note.find(filter).select("title description fileName contentType fileSize university course subject category studyType year tags visibility uploadStatus uploadedBy createdAt")
        .sort({ [sortBy]: direction }).skip(skip).limit(limit),
      Note.countDocuments(filter),
    ]);
    const mongoUploaderIds = [...new Set(mongoNotes.map((note) => String(note.uploadedBy)))];
    const mongoUploaders = await User.find({ _id: { $in: mongoUploaderIds } }).select("name email");
    const mongoUploaderById = new Map(mongoUploaders.map((user) => [String(user._id), user]));
    const merged = mongoNotes.map((note) => noteDto(note, mongoUploaderById.get(String(note.uploadedBy))));
    res.setHeader("Cache-Control", "private, no-store");
    return sendPage(res, merged, mongoTotal, page, limit);
  } catch {
    logError("admin.notes_list_failed");
    return res.status(503).json({ message: "Could not load notes from the configured storage" });
  }
};

const findAdminNote = async (id) => {
  if (!mongoose.isValidObjectId(id)) return null;
  const note = await Note.findById(id);
  return note ? { kind: "mongo", note } : null;
};

export const getAdminNote = async (req, res) => {
  try {
    const found = await findAdminNote(req.params.id);
    if (!found || found.note.uploadStatus === "deleting") {
      return res.status(404).json({ message: "Note not found" });
    }
    const uploaderId = String(found.note.uploadedBy || "");
    const uploader = mongoose.isValidObjectId(uploaderId)
      ? await User.findById(uploaderId).select("name email")
      : null;
    return res.json({ note: noteDto(found.note, uploader) });
  } catch {
    logError("admin.note_detail_failed");
    return res.status(503).json({ message: "Could not load note details" });
  }
};

const NOTE_FIELDS = ["title", "description", "category", "subject", "visibility", "tags"];
export const updateNote = async (req, res) => {
  const fields = Object.keys(req.body || {});
  if (!fields.length || fields.some((field) => !NOTE_FIELDS.includes(field))) {
    return res.status(400).json({ message: "Only note metadata fields may be updated" });
  }
  const updates = {};
  for (const field of fields) {
    const value = req.body[field];
    if (field === "visibility") {
      if (!["public", "private"].includes(value)) return res.status(400).json({ message: "Invalid visibility" });
      updates.visibility = value;
    } else if (field === "tags") {
      if (!Array.isArray(value) || value.length > 20 || value.some((tag) => typeof tag !== "string" || tag.length > 50)) {
        return res.status(400).json({ message: "Tags must be an array of up to 20 short strings" });
      }
      updates.tags = value.map((tag) => tag.trim()).filter(Boolean);
    } else {
      const max = field === "description" ? 2000 : 200;
      if (typeof value !== "string" || value.trim().length > max || (field === "title" && !value.trim())) {
        return res.status(400).json({ message: `Invalid ${field}` });
      }
      updates[field] = value.trim();
      if (field === "category") updates.studyType = value.trim();
    }
  }
  try {
    const found = await findAdminNote(req.params.id);
    if (!found || found.note.uploadStatus === "deleting") return res.status(404).json({ message: "Note not found" });
    await audit(req, "UPDATE_NOTE", "NOTE", req.params.id, fields, async () => {
      await Note.updateOne({ _id: found.note._id }, { $set: updates }, { runValidators: true });
    });
    return res.json({ message: "Note updated" });
  } catch {
    logError("admin.note_update_failed");
    return res.status(500).json({ message: "Could not update note" });
  }
};

export const deleteNote = async (req, res) => {
  try {
    const found = await findAdminNote(req.params.id);
    if (!found) return res.status(404).json({ message: "Note not found" });
    const note = found.note;
    if (found.kind === "s3" && !note.s3Key) {
      return res.status(409).json({ message: "Note file association is invalid" });
    }
    await audit(req, "DELETE_NOTE", "NOTE", req.params.id, [], async () => {
      note.uploadStatus = "deleting";
      await note.save();
      if (note.s3Key) {
        const shared = await Note.exists({
          s3Key: note.s3Key,
          _id: { $ne: note._id },
          uploadStatus: { $ne: "deleting" },
        });
        if (!shared) await s3Storage.deleteObject(note.s3Key);
      } else if (note.fileId) {
        const shared = await Note.exists({
          fileId: note.fileId,
          _id: { $ne: note._id },
          uploadStatus: { $ne: "deleting" },
        });
        if (!shared) {
          const files = mongoose.connection.db.collection("noteFiles.files");
          if (await files.findOne({ _id: note.fileId })) {
            await new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: "noteFiles" }).delete(note.fileId);
          }
        }
      }
      await Note.deleteOne({ _id: note._id, uploadStatus: "deleting" });
    });
    return res.json({ message: "Note and its associated file were deleted" });
  } catch {
    logError("admin.note_delete_failed");
    return res.status(500).json({ message: "Could not complete note deletion; the record may be marked for retry" });
  }
};

export const getDashboard = async (_req, res) => {
  try {
    const [
      userStats,
      mongoNoteStats,
      recentUsers,
      recentMongoNotes,
      recentAdminActions,
      trackedDownloads,
    ] = await Promise.all([
      User.aggregate([
        { $match: { deletedAt: null } },
        { $group: { _id: "$accountStatus", count: { $sum: 1 } } },
      ]),
      Note.aggregate([
        { $match: { uploadStatus: { $ne: "deleting" } } },
        { $group: { _id: "$visibility", count: { $sum: 1 }, storageBytes: { $sum: "$fileSize" } } },
      ]),
      User.find({ deletedAt: null }).select("name email university createdAt").sort({ createdAt: -1 }).limit(8),
      Note.find({ uploadStatus: { $ne: "deleting" } }).select("title fileName fileSize visibility createdAt uploadedBy").sort({ createdAt: -1 }).limit(8),
      AdminAuditLog.find().populate({ path: "adminId", select: "name email" }).sort({ timestamp: -1 }).limit(6),
      UserActivity.countDocuments({ eventType: "NOTE_DOWNLOAD", success: true }),
    ]);
    const statusCounts = Object.fromEntries(userStats.map((item) => [item._id || "active", item.count]));
    const publicCount = mongoNoteStats.find((item) => item._id !== "private")?.count || 0;
    const privateCount = mongoNoteStats.find((item) => item._id === "private")?.count || 0;
    const mongoBytes = mongoNoteStats.reduce((total, item) => total + (item.storageBytes || 0), 0);
    const recentUsersOut = recentUsers.map(userDto);
    const recentUploaderIds = [...new Set(
      recentMongoNotes.map((note) => String(note.uploadedBy))
    ).filter((id) => mongoose.isValidObjectId(id))];
    const mongoUploaders = await User.find({ _id: { $in: recentUploaderIds } }).select("name email");
    const uploaderById = new Map(mongoUploaders.map((user) => [String(user._id), user]));
    const combinedRecentNotes = recentMongoNotes
      .map((note) => noteDto(note, uploaderById.get(String(note.uploadedBy))))
      .sort((a, b) => new Date(b.uploadedAt).getTime() - new Date(a.uploadedAt).getTime())
      .slice(0, 8);
    const since = new Date();
    since.setUTCDate(1);
    since.setUTCHours(0, 0, 0, 0);
    const newUsers = await User.countDocuments({ createdAt: { $gte: since }, deletedAt: null });
    const photos = await User.countDocuments({
      deletedAt: null,
      $or: [{ profilePhotoS3Key: { $exists: true, $ne: null } }, { profilePhotoFileId: { $exists: true, $ne: null } }],
    });
    res.setHeader("Cache-Control", "private, no-store");
    return res.json({
      stats: {
        totalUsers: Object.values(statusCounts).reduce((sum, count) => sum + count, 0),
        activeUsers: statusCounts.active || 0,
        suspendedUsers: statusCounts.suspended || 0,
        newRegistrationsThisMonth: newUsers,
        totalNotes: mongoNoteStats.reduce((sum, item) => sum + item.count, 0),
        publicNotes: publicCount,
        privateNotes: privateCount,
        noteFiles: mongoNoteStats.reduce((sum, item) => sum + item.count, 0),
        profilePhotos: photos,
        trackedDownloads,
        knownNoteStorageBytes: mongoBytes,
      },
      recentRegistrations: recentUsersOut,
      recentNotes: combinedRecentNotes,
      recentAdminActions,
    });
  } catch {
    logError("admin.dashboard_load_failed");
    return res.status(503).json({ message: "Could not load live dashboard data" });
  }
};

export const getAnalytics = async (req, res) => {
  const dateRange = {};
  if (req.query.from) {
    dateRange.$gte = new Date(req.query.from);
    if (Number.isNaN(dateRange.$gte.getTime())) return res.status(400).json({ message: "Invalid start date" });
  }
  if (req.query.to) {
    dateRange.$lte = new Date(req.query.to);
    if (Number.isNaN(dateRange.$lte.getTime())) return res.status(400).json({ message: "Invalid end date" });
    dateRange.$lte.setUTCHours(23, 59, 59, 999);
  }
  const userMatch = { deletedAt: null, ...(Object.keys(dateRange).length ? { createdAt: dateRange } : {}) };
  const noteMatch = { uploadStatus: { $ne: "deleting" }, ...(Object.keys(dateRange).length ? { createdAt: dateRange } : {}) };
  const dateGroup = (format, source) => [
    { $match: source },
    { $group: { _id: { $dateToString: { format, date: "$createdAt" } }, count: { $sum: 1 } } },
    { $sort: { _id: 1 } },
  ];
  try {
    const [
      registrations,
      weeklyRegistrations,
      monthlyRegistrations,
      notesBySubject,
      notesByUniversity,
      noteStorage,
      mongoVisibility,
      loginActivity,
      downloadActivity,
      s3Notes,
    ] = await Promise.all([
      User.aggregate(dateGroup("%Y-%m-%d", userMatch)),
      User.aggregate(dateGroup("%G-W%V", userMatch)),
      User.aggregate(dateGroup("%Y-%m", userMatch)),
      Note.aggregate([
        { $match: noteMatch },
        { $group: { _id: { $ifNull: ["$subject", "Unspecified"] }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Note.aggregate([
        { $match: noteMatch },
        { $group: { _id: { $ifNull: ["$university", "Unspecified"] }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Note.aggregate([
        { $match: noteMatch },
        { $group: { _id: "$contentType", count: { $sum: 1 }, bytes: { $sum: "$fileSize" } } },
        { $sort: { count: -1 } },
      ]),
      Note.aggregate([
        { $match: noteMatch },
        { $group: { _id: { $ifNull: ["$visibility", "public"] }, count: { $sum: 1 } } },
      ]),
      UserActivity.aggregate([
        { $match: { eventType: "LOGIN", ...(Object.keys(dateRange).length ? { occurredAt: dateRange } : {}) } },
        { $group: { _id: { day: { $dateToString: { format: "%Y-%m-%d", date: "$occurredAt" } }, success: "$success" }, count: { $sum: 1 } } },
        { $sort: { "_id.day": 1 } },
      ]),
      UserActivity.aggregate([
        { $match: { eventType: "NOTE_DOWNLOAD", success: true, ...(Object.keys(dateRange).length ? { occurredAt: dateRange } : {}) } },
        { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$occurredAt" } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]),
      s3Storage.listNoteRecords(),
    ]);
    const inRangeS3 = s3Notes.filter((note) => {
      if (note.uploadStatus === "deleting") return false;
      const createdAt = new Date(note.createdAt).getTime();
      return (!dateRange.$gte || createdAt >= dateRange.$gte.getTime()) &&
        (!dateRange.$lte || createdAt <= dateRange.$lte.getTime());
    });
    const addCounts = (first, second) => {
      const values = new Map(first.map((item) => [String(item._id), { _id: String(item._id), count: item.count || 0, bytes: item.bytes || 0 }]));
      for (const item of second) {
        const key = String(item._id || "Unspecified");
        const current = values.get(key) || { _id: key, count: 0, bytes: 0 };
        current.count += item.count || 0;
        current.bytes += item.bytes || 0;
        values.set(key, current);
      }
      return [...values.values()].sort((a, b) => b.count - a.count);
    };
    const s3SubjectCounts = new Map();
    const s3UniversityCounts = new Map();
    const s3FileTypeCounts = new Map();
    const s3VisibilityCounts = new Map();
    for (const note of inRangeS3) {
      const increment = (map, key, bytes = 0) => {
        const entry = map.get(key) || { _id: key, count: 0, bytes: 0 };
        entry.count += 1;
        entry.bytes += bytes;
        map.set(key, entry);
      };
      increment(s3SubjectCounts, note.subject || "Unspecified");
      increment(s3UniversityCounts, note.university || "Unspecified");
      increment(s3FileTypeCounts, note.contentType || "Unspecified", Number(note.fileSize) || 0);
      increment(s3VisibilityCounts, note.visibility === "private" ? "private" : "public");
    }
    return res.json({
      registrations,
      weeklyRegistrations,
      monthlyRegistrations,
      loginActivity,
      downloadActivity,
      notesBySubject: addCounts(notesBySubject, [...s3SubjectCounts.values()]).slice(0, 10),
      notesByUniversity: addCounts(notesByUniversity, [...s3UniversityCounts.values()]).slice(0, 10),
      noteStorageByType: addCounts(noteStorage, [...s3FileTypeCounts.values()]),
      notesByVisibility: addCounts(mongoVisibility, [...s3VisibilityCounts.values()]),
      s3NoteCount: inRangeS3.length,
      s3NoteStorageBytes: inRangeS3
        .reduce((sum, note) => sum + (Number(note.fileSize) || 0), 0),
    });
  } catch {
    logError("admin.analytics_load_failed");
    return res.status(503).json({ message: "Could not load analytics from the configured storage" });
  }
};

export const listActivity = async (req, res) => {
  const { page, limit, skip } = pagination(req.query);
  const filter = {};
  if (req.query.type) filter.eventType = cleanQuery(req.query.type, 80);
  if (req.query.success === "true" || req.query.success === "false") {
    filter.success = req.query.success === "true";
  }
  if (req.query.from || req.query.to) {
    const range = {};
    if (req.query.from) {
      range.$gte = new Date(req.query.from);
      if (Number.isNaN(range.$gte.getTime())) return res.status(400).json({ message: "Invalid start date" });
    }
    if (req.query.to) {
      range.$lte = new Date(req.query.to);
      if (Number.isNaN(range.$lte.getTime())) return res.status(400).json({ message: "Invalid end date" });
      range.$lte.setUTCHours(23, 59, 59, 999);
    }
    if (range.$gte && range.$lte && range.$gte > range.$lte) {
      return res.status(400).json({ message: "Start date must not be after end date" });
    }
    filter.occurredAt = range;
  }
  try {
    const [records, total] = await Promise.all([
      UserActivity.find(filter).populate({ path: "userId", select: "name email" })
        .sort({ occurredAt: -1 }).skip(skip).limit(limit)
        .select("userId eventType success resourceId occurredAt"),
      UserActivity.countDocuments(filter),
    ]);
    return sendPage(res, records, total, page, limit);
  } catch {
    logError("admin.activity_list_failed");
    return res.status(500).json({ message: "Could not load activity records" });
  }
};

export const listAuditLogs = async (req, res) => {
  const { page, limit, skip } = pagination(req.query);
  const filter = {};
  if (req.query.action) filter.action = cleanQuery(req.query.action, 80);
  if (req.query.targetType) filter.targetType = cleanQuery(req.query.targetType, 40);
  if (req.query.from || req.query.to) {
    const range = {};
    if (req.query.from) {
      range.$gte = new Date(req.query.from);
      if (Number.isNaN(range.$gte.getTime())) return res.status(400).json({ message: "Invalid start date" });
    }
    if (req.query.to) {
      range.$lte = new Date(req.query.to);
      if (Number.isNaN(range.$lte.getTime())) return res.status(400).json({ message: "Invalid end date" });
      range.$lte.setUTCHours(23, 59, 59, 999);
    }
    if (range.$gte && range.$lte && range.$gte > range.$lte) {
      return res.status(400).json({ message: "Start date must not be after end date" });
    }
    filter.timestamp = range;
  }
  try {
    const [records, total] = await Promise.all([
      AdminAuditLog.find(filter).populate({ path: "adminId", select: "name email" })
        .sort({ timestamp: -1 }).skip(skip).limit(limit),
      AdminAuditLog.countDocuments(filter),
    ]);
    return sendPage(res, records, total, page, limit);
  } catch {
    logError("admin.audit_list_failed");
    return res.status(500).json({ message: "Could not load audit logs" });
  }
};

export const listMedia = async (req, res) => {
  const { page, limit, skip } = pagination(req.query);
  const dateRange = {};
  if (req.query.from) {
    dateRange.$gte = new Date(req.query.from);
    if (Number.isNaN(dateRange.$gte.getTime())) return res.status(400).json({ message: "Invalid start date" });
  }
  if (req.query.to) {
    dateRange.$lte = new Date(req.query.to);
    if (Number.isNaN(dateRange.$lte.getTime())) return res.status(400).json({ message: "Invalid end date" });
    dateRange.$lte.setUTCHours(23, 59, 59, 999);
  }
  if (dateRange.$gte && dateRange.$lte && dateRange.$gte > dateRange.$lte) {
    return res.status(400).json({ message: "Start date must not be after end date" });
  }
  try {
    const [users, notes, s3Notes] = await Promise.all([
      User.find({
        deletedAt: null,
        $or: [{ profilePhotoS3Key: { $exists: true, $ne: null } }, { profilePhotoFileId: { $exists: true, $ne: null } }],
      }).select("name email profilePhotoS3Key profilePhotoFileId profilePhotoContentType createdAt"),
      Note.find({ uploadStatus: { $ne: "deleting" } })
        .select("title fileName contentType fileSize uploadedBy createdAt").sort({ createdAt: -1 }),
      s3Storage.listNoteRecords(),
    ]);
    const ownerIds = [...new Set([...notes, ...s3Notes]
      .map((note) => String(note.uploadedBy || ""))
      .filter((id) => mongoose.isValidObjectId(id)))];
    const noteOwners = ownerIds.length
      ? await User.find({ _id: { $in: ownerIds } }).select("name email")
      : [];
    const userMap = new Map([...users, ...noteOwners].map((user) => [String(user._id), user]));
    const media = [
      ...users.map((user) => ({
        id: `profile:${user._id}`,
        kind: "profile",
        fileName: `${user.name || "User"} profile photo`,
        contentType: user.profilePhotoContentType || "image",
        sizeBytes: null,
        owner: { id: String(user._id), name: user.name, email: user.email },
        createdAt: user.createdAt,
        downloadUrl: `/api/admin/media/profile/${user._id}/download`,
      })),
      ...notes.map((note) => ({
        id: `note:${note._id}`,
        kind: "note",
        fileName: note.fileName,
        contentType: note.contentType,
        sizeBytes: note.fileSize,
        owner: userMap.get(String(note.uploadedBy))
          ? { id: String(note.uploadedBy), name: userMap.get(String(note.uploadedBy)).name, email: userMap.get(String(note.uploadedBy)).email }
          : null,
        createdAt: note.createdAt,
        downloadUrl: `/api/admin/media/note/${note._id}/download`,
      })),
      ...s3Notes.filter((note) => note.uploadStatus !== "deleting").map((note) => {
        const owner = userMap.get(String(note.uploadedBy));
        return {
          id: `note:${note._id}`,
          kind: "note",
          fileName: note.fileName,
          contentType: note.contentType,
          sizeBytes: note.fileSize,
          owner: owner ? { id: String(owner._id), name: owner.name, email: owner.email } : null,
          createdAt: note.createdAt,
          downloadUrl: `/api/admin/media/note/${encodeURIComponent(String(note._id))}/download`,
        };
      }),
    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    const query = cleanQuery(req.query.q).toLowerCase();
    const kind = cleanQuery(req.query.kind).toLowerCase();
    const type = cleanQuery(req.query.type);
    const filtered = media.filter((item) => {
      if (query && !`${item.fileName} ${item.contentType} ${item.owner?.name || ""} ${item.owner?.email || ""}`.toLowerCase().includes(query)) return false;
      if (kind && item.kind !== kind) return false;
      if (type && !item.contentType.toLowerCase().includes(type.toLowerCase())) return false;
      const createdAt = new Date(item.createdAt).getTime();
      if (dateRange.$gte && createdAt < dateRange.$gte.getTime()) return false;
      if (dateRange.$lte && createdAt > dateRange.$lte.getTime()) return false;
      return true;
    });
    return sendPage(res, filtered.slice(skip, skip + limit), filtered.length, page, limit);
  } catch {
    logError("admin.media_list_failed");
    return res.status(503).json({ message: "Could not load media records" });
  }
};

export const downloadMedia = async (req, res) => {
  const { kind, id } = req.params;
  try {
    if (kind === "profile") {
      if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user ID" });
      const user = await User.findById(id).select("profilePhotoS3Key profilePhotoFileId profilePhotoContentType");
      if (!user || (!user.profilePhotoS3Key && !user.profilePhotoFileId)) {
        return res.status(404).json({ message: "Profile photo not found" });
      }
      if (user.profilePhotoS3Key) {
        const url = await s3Storage.createProfilePhotoUrl({
          key: user.profilePhotoS3Key,
          contentType: user.profilePhotoContentType || "application/octet-stream",
        });
        res.setHeader("Cache-Control", "private, no-store");
        return res.redirect(302, url);
      }
      const stream = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: "profilePhotos" })
        .openDownloadStream(user.profilePhotoFileId);
      res.setHeader("Content-Type", user.profilePhotoContentType || "application/octet-stream");
      res.setHeader("Cache-Control", "private, no-store");
      stream.on("error", () => {
        if (res.headersSent) res.destroy();
        else res.status(404).json({ message: "Profile photo not found" });
      });
      return stream.pipe(res);
    }
    if (kind !== "note") return res.status(400).json({ message: "Invalid media type" });
    const found = await findAdminNote(id);
    if (!found || found.note.uploadStatus === "deleting") return res.status(404).json({ message: "File not found" });
    if (found.kind === "s3" || found.note.s3Key) {
      const url = await s3Storage.createDownloadUrl({
        key: found.note.s3Key,
        fileName: found.note.fileName,
        contentType: found.note.contentType,
      });
      res.setHeader("Cache-Control", "private, no-store");
      return res.redirect(302, url);
    }
    if (!found.note.fileId) return res.status(404).json({ message: "File not found" });
    const stream = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: "noteFiles" })
      .openDownloadStream(found.note.fileId);
    res.setHeader("Content-Type", found.note.contentType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(found.note.fileName || "download")}`);
    res.setHeader("Cache-Control", "private, no-store");
    stream.on("error", () => {
      if (res.headersSent) res.destroy();
      else res.status(404).json({ message: "File not found" });
    });
    return stream.pipe(res);
  } catch {
    logError("admin.media_download_failed");
    return res.status(503).json({ message: "Could not access the requested file" });
  }
};

export const deleteProfilePhoto = async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid user ID" });
  try {
    const user = await User.findById(req.params.id).select("profilePhotoS3Key profilePhotoFileId");
    if (!user || (!user.profilePhotoS3Key && !user.profilePhotoFileId)) {
      return res.status(404).json({ message: "Profile photo not found" });
    }
    await audit(req, "DELETE_PROFILE_PHOTO", "USER", user._id, ["profilePhoto"], async () => {
      if (user.profilePhotoS3Key) {
        const shared = await User.exists({
          profilePhotoS3Key: user.profilePhotoS3Key,
          _id: { $ne: user._id },
        });
        if (!shared) await s3Storage.deleteObject(user.profilePhotoS3Key);
      }
      if (user.profilePhotoFileId) {
        const shared = await User.exists({
          profilePhotoFileId: user.profilePhotoFileId,
          _id: { $ne: user._id },
        });
        if (shared) {
          user.profilePhotoS3Key = undefined;
          user.profilePhotoFileId = undefined;
          user.profilePhotoContentType = undefined;
          await user.save();
          return;
        }
        const files = mongoose.connection.db.collection("profilePhotos.files");
        if (await files.findOne({ _id: user.profilePhotoFileId })) {
          await new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: "profilePhotos" })
            .delete(user.profilePhotoFileId);
        }
      }
      user.profilePhotoS3Key = undefined;
      user.profilePhotoFileId = undefined;
      user.profilePhotoContentType = undefined;
      await user.save();
    });
    return res.json({ message: "Profile photo removed" });
  } catch {
    logError("admin.profile_photo_delete_failed");
    return res.status(500).json({ message: "Could not remove profile photo" });
  }
};

export const getSettings = (_req, res) => {
  try {
    return res.json({
      platformName: "NotesHub",
      uploadLimitBytes: getMaxNoteFileSizeBytes(),
      allowedUploadExtensions: [".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".txt", ".csv", ".md", ".json", ".xml", ".jpg", ".jpeg", ".png", ".gif", ".webp"],
      fileStorage: getAppSecrets().s3Bucket ? "S3 (private bucket)" : "S3 is not configured",
      note: "Runtime and credential settings are deployment-managed and cannot be changed from the admin panel.",
    });
  } catch {
    logError("admin.settings_load_failed");
    return res.status(500).json({ message: "Could not load effective settings" });
  }
};

export const logAdminLogout = async (req, res, next) => {
  try {
    await trackActivity(req.admin.id, "ADMIN_LOGOUT", true);
    return next();
  } catch {
    logError("admin.logout_activity_failed");
    return res.status(500).json({ message: "Could not complete administrator logout" });
  }
};
