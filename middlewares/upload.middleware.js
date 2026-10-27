// middlewares/upload.middleware.js
import multer from "multer";

const allowedTypes = new Set([
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/zip",
  "application/x-zip-compressed",
  "text/plain",
  "text/csv",
  "image/jpeg",
  "image/png",
  "image/webp",
]);

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024,
    fieldSize: 64 * 1024,
    fields: 20,
    parts: 21,
  },
  fileFilter: (_req, file, callback) => {
    if (allowedTypes.has(file.mimetype)) return callback(null, true);
    callback(new Error("Unsupported file type"));
  },
});

export default upload;
