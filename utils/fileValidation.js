const signatures = {
  "application/pdf": [Buffer.from("%PDF-")],
  "image/jpeg": [Buffer.from([0xff, 0xd8, 0xff])],
  "image/png": [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
  "image/gif": [Buffer.from("GIF87a"), Buffer.from("GIF89a")],
  "image/webp": [Buffer.from("RIFF"), Buffer.from("WEBP")],
  "application/msword": [Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
  "application/vnd.ms-powerpoint": [Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
  "application/vnd.ms-excel": [Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])],
  "application/zip": [Buffer.from([0x50, 0x4b, 0x03, 0x04])],
  "application/x-zip-compressed": [Buffer.from([0x50, 0x4b, 0x03, 0x04])],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  ],
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": [
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  ],
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  ],
};

const fileTypes = new Map([
  [".pdf", ["application/pdf"]],
  [".doc", ["application/msword"]],
  [".docx", ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]],
  [".ppt", ["application/vnd.ms-powerpoint"]],
  [".pptx", ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]],
  [".xls", ["application/vnd.ms-excel"]],
  [".xlsx", ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]],
  [".txt", ["text/plain"]],
  [".csv", ["text/csv"]],
  [".md", ["text/markdown", "text/plain"]],
  [".json", ["application/json"]],
  [".xml", ["application/xml", "text/xml"]],
  [".jpg", ["image/jpeg"]],
  [".jpeg", ["image/jpeg"]],
  [".png", ["image/png"]],
  [".gif", ["image/gif"]],
  [".webp", ["image/webp"]],
]);

const textTypes = new Set([
  "text/plain",
  "text/csv",
  "text/markdown",
  "application/json",
  "application/xml",
  "text/xml",
]);

export const getMaxNoteFileSizeBytes = () => {
  const configured = process.env.MAX_NOTE_FILE_SIZE_BYTES;
  if (configured === undefined || configured.trim() === "") return 50 * 1024 * 1024;
  const size = Number(configured);
  if (!Number.isSafeInteger(size) || size < 1 || size > 5_000_000_000) {
    throw new Error("MAX_NOTE_FILE_SIZE_BYTES must be an integer between 1 and 5000000000");
  }
  return size;
};

export const sanitizeFileName = (fileName) => {
  const basename = String(fileName || "")
    .split(/[\\/]/)
    .pop()
    ?.normalize("NFC")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 200);
  return basename || "upload";
};

export const validateFileMetadata = ({ fileName, fileSize }) => {
  const safeName = sanitizeFileName(fileName);
  const extension = safeName.slice(safeName.lastIndexOf(".")).toLowerCase();
  const allowedMimeTypes = fileTypes.get(extension);

  if (!allowedMimeTypes) {
    return { valid: false, message: "Unsupported file extension or MIME type" };
  }
  const normalizedContentType = allowedMimeTypes[0];
  if (!Number.isSafeInteger(fileSize) || fileSize <= 0) {
    return { valid: false, message: "File size must be greater than zero" };
  }
  const maxFileSizeBytes = getMaxNoteFileSizeBytes();
  if (fileSize > maxFileSizeBytes) {
    return {
      valid: false,
      tooLarge: true,
      message: `File exceeds the ${Math.floor(maxFileSizeBytes / (1024 * 1024))} MB limit`,
    };
  }

  return { valid: true, safeName, contentType: normalizedContentType, fileSize };
};

export const hasValidFileSignature = ({ buffer, mimetype, contentType = mimetype }) => {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return false;
  if (textTypes.has(contentType)) return !buffer.includes(0);

  const expected = signatures[contentType];
  if (!expected) return false;

  if (contentType === "image/webp") {
    return (
      buffer.length >= 12 &&
      buffer.subarray(0, 4).equals(expected[0]) &&
      buffer.subarray(8, 12).equals(expected[1])
    );
  }
  return expected.some(
    (signature) =>
      buffer.length >= signature.length &&
      buffer.subarray(0, signature.length).equals(signature)
  );
};
