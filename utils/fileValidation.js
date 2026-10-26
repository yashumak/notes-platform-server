const signatures = {
  "application/pdf": [Buffer.from("%PDF-")],
  "image/jpeg": [Buffer.from([0xff, 0xd8, 0xff])],
  "image/png": [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
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

export const hasValidFileSignature = ({ buffer, mimetype }) => {
  if (!Buffer.isBuffer(buffer)) return false;
  if (mimetype === "text/plain" || mimetype === "text/csv") {
    return !buffer.includes(0);
  }

  const expected = signatures[mimetype];
  if (!expected) return false;

  if (mimetype === "image/webp") {
    return (
      buffer.length >= 12 &&
      buffer.subarray(0, 4).equals(expected[0]) &&
      buffer.subarray(8, 12).equals(expected[1])
    );
  }

  return buffer.length >= expected[0].length && buffer.subarray(0, expected[0].length).equals(expected[0]);
};
