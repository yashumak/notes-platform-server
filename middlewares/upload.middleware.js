// middlewares/upload.middleware.js
import multer from "multer";

const storage = multer.memoryStorage(); // keep file in memory so we can upload buffer to B2
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB limit (adjust as needed)
});

export default upload;
