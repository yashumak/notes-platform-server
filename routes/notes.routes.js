import express from "express";
import multer from "multer";
import path from "path";

const router = express.Router();

// Configure Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/notes"); // folder where files will be stored
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// Upload Route
router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const { title, description, university, course, studyType, year } = req.body;

    console.log("File received:", req.file);
    console.log("Body:", req.body);

    if (!req.file) {
      return res.status(400).json({ success: false, message: "File missing!" });
    }

    return res.json({
      success: true,
      message: "Upload successful!",
      file_url: `/uploads/notes/${req.file.filename}`,
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
