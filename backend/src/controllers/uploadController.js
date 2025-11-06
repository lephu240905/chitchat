import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Upload ảnh
export const uploadImage = (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "Không có file được upload" });
    }

    // Trả về URL để frontend có thể sử dụng
    // Trong production, bạn nên upload lên Cloudinary hoặc S3
    const fileUrl = `/uploads/images/${req.file.filename}`;
    
    return res.status(200).json({
      message: "Upload ảnh thành công",
      url: fileUrl,
      filename: req.file.filename,
    });
  } catch (error) {
    console.error("❌ Lỗi upload ảnh:", error);
    res.status(500).json({ message: "Lỗi upload ảnh" });
  }
};

// Upload audio
export const uploadAudio = (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "Không có file được upload" });
    }

    const fileUrl = `/uploads/audio/${req.file.filename}`;
    
    return res.status(200).json({
      message: "Upload audio thành công",
      url: fileUrl,
      filename: req.file.filename,
    });
  } catch (error) {
    console.error("❌ Lỗi upload audio:", error);
    res.status(500).json({ message: "Lỗi upload audio" });
  }
};

