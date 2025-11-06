import User from "../models/User.js";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const authMe = async (req, res) => {
  try {
    const user = req.user; // lấy từ protectedRoute
    return res.status(200).json({ user });
  } catch (error) {
    console.error("Lỗi khi gọi authMe:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id).select("-hashedPassword -__v");
    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy user" });
    }
    
    // Kiểm tra user có online không từ socket
    const io = req.app && req.app.get("io");
    let status = "offline";
    if (io) {
      const sockets = await io.fetchSockets();
      const isOnline = sockets.some((s) => s.handshake.query.userId === id);
      status = isOnline ? "online" : "offline";
    }
    
    const userWithStatus = {
      ...user.toObject(),
      status,
    };
    
    res.json(userWithStatus);
  } catch (err) {
    console.error("Lỗi getUserById:", err);
    res.status(500).json({ message: "Lỗi server" });
  }
};

// Cập nhật avatar
export const updateAvatar = async (req, res) => {
  try {
    const userId = req.user._id; // Lấy user từ protectedRoute
    if (!req.file) {
      return res.status(400).json({ message: "Không có file được upload" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy user" });
    }

    // Xóa avatar cũ nếu có
    if (user.avatarId) {
      const oldAvatarPath = path.join(__dirname, "../../uploads/avatars", user.avatarId);
      if (fs.existsSync(oldAvatarPath)) {
        fs.unlinkSync(oldAvatarPath);
      }
    }

    // Cập nhật avatar mới
    const fileUrl = `/uploads/avatars/${req.file.filename}`;
    user.avatarUrl = fileUrl;
    user.avatarId = req.file.filename;
    await user.save();

    // Emit socket event để bạn bè cập nhật avatar real-time
    const io = req.app.get("io");
    io.emit("user_avatar_updated", {
      userId: userId.toString(),
      avatarUrl: fileUrl,
    });

    res.status(200).json({
      message: "Cập nhật avatar thành công",
      avatarUrl: fileUrl,
    });
  } catch (error) {
    console.error("❌ Lỗi cập nhật avatar:", error);
    res.status(500).json({ message: "Lỗi cập nhật avatar" });
  }
};
