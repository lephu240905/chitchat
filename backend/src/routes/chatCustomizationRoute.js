import express from "express";
import {
  getOrCreateCustomization,
  updateCustomization,
  deleteCustomization,
  getAllCustomizations,
} from "../controllers/chatCustomizationController.js";
import { protectedRoute } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Lấy hoặc tạo customization cho một chat
router.get("/:chatId", protectedRoute, getOrCreateCustomization);

// Cập nhật customization
router.put("/:chatId", protectedRoute, updateCustomization);

// Xóa customization
router.delete("/:chatId", protectedRoute, deleteCustomization);

// Lấy tất cả customizations của user
router.get("/", protectedRoute, getAllCustomizations);

export default router;

