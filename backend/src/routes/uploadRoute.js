import express from "express";
import { protectedRoute } from "../middlewares/authMiddleware.js";
import { uploadImage as uploadImageMw, uploadAudio as uploadAudioMw } from "../middlewares/uploadMiddleware.js";
import { uploadImage, uploadAudio } from "../controllers/uploadController.js";

const router = express.Router();

// Upload ảnh
router.post(
  "/image",
  protectedRoute,
  uploadImageMw.single("image"),
  uploadImage
);

// Upload audio
router.post(
  "/audio",
  protectedRoute,
  uploadAudioMw.single("audio"),
  uploadAudio
);

export default router;

