import express from "express";
import { authMe, getUserById, updateAvatar } from "../controllers/userController.js";
import { uploadAvatar } from "../middlewares/uploadMiddleware.js";

const router = express.Router();

router.get("/me", authMe);

router.put("/me/avatar", uploadAvatar.single("avatar"), updateAvatar);

router.get("/:id", getUserById);

export default router;
