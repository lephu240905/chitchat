import express from "express";
import {
  createGroup,
  listMyGroups,
  getGroupById,
  leaveGroup,
} from "../controllers/groupController.js";

const router = express.Router();

router.post("/", createGroup);
router.get("/", listMyGroups);
router.get("/:id", getGroupById);
router.post("/:id/leave", leaveGroup);

export default router;
