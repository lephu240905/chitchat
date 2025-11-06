import Group from "../models/Group.js";
import User from "../models/User.js";

// POST /api/groups
export const createGroup = async (req, res) => {
  try {
    const { name, members } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ message: "Tên nhóm không được để trống" });
    }

    // ensure members is array of ids
    const memberIds = Array.isArray(members) ? members.slice() : [];

    // ensure current user is in members
    const userId = req.user && req.user._id;
    if (!userId) {
      return res.status(401).json({ message: "Người dùng chưa xác thực" });
    }

    if (!memberIds.find((id) => String(id) === String(userId))) {
      memberIds.push(userId);
    }

    // validate users exist (optional)
    const validUsers = await User.find({ _id: { $in: memberIds } }).select(
      "_id"
    );
    const validIds = validUsers.map((u) => String(u._id));

    const finalMembers = memberIds.filter((id) =>
      validIds.includes(String(id))
    );

    const group = new Group({
      name: name.trim(),
      members: finalMembers,
      admin: userId,
    });

    await group.save();

    // Emit socket event to all members to notify about new group
    try {
      const io = req.app && req.app.get("io");
      if (io) {
        finalMembers.forEach((memberId) => {
          try {
            io.to(String(memberId)).emit("groupCreated", group);
          } catch (e) {
            console.warn("Không thể emit socket tới", memberId, e);
          }
        });
      }
    } catch (e) {
      console.warn("Lỗi khi emit event groupCreated:", e);
    }

    return res.status(201).json(group);
  } catch (error) {
    console.error("Lỗi khi tạo nhóm:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// GET /api/groups (simple list of groups the user is member of)
export const listMyGroups = async (req, res) => {
  try {
    const userId = req.user && req.user._id;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    const groups = await Group.find({ members: userId }).populate(
      "members",
      "username displayName avatarUrl"
    );
    return res.json(groups);
  } catch (error) {
    console.error("Lỗi khi lấy nhóm:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getGroupById = async (req, res) => {
  try {
    const { id } = req.params;
    const group = await Group.findById(id).populate(
      "members",
      "username displayName avatarUrl"
    );
    if (!group) return res.status(404).json({ message: "Group không tồn tại" });
    return res.json(group);
  } catch (error) {
    console.error("Lỗi khi lấy nhóm theo id:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// Rời nhóm
export const leaveGroup = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    const group = await Group.findById(id);
    if (!group) {
      return res.status(404).json({ message: "Nhóm không tồn tại" });
    }

    // Kiểm tra user có phải thành viên không
    const isMember = group.members.some(
      (m) => String(m) === String(userId)
    );
    if (!isMember) {
      return res.status(403).json({ message: "Bạn không phải thành viên nhóm" });
    }

    // Không cho phép admin rời nhóm (hoặc có thể chuyển admin trước)
    if (String(group.admin) === String(userId)) {
      return res.status(400).json({ 
        message: "Admin không thể rời nhóm. Vui lòng chuyển quyền admin trước." 
      });
    }

    // Xóa user khỏi members
    group.members = group.members.filter(
      (m) => String(m) !== String(userId)
    );
    await group.save();

    // Emit event để các thành viên khác biết
    const io = req.app && req.app.get("io");
    if (io) {
      group.members.forEach((memberId) => {
        io.to(String(memberId)).emit("groupUpdated", group);
        io.to(String(memberId)).emit("memberLeft", {
          groupId: id,
          userId: userId.toString(),
        });
      });
      // Emit cho user vừa rời
      io.to(String(userId)).emit("leftGroup", { groupId: id });
    }

    res.status(200).json({ message: "Đã rời nhóm thành công", group });
  } catch (error) {
    console.error("Lỗi khi rời nhóm:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};