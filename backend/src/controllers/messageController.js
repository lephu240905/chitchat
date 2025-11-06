import Message from "../models/Message.js";
import Group from "../models/Group.js";

// 📨 Gửi tin nhắn
export const sendMessage = async (req, res) => {
  try {
    const { receiverId, content, imgUrl, audioUrl, gifUrl, messageType, groupId } = req.body;
    const senderId = req.user._id;

    // If groupId provided, validate sender is member
    if (groupId) {
      const group = await Group.findById(groupId).select("members name");
      if (!group)
        return res.status(404).json({ message: "Group không tồn tại" });
      const isMember = group.members.some(
        (m) => String(m) === String(senderId)
      );
      if (!isMember)
        return res
          .status(403)
          .json({ message: "Bạn không phải thành viên nhóm" });
    }

    const message = await Message.create({
      senderId,
      receiverId: receiverId || null,
      groupId: groupId || null,
      content: content || "",
      imgUrl: imgUrl || "",
      audioUrl: audioUrl || "",
      gifUrl: gifUrl || "",
      messageType: messageType || "text",
    });

    const populatePaths = [
      { path: "senderId", select: "username displayName" },
    ];
    if (groupId) populatePaths.push({ path: "groupId", select: "name" });
    else
      populatePaths.push({
        path: "receiverId",
        select: "username displayName",
      });

    const populatedMsg = await message.populate(populatePaths);

    return res.status(201).json(populatedMsg);
  } catch (error) {
    console.error("❌ Lỗi gửi tin nhắn:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// 📜 Lấy lịch sử chat giữa 2 user
export const getMessages = async (req, res) => {
  try {
    // ✅ Đúng tên param trong route
    const { receiverId } = req.params;
    const currentUserId = req.user._id;

    // 🔍 Lấy tin nhắn giữa 2 người (dù ai gửi)
    const messages = await Message.find({
      $or: [
        { senderId: currentUserId, receiverId },
        { senderId: receiverId, receiverId: currentUserId },
      ],
    })
      .populate("senderId", "username displayName")
      .populate("receiverId", "username displayName")
      .sort({ createdAt: 1 });

    return res.status(200).json(messages);
  } catch (error) {
    console.error("❌ Lỗi lấy tin nhắn:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// Lấy tin nhắn của 1 nhóm
export const getGroupMessages = async (req, res) => {
  try {
    const { groupId } = req.params;
    const currentUserId = req.user._id;

    const group = await Group.findById(groupId).select("members");
    if (!group) return res.status(404).json({ message: "Group không tồn tại" });

    const isMember = group.members.some(
      (m) => String(m) === String(currentUserId)
    );
    if (!isMember)
      return res
        .status(403)
        .json({ message: "Bạn không phải thành viên nhóm" });

    const messages = await Message.find({ groupId })
      .populate("senderId", "username displayName")
      .populate("groupId", "name")
      .sort({ createdAt: 1 });

    return res.status(200).json(messages);
  } catch (error) {
    console.error("❌ Lỗi lấy tin nhắn nhóm:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
