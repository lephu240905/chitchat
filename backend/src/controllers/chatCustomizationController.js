import ChatCustomization from "../models/ChatCustomization.js";

// Lấy hoặc tạo customization cho một chat
export const getOrCreateCustomization = async (req, res) => {
  try {
    const userId = req.user._id;
    const { chatId } = req.params;

    if (!chatId) {
      return res.status(400).json({ message: "Thiếu chatId" });
    }

    let customization = await ChatCustomization.findOne({
      userId,
      chatId,
    });

    if (!customization) {
      // Tạo mới nếu chưa có
      customization = await ChatCustomization.create({
        userId,
        chatId,
        quickReaction: "👍", // Mặc định
      });
    }

    res.status(200).json(customization);
  } catch (error) {
    console.error("❌ Lỗi lấy customization:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// Cập nhật customization
export const updateCustomization = async (req, res) => {
  try {
    const userId = req.user._id;
    const { chatId } = req.params;
    const { nickname, theme, quickReaction, isGroup } = req.body;

    if (!chatId) {
      return res.status(400).json({ message: "Thiếu chatId" });
    }

    // Nếu là nhóm, cần xử lý khác
    if (isGroup) {
      // Với nhóm, theme được áp dụng cho tất cả thành viên
      if (theme !== undefined) {
        const Group = (await import("../models/Group.js")).default;
        const group = await Group.findById(chatId).select("members");
        
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

        // Cập nhật theme cho tất cả thành viên
        const io = req.app && req.app.get("io");
        for (const memberId of group.members) {
          let memberCustomization = await ChatCustomization.findOne({
            userId: memberId,
            chatId: chatId,
            isGroup: true,
          });

          if (!memberCustomization) {
            memberCustomization = await ChatCustomization.create({
              userId: memberId,
              chatId: chatId,
              isGroup: true,
              theme: theme || null,
              quickReaction: "👍",
            });
          } else {
            memberCustomization.theme = theme || null;
            memberCustomization.isGroup = true;
            await memberCustomization.save();
          }

          // Emit socket event đến từng thành viên
          if (io) {
            io.to(String(memberId)).emit("chatThemeChanged", {
              chatId: chatId,
              theme: theme || null,
            });
          }
        }

        return res.status(200).json({
          message: "Cập nhật theme nhóm thành công",
          customization: await ChatCustomization.findOne({
            userId,
            chatId,
            isGroup: true,
          }),
        });
      }

      // Nếu là đổi tên nhóm (nickname trong context nhóm)
      if (nickname !== undefined) {
        const Group = (await import("../models/Group.js")).default;
        const group = await Group.findById(chatId);
        
        if (!group) {
          return res.status(404).json({ message: "Nhóm không tồn tại" });
        }

        // Chỉ admin mới đổi được tên nhóm
        if (String(group.admin) !== String(userId)) {
          return res.status(403).json({ message: "Chỉ admin mới đổi được tên nhóm" });
        }

        group.name = nickname.trim();
        await group.save();

        // Emit event để refresh
        const io = req.app && req.app.get("io");
        if (io) {
          group.members.forEach((memberId) => {
            io.to(String(memberId)).emit("groupUpdated", group);
          });
        }

        return res.status(200).json({
          message: "Đổi tên nhóm thành công",
          group,
        });
      }
    }

    // Logic cho chat cá nhân (giữ nguyên)
    let customization = await ChatCustomization.findOne({
      userId,
      chatId,
      isGroup: false,
    });

    if (!customization) {
      customization = await ChatCustomization.create({
        userId,
        chatId,
        isGroup: false,
        nickname: nickname || null,
        theme: theme || null,
        quickReaction: quickReaction || "👍",
      });
    } else {
      // Cập nhật các trường được gửi lên
      if (nickname !== undefined) {
        customization.nickname = nickname || null;
      }
      if (theme !== undefined) {
        customization.theme = theme || null;
      }
      if (quickReaction !== undefined) {
        customization.quickReaction = quickReaction || "👍";
      }
      await customization.save();
    }

    // Nếu thay đổi theme, cũng cập nhật theme cho người bạn đang chat
    if (theme !== undefined && !isGroup) {
      try {
        // Tìm customization của người bạn (chatId là userId của bạn, userId là chatId)
        let friendCustomization = await ChatCustomization.findOne({
          userId: chatId,
          chatId: userId.toString(),
          isGroup: false,
        });

        if (!friendCustomization) {
          friendCustomization = await ChatCustomization.create({
            userId: chatId,
            chatId: userId.toString(),
            isGroup: false,
            theme: theme || null,
            quickReaction: "👍", // Mặc định
          });
        } else {
          friendCustomization.theme = theme || null;
          await friendCustomization.save();
        }

        // Emit socket event để cả hai bên cùng cập nhật
        const io = req.app && req.app.get("io");
        if (io) {
          // Emit đến user hiện tại
          io.to(userId.toString()).emit("chatThemeChanged", {
            chatId: chatId,
            theme: theme || null,
          });
          // Emit đến người bạn
          io.to(chatId.toString()).emit("chatThemeChanged", {
            chatId: userId.toString(),
            theme: theme || null,
          });
        }
      } catch (e) {
        console.warn("⚠️ Không thể đồng bộ theme với bạn:", e);
        // Vẫn tiếp tục, không fail toàn bộ request
      }
    }

    res.status(200).json({
      message: "Cập nhật customization thành công",
      customization,
    });
  } catch (error) {
    console.error("❌ Lỗi cập nhật customization:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// Xóa customization (để reset về mặc định)
export const deleteCustomization = async (req, res) => {
  try {
    const userId = req.user._id;
    const { chatId } = req.params;

    if (!chatId) {
      return res.status(400).json({ message: "Thiếu chatId" });
    }

    await ChatCustomization.findOneAndDelete({
      userId,
      chatId,
    });

    res.status(200).json({ message: "Đã xóa customization" });
  } catch (error) {
    console.error("❌ Lỗi xóa customization:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// Lấy tất cả customizations của user
export const getAllCustomizations = async (req, res) => {
  try {
    const userId = req.user._id;

    const customizations = await ChatCustomization.find({
      userId,
    });

    res.status(200).json(customizations);
  } catch (error) {
    console.error("❌ Lỗi lấy customizations:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

