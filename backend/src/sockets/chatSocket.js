import { Message } from "../models/Message.js";
import Friend from "../models/friendModel.js";

export const chatSocket = (io) => {
  io.on("connection", (socket) => {
    console.log("🟢 Client connected:", socket.id);

    // Khi user join phòng riêng của họ
    socket.on("join", (userId) => {
      if (!userId) return;
      socket.join(userId.toString());
      console.log(`✅ User ${userId} joined room ${userId}`);
    });

    // Khi gửi tin nhắn (hỗ trợ user -> user và group)
    socket.on(
      "sendMessage",
      async ({ senderId, receiverId, content, imgUrl, audioUrl, gifUrl, messageType, groupId }) => {
        try {
          // Kiểm tra có ít nhất một loại nội dung
          const hasContent = content || imgUrl || audioUrl || gifUrl;
          if (!senderId || !hasContent || (!receiverId && !groupId)) {
            socket.emit("errorMessage", "Thiếu dữ liệu tin nhắn!");
            return;
          }

          // Nếu là group message
          if (groupId) {
            // Lấy thành viên nhóm
            const group = await (await import("../models/Group.js")).default
              .findById(groupId)
              .select("members name");
            if (!group) {
              socket.emit("errorMessage", "Group không tồn tại");
              return;
            }

            const isMember = group.members.some(
              (m) => String(m) === String(senderId)
            );
            if (!isMember) {
              socket.emit("errorMessage", "Bạn không phải thành viên nhóm");
              return;
            }

            // Lưu tin nhắn
            const message = await Message.create({
              senderId,
              groupId,
              content: content || "",
              imgUrl: imgUrl || "",
              audioUrl: audioUrl || "",
              gifUrl: gifUrl || "",
              messageType: messageType || "text",
            });

            const populatedMsg = await message.populate([
              { path: "senderId", select: "username displayName" },
              { path: "groupId", select: "name" },
            ]);

            // Emit tới tất cả thành viên
            group.members.forEach((memberId) => {
              try {
                io.to(String(memberId)).emit("receiveMessage", populatedMsg);
              } catch (e) {
                console.warn("Không thể emit tới", memberId, e);
              }
            });

            console.log(
              `💬 Tin nhắn nhóm ${groupId} từ ${senderId}: ${content}`
            );
            return;
          }

          // Nếu là private message: giữ nguyên logic cũ
          if (!receiverId) {
            socket.emit("errorMessage", "Thiếu receiverId");
            return;
          }

          const isFriend = await Friend.findOne({
            $or: [
              { sender: senderId, receiver: receiverId, status: "accepted" },
              { sender: receiverId, receiver: senderId, status: "accepted" },
            ],
          });

          if (!isFriend) {
            socket.emit("errorMessage", "Hai người chưa phải bạn bè!");
            return;
          }

          const message = await Message.create({
            senderId,
            receiverId,
            content: content || "",
            imgUrl: imgUrl || "",
            audioUrl: audioUrl || "",
            gifUrl: gifUrl || "",
            messageType: messageType || "text",
          });

          const populatedMsg = await message.populate([
            { path: "senderId", select: "username displayName" },
            { path: "receiverId", select: "username displayName" },
          ]);

          io.to(senderId.toString()).emit("receiveMessage", populatedMsg);
          io.to(receiverId.toString()).emit("receiveMessage", populatedMsg);

          console.log(`💬 Tin nhắn từ ${senderId} → ${receiverId}: ${content}`);
        } catch (error) {
          console.error("❌ Lỗi gửi tin nhắn:", error);
          socket.emit("errorMessage", "Lỗi server khi gửi tin nhắn!");
        }
      }
    );

    // ===== WebRTC signaling handlers for call setup =====
    // forward the whole payload so fields like isVideo are preserved
    socket.on("callUser", (payload) => {
      try {
        const to = payload?.to;
        if (!to) return;
        io.to(String(to)).emit("incomingCall", payload);
      } catch (e) {
        console.error("Error forwarding callUser", e);
      }
    });

    socket.on("answerCall", ({ to, from, answer }) => {
      try {
        if (!to) return;
        io.to(String(to)).emit("callAnswered", { from, answer });
      } catch (e) {
        console.error("Error forwarding answerCall", e);
      }
    });

    socket.on("iceCandidate", ({ to, from, candidate }) => {
      try {
        if (!to) return;
        io.to(String(to)).emit("iceCandidate", { from, candidate });
      } catch (e) {
        console.error("Error forwarding iceCandidate", e);
      }
    });

    socket.on("endCall", ({ to, from }) => {
      try {
        if (!to) return;
        io.to(String(to)).emit("endCall", { from });
      } catch (e) {
        console.error("Error forwarding endCall", e);
      }
    });

    // Khi ngắt kết nối
    socket.on("disconnect", () => {
      console.log("🔴 Client disconnected:", socket.id);
    });
  });
};
