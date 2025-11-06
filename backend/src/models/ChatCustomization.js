import mongoose from "mongoose";

const chatCustomizationSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    chatId: {
      type: String,
      required: true, // ID của người bạn hoặc nhóm đang chat
    },
    isGroup: {
      type: Boolean,
      default: false,
    },
    nickname: {
      type: String,
      trim: true,
      default: null,
    },
    theme: {
      type: String,
      trim: true,
      default: null,
    },
    quickReaction: {
      type: String,
      default: "👍",
    },
  },
  {
    timestamps: true,
  }
);

// Index để tìm nhanh customization của user cho một chat cụ thể
chatCustomizationSchema.index({ userId: 1, chatId: 1 }, { unique: true });

const ChatCustomization = mongoose.model("ChatCustomization", chatCustomizationSchema);
export default ChatCustomization;

