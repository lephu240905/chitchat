import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    // Optional groupId for group chats
    groupId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Group",
    },
    content: { type: String, trim: true, default: "" },
    imgUrl: { type: String, trim: true, default: "" },
    audioUrl: { type: String, trim: true, default: "" },
    gifUrl: { type: String, trim: true, default: "" },
    messageType: { 
      type: String, 
      enum: ["text", "image", "audio", "gif", "emoji"], 
      default: "text" 
    },
  },
  { timestamps: true }
);

messageSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: (_, ret) => {
    ret.id = ret._id;
    delete ret._id;
  },
});

export const Message = mongoose.model("Message", messageSchema);
export default Message;
