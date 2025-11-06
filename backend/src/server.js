import express from "express";
import dotenv from "dotenv";
import { connectDB } from "./libs/db.js";
import authRoute from "./routes/authRoute.js";
import userRoute from "./routes/userRoute.js";
import friendRoute from "./routes/friendRoute.js";
import messageRoute from "./routes/messageRoute.js";
import groupRoute from "./routes/groupRoute.js";
import uploadRoute from "./routes/uploadRoute.js";
import chatCustomizationRoute from "./routes/chatCustomizationRoute.js";
import { fileURLToPath } from "url";
import path from "path";
import cookieParser from "cookie-parser";
import { protectedRoute } from "./middlewares/authMiddleware.js";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";
import { chatSocket } from "./sockets/chatSocket.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:5173", "http://localhost:5174"],
    credentials: true,
  },
});

const PORT = process.env.PORT || 5001;

// Gắn io vào app để controller có thể truy cập
app.set("io", io);

// Lưu map userId ↔ socketId
const userSockets = new Map();

io.on("connection", (socket) => {
  const userId = socket.handshake.query.userId;
  if (userId) {
    userSockets.set(userId, socket.id);
    socket.join(userId); // để có thể io.to(userId).emit()
    
    // Emit user online status đến tất cả bạn bè
    io.emit("user_status_changed", {
      userId: userId.toString(),
      status: "online",
    });
  }

  socket.on("disconnect", () => {
    if (userId) {
      userSockets.delete(userId);
      // Emit user offline status đến tất cả bạn bè
      io.emit("user_status_changed", {
        userId: userId.toString(),
        status: "offline",
      });
    }
  });
});

// =======================
// 🧩 MIDDLEWARES
// =======================
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    credentials: true,
  })
);

// Serve static files from uploads directory
app.use("/uploads", express.static(path.join(__dirname, "../uploads")));
// Serve static files for avatars specifically
app.use("/uploads/avatars", express.static(path.join(__dirname, "../uploads/avatars")));

// =======================
// 🌐 ROUTES
// =======================
app.use("/api/auth", authRoute);
app.use(protectedRoute);
app.use("/api/users", userRoute);
app.use("/api/friends", friendRoute);
app.use("/api/messages", messageRoute);
app.use("/api/groups", groupRoute);
app.use("/api/upload", uploadRoute);
app.use("/api/chat-customizations", chatCustomizationRoute);

// =======================
// ⚙️ DATABASE & SERVER START
// =======================
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`✅ Server (Express + Socket.IO) đang chạy trên cổng ${PORT}`);
  });
});

// =======================
// 💬 SOCKET.IO CHAT SETUP
// =======================
chatSocket(io);
