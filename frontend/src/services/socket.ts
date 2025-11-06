// src/services/socket.ts
import { io } from "socket.io-client";

// ✅ Dùng domain backend Render khi ở môi trường production
export const socket = io(
  import.meta.env.MODE === "development"
    ? "http://localhost:5001"
    : "https://chitchat-txdo.onrender.com", // 🔥 backend Render
  {
    withCredentials: true,
    transports: ["websocket", "polling"],
  }
);
