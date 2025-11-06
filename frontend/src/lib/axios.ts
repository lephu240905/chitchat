import { useAuthStore } from "@/stores/useAuthStore";
import axios from "axios";

// ✅ Tự động chọn baseURL tùy môi trường
const api = axios.create({
  baseURL:
    import.meta.env.MODE === "development"
      ? "http://localhost:5001/api" // khi chạy dev local
      : "https://chitchat-txdo.onrender.com/api", // khi deploy trên Render
  withCredentials: true, // cần thiết nếu backend dùng cookie (refresh token)
});

// ✅ Gắn access token vào header mỗi request
api.interceptors.request.use((config) => {
  const { accessToken } = useAuthStore.getState();
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// ✅ Tự động refresh token nếu access token hết hạn
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

    // Không retry cho các route auth
    if (
      originalRequest.url.includes("/auth/signin") ||
      originalRequest.url.includes("/auth/signup") ||
      originalRequest.url.includes("/auth/refresh")
    ) {
      return Promise.reject(error);
    }

    // Khi bị lỗi 403 (token hết hạn)
    if (error.response?.status === 403 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const res = await api.post("/auth/refresh");
        const newAccessToken = res.data.accessToken;
        useAuthStore.getState().setAccessToken(newAccessToken);

        // Gắn lại token mới vào header
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;

        // Gửi lại request gốc
        return api(originalRequest);
      } catch (err) {
        // Refresh thất bại → xóa token và logout
        useAuthStore.getState().clearState();
        return Promise.reject(err);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
