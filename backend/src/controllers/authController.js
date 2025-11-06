// @ts-nocheck
import bcrypt from "bcrypt";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import Session from "../models/Session.js";

const ACCESS_TOKEN_TTL = "30m"; // Access token hết hạn sau 30 phút
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 ngày

// ========================
// 🧩 ĐĂNG KÝ (SIGN UP)
// ========================
export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body;

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({
        message:
          "Thiếu thông tin: username, password, email, firstName hoặc lastName",
      });
    }

    // Kiểm tra trùng username / email
    const duplicateUsername = await User.findOne({ username });
    if (duplicateUsername) {
      return res.status(409).json({ message: "Tên đăng nhập đã tồn tại" });
    }

    const duplicateEmail = await User.findOne({ email });
    if (duplicateEmail) {
      return res.status(409).json({ message: "Email đã được sử dụng" });
    }

    // Mã hoá mật khẩu
    const hashedPassword = await bcrypt.hash(password, 10);

    // Tạo user mới
    const newUser = await User.create({
      username,
      hashedPassword,
      email,
      displayName: `${firstName} ${lastName}`,
    });

    // Tạo access token và refresh token
    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );

    const refreshToken = crypto.randomBytes(64).toString("hex");

    // Lưu refresh token vào database
    await Session.create({
      userId: newUser._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });

    // Gửi refresh token cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true, // 🔒 cần cho HTTPS trên Render
      sameSite: "none", // 🔄 cho phép frontend + backend khác domain
      path: "/",
      maxAge: REFRESH_TOKEN_TTL,
    });

    // Trả access token để frontend tự lưu
    return res.status(201).json({
      message: `Đăng ký thành công!`,
      accessToken,
    });
  } catch (error) {
    console.error("Lỗi khi gọi signUp:", error);

    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({
        message: `${
          field === "email" ? "Email" : "Tên đăng nhập"
        } đã được sử dụng`,
      });
    }

    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// ========================
// 🧩 ĐĂNG NHẬP (SIGN IN)
// ========================
export const signIn = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Thiếu username hoặc password" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res
        .status(401)
        .json({ message: "Tên đăng nhập hoặc mật khẩu không đúng" });
    }

    const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);
    if (!passwordCorrect) {
      return res
        .status(401)
        .json({ message: "Tên đăng nhập hoặc mật khẩu không đúng" });
    }

    // Tạo access token và refresh token
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );

    const refreshToken = crypto.randomBytes(64).toString("hex");

    await Session.create({
      userId: user._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });

    // Gửi cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: REFRESH_TOKEN_TTL,
    });

    return res
      .status(200)
      .json({ message: "Đăng nhập thành công!", accessToken });
  } catch (error) {
    console.error("Lỗi khi gọi signIn:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// ========================
// 🧩 ĐĂNG XUẤT (SIGN OUT)
// ========================
export const signOut = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (token) {
      await Session.deleteOne({ refreshToken: token });

      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/",
      });
    }

    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi khi gọi signOut:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

// ========================
// ♻️ REFRESH TOKEN
// ========================
export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (!token) {
      return res.status(401).json({ message: "Token không tồn tại" });
    }

    const session = await Session.findOne({ refreshToken: token });
    if (!session) {
      return res
        .status(403)
        .json({ message: "Token không hợp lệ hoặc đã hết hạn" });
    }

    if (session.expiresAt < new Date()) {
      await Session.deleteOne({ refreshToken: token });
      return res.status(403).json({ message: "Token đã hết hạn" });
    }

    const accessToken = jwt.sign(
      { userId: session.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error("Lỗi khi gọi refreshToken:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
