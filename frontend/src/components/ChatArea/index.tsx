"use client";

import { useState, useEffect, useRef } from "react";
import { socket } from "@/services/socket";
import api from "@/lib/axios";
import {
  MessageCircle,
  Send,
  Phone,
  Video,
  MoreHorizontal,
  Image,
  ThumbsUp,
} from "lucide-react";
import CreateGroupModal from "./CreateGroupModal";
import CallModal from "./CallModal";
import ChatCustomizeModal from "./ChatCustomizeModal";

// Helper function để build avatar URL
const getAvatarUrl = (avatarUrl: string | undefined) => {
  if (!avatarUrl) return null;
  if (avatarUrl.startsWith("http")) return avatarUrl;
  const baseURL = import.meta.env.MODE === "development" 
    ? "http://localhost:5001" 
    : "";
  return `${baseURL}${avatarUrl}`;
};

interface ChatAreaProps {
  selectedChat: string | null;
  isDark: boolean;
  user: any;
  onSelectChat?: (chatId: string) => void;
}

export default function ChatArea({
  selectedChat,
  isDark,
  user,
  onSelectChat,
}: ChatAreaProps) {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<any[]>([]);
  const [friendInfo, setFriendInfo] = useState<any>(null);
  const [groupInfo, setGroupInfo] = useState<any>(null);
  const [isGroup, setIsGroup] = useState(false);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isCustomizeOpen, setIsCustomizeOpen] = useState(false);
  const [inCall, setInCall] = useState(false);
  const [chatNickname, setChatNickname] = useState<string | null>(null);
  const [chatTheme, setChatTheme] = useState<string | null>(null);
  const [chatQuickReaction, setChatQuickReaction] = useState<string>("👍"); // Emoji mặc định là 👍
  // const [incomingCall, setIncomingCall] = useState<any | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null);
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteVideoRef = useRef<HTMLVideoElement | null>(null);
  const [incomingPayload, setIncomingPayload] = useState<any | null>(null);
  const [outgoing, setOutgoing] = useState(false);
  const [currentCallIsVideo, setCurrentCallIsVideo] = useState(false);
  const imageInputRef = useRef<HTMLInputElement | null>(null);

  // 📨 Lấy tin nhắn cũ + thông tin người bạn đang chat
  useEffect(() => {
    setIsGroup(false);
    setGroupInfo(null);
    if (!selectedChat || !user) return;

    const fetchData = async () => {
             // Load customizations từ database
             try {
               if (selectedChat && user?._id) {
                 const customizationRes = await api.get(`/chat-customizations/${selectedChat}`);
                 const customization = customizationRes.data;
                 
                 // Cập nhật state từ database
                 setChatNickname(customization.nickname || null);
                 setChatTheme(customization.theme || null);
                 setChatQuickReaction(customization.quickReaction || "👍");

          // Đồng bộ với localStorage như cache
          const nicknameKey = `chat_nickname_${selectedChat}`;
          const themeKey = `chat_theme_${selectedChat}`;
          const quickReactionKey = `chat_quick_reaction_${selectedChat}`;
          
          if (customization.nickname) {
            localStorage.setItem(nicknameKey, customization.nickname);
          } else {
            localStorage.removeItem(nicknameKey);
          }
          
          if (customization.theme) {
            localStorage.setItem(themeKey, customization.theme);
          } else {
            localStorage.removeItem(themeKey);
          }
          
          if (customization.quickReaction) {
            localStorage.setItem(quickReactionKey, customization.quickReaction);
          } else {
            localStorage.setItem(quickReactionKey, "👍");
          }
        }
      } catch (error) {
        console.error("Lỗi load customization:", error);
        // Fallback về localStorage nếu API lỗi
        const nicknameKey = `chat_nickname_${selectedChat}`;
        const themeKey = `chat_theme_${selectedChat}`;
        const quickReactionKey = `chat_quick_reaction_${selectedChat}`;
        setChatNickname(localStorage.getItem(nicknameKey));
        setChatTheme(localStorage.getItem(themeKey));
        setChatQuickReaction(localStorage.getItem(quickReactionKey) || "👍");
      }

      // Fetch messages and user/group info
      try {
        // First try to fetch as a user chat
        try {
          const [msgRes, userRes] = await Promise.all([
            api.get(`/messages/${selectedChat}`),
            api.get(`/users/${selectedChat}`),
          ]);
          setMessages(msgRes.data || []);
          setFriendInfo(userRes.data || null);
          setIsGroup(false);
          setGroupInfo(null);
          return;
        } catch {
          // if fetching user failed, try as group
        }

        // Try group
        const [groupRes, groupMsgRes] = await Promise.all([
          api.get(`/groups/${selectedChat}`),
          api.get(`/messages/group/${selectedChat}`),
        ]);
        setGroupInfo(groupRes.data || null);
        setMessages(groupMsgRes.data || []);
        setFriendInfo(null);
        setIsGroup(true);
      } catch (err) {
        console.error("Lỗi tải tin nhắn:", err);
      }
    };

    fetchData();
  }, [selectedChat, user]);

  // 🔌 Socket realtime — join room + nhận tin nhắn
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!user?._id) return;

    socket.emit("join", user._id);

    const handleReceiveMessage = (msg: any) => {
      try {
        // group message
        const gId = msg.groupId?._id || msg.groupId;
        if (gId && gId === selectedChat) {
          setMessages((prev) => {
            if (msg._id && prev.some((m) => m._id === msg._id)) return prev;
            return [...prev, msg];
          });
          return;
        }

        // private message
        const sender = msg.senderId?._id || msg.senderId;
        const receiver = msg.receiverId?._id || msg.receiverId;

        if (sender === selectedChat || receiver === selectedChat) {
          setMessages((prev) => {
            if (msg._id && prev.some((m) => m._id === msg._id)) return prev;
            return [...prev, msg];
          });
        }
      } catch (e) {
        console.error("Lỗi xử lý receiveMessage:", e);
      }
    };

    socket.off("receiveMessage");
    socket.on("receiveMessage", handleReceiveMessage);

    // Listen for avatar updates từ bạn bè
    socket.on("user_avatar_updated", (data: { userId: string; avatarUrl: string }) => {
      // Cập nhật avatar trong header nếu đang chat với người đó
      if (selectedChat === data.userId && friendInfo) {
        setFriendInfo({ ...friendInfo, avatarUrl: data.avatarUrl });
      }
    });

    // Listen for status changes từ bạn bè
    socket.on("user_status_changed", (data: { userId: string; status: "online" | "offline" }) => {
      // Cập nhật status trong header nếu đang chat với người đó
      if (selectedChat === data.userId && friendInfo) {
        setFriendInfo({ ...friendInfo, status: data.status });
      }
    });

    const handleGroupCreated = (group: any) => {
      try {
        const memberIds = (group.members || []).map((m: any) =>
          m._id ? m._id : m
        );
        if (memberIds.includes(user._id)) {
          alert(`Bạn được thêm vào nhóm: ${group.name}`);
          // optionally refresh messages if currently viewing group
          if (selectedChat === group._id) {
            // refetch messages for the group
            api
              .get(`/messages/group/${group._id}`)
              .then((r) => setMessages(r.data || []));
            setGroupInfo(group);
            setIsGroup(true);
          }
        }
      } catch (err) {
        console.error("Lỗi xử lý groupCreated:", err);
      }
    };

    socket.off("groupCreated");
    socket.on("groupCreated", handleGroupCreated);

    // Listen for group updates (socket event)
    const handleSocketGroupUpdated = (group: any) => {
      const groupId = group._id || group.id;
      if (selectedChat === groupId) {
        // Cập nhật groupInfo ngay lập tức
        setGroupInfo(group);
        // Emit window event để các component khác cũng cập nhật
        window.dispatchEvent(new CustomEvent('groupUpdated', { detail: group }));
      }
      // Refresh groups list trong sidebar
      window.dispatchEvent(new CustomEvent('refreshGroups'));
    };

    socket.off("groupUpdated");
    socket.on("groupUpdated", handleSocketGroupUpdated);

    // Signaling: incoming call / answer / ice / end
    const handleIncomingCall = async (data: any) => {
      // data: { from, offer, isVideo }
      console.log("Incoming call", data);
      try {
        // try to resolve caller name
        const res = await api.get(`/users/${data.from}`);
        const callerName = res?.data?.username || undefined;
        setIncomingPayload({ ...data, callerName });
      } catch (err) {
        // fallback to raw payload
        setIncomingPayload(data);
      }
    };

    const handleCallAnswered = async (data: any) => {
      try {
        if (peerRef.current && data.answer) {
          await peerRef.current.setRemoteDescription(data.answer);
          // call is established
          setInCall(true);
          setOutgoing(false);
        }
      } catch (e) {
        console.error("Error handling callAnswered", e);
      }
    };

    const handleIce = async (data: any) => {
      try {
        if (peerRef.current && data.candidate) {
          await peerRef.current.addIceCandidate(
            new RTCIceCandidate(data.candidate)
          );
        }
      } catch (e) {
        console.error("Error adding remote ICE", e);
      }
    };

    const handleEndCall = (data: any) => {
      console.log("Call ended by remote", data);
      cleanupCall();
    };

    socket.off("incomingCall");
    socket.on("incomingCall", handleIncomingCall);

    socket.on("callAnswered", handleCallAnswered);
    socket.on("iceCandidate", handleIce);
    socket.on("endCall", handleEndCall);

    return () => {
      socket.off("receiveMessage", handleReceiveMessage);
      socket.off("groupCreated");
      socket.off("incomingCall");
      socket.off("callAnswered");
      socket.off("iceCandidate");
      socket.off("endCall");
    };
  }, [selectedChat, user?._id /* answerCall */]);

  // cleanup helper
  const cleanupCall = () => {
    try {
      if (peerRef.current) {
        peerRef.current.onicecandidate = null;
        peerRef.current.ontrack = null;
        peerRef.current.close();
        peerRef.current = null;
      }
      if (localStreamRef.current) {
        localStreamRef.current.getTracks().forEach((t) => t.stop());
        localStreamRef.current = null;
      }
      if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = null;
      }
    } catch (e) {
      console.warn("Error during cleanupCall", e);
    }
    setInCall(false);
    // cleared incoming call state (if any)
  };

  const startCall = async (isVideo: boolean) => {
    if (!selectedChat || !user) return;
    try {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
      });
      peerRef.current = pc;
      setOutgoing(true);
      setCurrentCallIsVideo(isVideo);

      const localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: !!isVideo,
      });
      localStreamRef.current = localStream;
      localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));

      pc.ontrack = (e) => {
        // attach both audio and video streams
        if (remoteAudioRef.current)
          remoteAudioRef.current.srcObject = e.streams[0];
        if (remoteVideoRef.current)
          remoteVideoRef.current.srcObject = e.streams[0];
      };

      pc.onicecandidate = (e) => {
        if (e.candidate) {
          socket.emit("iceCandidate", {
            to: selectedChat,
            from: user._id,
            candidate: e.candidate,
          });
        }
      };
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      socket.emit("callUser", {
        to: selectedChat,
        from: user._id,
        offer,
        isVideo,
      });
      // outgoing modal shown; wait for answer to set inCall
    } catch (e) {
      console.error("Lỗi khi bắt đầu gọi:", e);
      cleanupCall();
    }
  };

  const answerCall = async (from: string, offer: any, isVideo = false) => {
    try {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
      });
      peerRef.current = pc;
      setCurrentCallIsVideo(isVideo);

      const localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: !!isVideo,
      });
      localStreamRef.current = localStream;
      localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));

      pc.ontrack = (e) => {
        if (remoteAudioRef.current)
          remoteAudioRef.current.srcObject = e.streams[0];
        if (remoteVideoRef.current)
          remoteVideoRef.current.srcObject = e.streams[0];
      };

      pc.onicecandidate = (e) => {
        if (e.candidate) {
          socket.emit("iceCandidate", {
            to: from,
            from: user._id,
            candidate: e.candidate,
          });
        }
      };

      await pc.setRemoteDescription(offer);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      socket.emit("answerCall", { to: from, from: user._id, answer });
      setInCall(true);
    } catch (e) {
      console.error("Lỗi trả lời cuộc gọi:", e);
      cleanupCall();
    }
  };

  const endCall = () => {
    try {
      if (peerRef.current) {
        // inform remote
        socket.emit("endCall", { to: selectedChat, from: user._id });
      }
    } catch (e) {
      console.warn("Error sending endCall", e);
    }
    cleanupCall();
    setOutgoing(false);
    setIncomingPayload(null);
  };

  // ✅ Cuộn xuống cuối khi có tin nhắn mới
  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Debug: Log khi selectedChat thay đổi
  useEffect(() => {
    if (selectedChat) {
      console.log("✅ ChatArea rendered with selectedChat:", selectedChat);
      console.log("✅ isCustomizeOpen state:", isCustomizeOpen);
    }
  }, [selectedChat, isCustomizeOpen]);

  // Listen for theme changes (từ window event và socket)
  useEffect(() => {
    if (!user?._id) return;

    // Listen window event (local changes)
    const handleThemeChange = (e: CustomEvent) => {
      if (e.detail.chatId === selectedChat) {
        setChatTheme(e.detail.theme);
        console.log("Theme changed (local):", e.detail.theme);
      }
    };
    
    // Listen socket event (remote changes từ bạn bè)
    const handleSocketThemeChange = (data: { chatId: string; theme: string | null }) => {
      // data.chatId là userId của người gửi, selectedChat là userId của người đang chat
      // Nếu đang chat với người gửi event, thì cập nhật theme
      if (data.chatId === selectedChat) {
        setChatTheme(data.theme);
        // Cũng cập nhật localStorage
        const themeKey = `chat_theme_${selectedChat}`;
        if (data.theme) {
          localStorage.setItem(themeKey, data.theme);
        } else {
          localStorage.removeItem(themeKey);
        }
        console.log("Theme changed (socket):", data.theme);
      }
    };

    window.addEventListener('chatThemeChanged', handleThemeChange as EventListener);
    socket.on("chatThemeChanged", handleSocketThemeChange);

           return () => {
             window.removeEventListener('chatThemeChanged', handleThemeChange as EventListener);
             socket.off("chatThemeChanged", handleSocketThemeChange);
             socket.off("groupUpdated");
             socket.off("leftGroup");
           };
         }, [selectedChat, user?._id]);

  // Listen for group updates (window event)
  useEffect(() => {
    const handleGroupUpdated = async (e: Event) => {
      const customEvent = e as CustomEvent;
      if (!selectedChat || !isGroup) return;
      
      const updatedGroup = customEvent.detail;
      if (updatedGroup && (updatedGroup._id === selectedChat || updatedGroup.id === selectedChat)) {
        // Cập nhật groupInfo từ event hoặc fetch lại
        if (updatedGroup.name) {
          setGroupInfo(updatedGroup);
        } else {
          // Fetch lại từ API nếu không có đầy đủ thông tin
          try {
            const res = await api.get(`/groups/${selectedChat}`);
            setGroupInfo(res.data);
          } catch (err) {
            console.error("Lỗi fetch group info:", err);
          }
        }
      }
    };

    window.addEventListener('groupUpdated', handleGroupUpdated);
    return () => {
      window.removeEventListener('groupUpdated', handleGroupUpdated);
    };
  }, [selectedChat, isGroup]);

  // Listen for customization changes (when nickname/theme/quickReaction is saved)
  useEffect(() => {
    const handleCustomizationChange = (e: CustomEvent) => {
      if (!selectedChat || e.detail.chatId !== selectedChat) return;
      
      if (e.detail.type === 'nickname') {
        setChatNickname(e.detail.value);
        console.log("Nickname updated:", e.detail.value);
      }
      if (e.detail.type === 'theme') {
        setChatTheme(e.detail.value);
        console.log("Theme updated:", e.detail.value);
      }
      if (e.detail.type === 'quickReaction') {
        setChatQuickReaction(e.detail.value || "👍");
        console.log("Quick reaction updated:", e.detail.value);
      }
    };
    
    window.addEventListener('chatCustomizationChanged', handleCustomizationChange as EventListener);
    return () => {
      window.removeEventListener('chatCustomizationChanged', handleCustomizationChange as EventListener);
    };
  }, [selectedChat]);

  // 🚀 Gửi tin nhắn
  const handleSend = async (
    content?: string,
    messageType: "text" | "image" | "audio" | "gif" | "emoji" = "text",
    imgUrl?: string,
    audioUrl?: string,
    gifUrl?: string
  ) => {
    const messageContent = content || message;
    if ((!messageContent.trim() && !imgUrl && !audioUrl && !gifUrl) || !selectedChat || !user) return;

    try {
      const messageData: any = {
        senderId: user._id,
        content: messageContent,
        messageType,
        imgUrl: imgUrl || "",
        audioUrl: audioUrl || "",
        gifUrl: gifUrl || "",
      };

      if (isGroup) {
        messageData.groupId = selectedChat;
        socket.emit("sendMessage", messageData);
      } else {
        messageData.receiverId = selectedChat;
        socket.emit("sendMessage", messageData);
      }
      
      // Also save to database via API
      try {
        await api.post("/messages", messageData);
      } catch (apiErr) {
        console.error("Lỗi lưu message vào database:", apiErr);
      }

      setMessage("");
    } catch (err) {
      console.error("Lỗi gửi tin:", err);
    }
  };

  // open group creation modal
  const handleOpenCreate = () => {
    setIsCreateOpen(true);
  };

  // 📷 Xử lý upload ảnh
  const handleImageSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate image file
    if (!file.type.startsWith("image/")) {
      alert("Vui lòng chọn file ảnh");
      return;
    }

    const formData = new FormData();
    formData.append("image", file);

    try {
      const uploadRes = await api.post("/upload/image", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      
      // Use baseURL from axios config
      const baseURL = import.meta.env.MODE === "development" 
        ? "http://localhost:5001" 
        : "";
      const imgUrl = `${baseURL}${uploadRes.data.url}`;
      await handleSend(message, "image", imgUrl);
    } catch (err) {
      console.error("Lỗi upload ảnh:", err);
      alert("Lỗi khi upload ảnh");
    }

    // Reset input
    if (imageInputRef.current) {
      imageInputRef.current.value = "";
    }
  };

  // 👍 Gửi cảm xúc nhanh (quick reaction)
  const handleQuickReaction = () => {
    handleSend(chatQuickReaction, "emoji");
  };


  // Helper function to get theme colors as CSS values
  const getThemeColors = () => {
    if (!chatTheme) {
      return null;
    }
    
    // Map of color names to Tailwind color values
    const colorMap: { [key: string]: { light: string; lighter: string; dark: string; border: string } } = {
      blue: {
        light: "rgb(239, 246, 255)", // blue-50
        lighter: "rgb(219, 234, 254)", // blue-100
        dark: "rgb(30, 58, 138)", // blue-900
        border: "rgb(191, 219, 254)", // blue-200
      },
      purple: {
        light: "rgb(250, 245, 255)", // purple-50
        lighter: "rgb(243, 232, 255)", // purple-100
        dark: "rgb(88, 28, 135)", // purple-900
        border: "rgb(233, 213, 255)", // purple-200
      },
      pink: {
        light: "rgb(253, 244, 255)", // pink-50
        lighter: "rgb(250, 232, 255)", // pink-100
        dark: "rgb(131, 24, 67)", // pink-900
        border: "rgb(251, 207, 232)", // pink-200
      },
      green: {
        light: "rgb(240, 253, 244)", // green-50
        lighter: "rgb(220, 252, 231)", // green-100
        dark: "rgb(20, 83, 45)", // green-900
        border: "rgb(187, 247, 208)", // green-200
      },
      orange: {
        light: "rgb(255, 247, 237)", // orange-50
        lighter: "rgb(255, 237, 213)", // orange-100
        dark: "rgb(154, 52, 18)", // orange-900
        border: "rgb(254, 215, 170)", // orange-200
      },
    };

    const colorMatch = chatTheme.match(/from-(\w+)-500/);
    if (colorMatch) {
      const colorName = colorMatch[1];
      return colorMap[colorName] || null;
    }
    return null;
  };

  // Helper function to get background style for main area
  const getThemeBackgroundStyle = (): React.CSSProperties => {
    const colors = getThemeColors();
    if (!colors) {
      return {};
    }
    return {
      background: `linear-gradient(to bottom right, ${colors.light}, ${colors.lighter})`,
    };
  };

  // Helper function to convert rgb to rgba with opacity
  const rgbToRgba = (rgb: string, opacity: number): string => {
    const match = rgb.match(/\d+/g);
    if (match && match.length === 3) {
      return `rgba(${match[0]}, ${match[1]}, ${match[2]}, ${opacity})`;
    }
    return rgb;
  };

  // Helper function to get header/input background style
  const getThemeHeaderStyle = (): React.CSSProperties => {
    const colors = getThemeColors();
    if (!colors) {
      return {};
    }
    return {
      backgroundColor: isDark 
        ? rgbToRgba(colors.dark, 0.95) // 95% opacity
        : rgbToRgba(colors.light, 0.95), // 95% opacity
      borderColor: isDark 
        ? colors.dark 
        : colors.border,
    };
  };

  // 💤 Nếu chưa chọn chat
  if (!selectedChat) {
    return (
      <div
        className={`flex-1 flex items-center justify-center ${
          isDark ? "bg-gray-900" : "bg-gray-50"
        }`}
      >
        <div className="text-center">
          <MessageCircle
            className={`w-20 h-20 mx-auto mb-4 ${
              isDark ? "text-gray-700" : "text-gray-300"
            }`}
          />
          <h3
            className={`text-xl font-semibold mb-2 ${
              isDark ? "text-gray-300" : "text-gray-700"
            }`}
          >
            Chọn một cuộc trò chuyện
          </h3>
          <p className={`${isDark ? "text-gray-500" : "text-gray-400"}`}>
            Chọn bạn bè từ danh sách để bắt đầu nhắn tin
          </p>
        </div>
      </div>
    );
  }
  const themeColors = getThemeColors();
  const hasTheme = !!chatTheme && !!themeColors;

  return (
    <div
      className={`flex-1 flex flex-col ${
        hasTheme
          ? "text-gray-900"
          : isDark
          ? "bg-gray-900 text-white"
          : "bg-gray-50 text-gray-900"
      }`}
      style={hasTheme ? getThemeBackgroundStyle() : undefined}
    >
      {/* Header */}
      <div
        className={`p-4 border-b backdrop-blur-sm ${
          hasTheme
            ? ""
            : isDark
            ? "bg-gray-900/95 border-gray-800"
            : "bg-white/95 border-gray-200"
        }`}
        style={hasTheme ? getThemeHeaderStyle() : undefined}
      >
        <div className="flex items-center gap-3">
          <div className="relative">
            {isGroup ? (
              <div className="w-12 h-12 bg-gradient-to-br from-indigo-400 to-purple-400 rounded-full flex items-center justify-center text-white font-semibold">
                {groupInfo?.name?.[0]?.toUpperCase() || "?"}
              </div>
            ) : getAvatarUrl(friendInfo?.avatarUrl) ? (
              <img
                src={getAvatarUrl(friendInfo?.avatarUrl)!}
                alt="Avatar"
                className="w-12 h-12 rounded-full object-cover"
              />
            ) : (
              <div className="w-12 h-12 bg-gradient-to-br from-indigo-400 to-purple-400 rounded-full flex items-center justify-center text-white font-semibold">
                {((friendInfo?.displayName || friendInfo?.username)?.[0]
                )?.toUpperCase() || "?"}
              </div>
            )}
            {friendInfo?.status === "online" && !isGroup && (
              <span className="absolute bottom-0 right-0 w-3.5 h-3.5 bg-green-500 border-2 border-white rounded-full"></span>
            )}
          </div>
          <div>
            <h2 className="font-semibold flex items-center gap-2">
              {isGroup
                ? groupInfo?.name
                : chatNickname || friendInfo?.displayName || friendInfo?.username || "Đang tải..."}
            </h2>
            <p
              className={`text-xs ${
                isDark ? "text-gray-400" : "text-gray-500"
              }`}
            >
              {isGroup
                ? `Thành viên: ${groupInfo?.members?.length || 0}`
                : friendInfo?.status === "online"
                ? "Đang hoạt động"
                : "Không hoạt động"}
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            {isGroup ? (
              <>
                <button
                  onClick={() => (inCall ? endCall() : startCall(false))}
                  className={`p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 ${
                    inCall ? "bg-red-500 text-white" : ""
                  }`}
                >
                  <Phone className="w-4 h-4" />
                </button>
                <button
                  onClick={() => (inCall ? endCall() : startCall(true))}
                  className={`p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 ${
                    inCall ? "bg-red-500 text-white" : ""
                  }`}
                >
                  <Video className="w-4 h-4" />
                </button>
                <button
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log("🔵 More button clicked!", { 
                      selectedChat, 
                      isCustomizeOpen,
                      willSetTo: true 
                    });
                    setIsCustomizeOpen(true);
                    console.log("🔵 After setState, checking in next render...");
                  }}
                  className="p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"
                  title="Tùy chỉnh đoạn chat"
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                >
                  <MoreHorizontal className="w-5 h-5" style={{ minWidth: '20px', minHeight: '20px' }} />
                </button>
              </>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => (inCall ? endCall() : startCall(false))}
                  className={`p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 ${
                    inCall ? "bg-red-500 text-white" : ""
                  }`}
                >
                  <Phone className="w-4 h-4" />
                </button>
                <button
                  onClick={() => (inCall ? endCall() : startCall(true))}
                  className={`p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 ${
                    inCall ? "bg-red-500 text-white" : ""
                  }`}
                >
                  <Video className="w-4 h-4" />
                </button>
                <button
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log("🔵 More button clicked!", { 
                      selectedChat, 
                      isCustomizeOpen,
                      willSetTo: true 
                    });
                    setIsCustomizeOpen(true);
                    console.log("🔵 After setState, checking in next render...");
                  }}
                  className="p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"
                  title="Tùy chỉnh đoạn chat"
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                >
                  <MoreHorizontal className="w-5 h-5" style={{ minWidth: '20px', minHeight: '20px' }} />
                </button>
                <button
                  onClick={handleOpenCreate}
                  className="text-sm px-3 py-1 rounded-md bg-green-500 text-white hover:bg-green-600"
                >
                  Tạo nhóm
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {!isGroup && (
        <CreateGroupModal
          isOpen={isCreateOpen}
          onClose={() => setIsCreateOpen(false)}
          preselect={selectedChat}
          onGroupCreated={(groupId?: string) => {
            // Refresh groups if needed
            window.dispatchEvent(new CustomEvent('refreshGroups'));
            // Tự động chọn nhóm vừa tạo
            if (groupId && onSelectChat) {
              onSelectChat(groupId);
            }
          }}
        />
      )}

      <ChatCustomizeModal
        isOpen={isCustomizeOpen}
        onClose={() => setIsCustomizeOpen(false)}
        isDark={isDark}
        selectedChat={selectedChat}
        userId={user?._id || null}
        isGroup={isGroup}
        groupInfo={groupInfo}
        onSelectChat={onSelectChat}
      />

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.map((msg, idx) => {
          const isOwn = (msg.senderId._id || msg.senderId) === user._id;
          const showAvatar =
            idx === 0 ||
            (messages[idx - 1].senderId._id || messages[idx - 1].senderId) !==
              (msg.senderId._id || msg.senderId);

          return (
            <div
              key={msg._id || Math.random()}
              className={`flex ${isOwn ? "justify-end" : "justify-start"}`}
            >
              <div
                className={`flex gap-2 max-w-md ${
                  isOwn ? "flex-row-reverse" : "flex-row"
                }`}
              >
                {!isOwn && (
                  <div
                    className={`w-8 h-8 flex-shrink-0 ${
                      showAvatar ? "" : "invisible"
                    }`}
                  >
                    <div className="w-8 h-8 bg-gradient-to-br from-indigo-400 to-purple-400 rounded-full flex items-center justify-center text-white text-xs font-semibold">
                      {friendInfo?.username?.[0]?.toUpperCase() || "?"}
                    </div>
                  </div>
                )}
                <div
                  className={`flex flex-col ${
                    isOwn ? "items-end" : "items-start"
                  }`}
                >
                  <div
                    className={`px-4 py-2.5 rounded-2xl shadow-sm ${
                      isOwn
                        ? chatTheme
                          ? `bg-gradient-to-r ${chatTheme} text-white rounded-br-sm`
                          : "bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-br-sm"
                        : isDark
                        ? "bg-gray-800 text-gray-100 border border-gray-700 rounded-bl-sm"
                        : "bg-white text-gray-900 border border-gray-200 rounded-bl-sm"
                    }`}
                  >
                    {/* Hiển thị ảnh */}
                    {msg.imgUrl && (
                      <img
                        src={msg.imgUrl}
                        alt="Message image"
                        className="max-w-xs rounded-lg mb-2"
                        onError={(e) => {
                          (e.target as HTMLImageElement).src = "placeholder.png";
                        }}
                      />
                    )}
                    {/* Hiển thị GIF */}
                    {msg.gifUrl && (
                      <img
                        src={msg.gifUrl}
                        alt="GIF"
                        className="max-w-xs rounded-lg mb-2"
                      />
                    )}
                    {/* Hiển thị audio */}
                    {msg.audioUrl && (
                      <audio
                        controls
                        src={msg.audioUrl}
                        className="w-full mb-2"
                      >
                        Your browser does not support the audio element.
                      </audio>
                    )}
                    {/* Hiển thị text content hoặc emoji lớn */}
                    {msg.content && (
                      msg.messageType === "emoji" && msg.content.length <= 2 ? (
                        // Hiển thị emoji lớn nếu là quick reaction
                        <div className="text-4xl text-center py-2">
                          {msg.content}
                        </div>
                      ) : (
                        <p className="text-sm break-words">{msg.content}</p>
                      )
                    )}
                  </div>
                  {msg.createdAt && (
                    <span
                      className={`text-[10px] mt-1 ${
                        isDark ? "text-gray-500" : "text-gray-400"
                      }`}
                    >
                      {new Date(msg.createdAt).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
        <div ref={scrollRef} />
      </div>

      {/* Input */}
      <div
        className={`p-4 border-t backdrop-blur-sm ${
          hasTheme
            ? ""
            : isDark
            ? "bg-gray-900/95 border-gray-800"
            : "bg-white/95 border-gray-200"
        }`}
        style={hasTheme ? getThemeHeaderStyle() : undefined}
      >
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Aa"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            className={`flex-1 rounded-xl px-4 py-3 text-sm border transition-colors ${
              isDark
                ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-blue-500"
                : "bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:border-blue-500"
            } focus:outline-none focus:ring-2 focus:ring-blue-500/20`}
          />
          {/* Icons on the right side */}
          <div className="flex items-center gap-1 relative">
            {/* Hidden file input for images */}
            <input
              type="file"
              ref={imageInputRef}
              accept="image/*"
              onChange={handleImageSelect}
              className="hidden"
            />
            
            <button
              onClick={() => imageInputRef.current?.click()}
              className={`p-2.5 rounded-lg transition-colors ${
                isDark
                  ? "hover:bg-gray-700 text-gray-300 hover:text-white"
                  : "hover:bg-gray-100 text-gray-600 hover:text-gray-900"
              }`}
              title="Gửi ảnh"
            >
              <Image className="w-5 h-5" />
            </button>
            <button
              onClick={handleQuickReaction}
              className="p-2.5 rounded-lg transition-colors text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 dark:text-blue-400"
              title="Cảm xúc nhanh"
            >
              {chatQuickReaction ? (
                <span className="text-xl">{chatQuickReaction}</span>
              ) : (
                <ThumbsUp className="w-5 h-5" />
              )}
            </button>
            <button
              onClick={() => handleSend()}
              className="p-2.5 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg transition-all hover:scale-105 shadow-lg shadow-blue-500/30"
              title="Gửi"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
      {/* Call modal (incoming / outgoing) */}
      <CallModal
        open={!!incomingPayload || outgoing || inCall}
        outgoing={outgoing}
        inCall={inCall}
        callerName={
          incomingPayload?.callerName ||
          (outgoing
            ? isGroup
              ? groupInfo?.name
              : friendInfo?.username
            : undefined)
        }
        isVideo={incomingPayload?.isVideo || currentCallIsVideo}
        onAccept={() => {
          if (incomingPayload) {
            answerCall(
              incomingPayload.from,
              incomingPayload.offer,
              incomingPayload.isVideo
            );
            setIncomingPayload(null);
          }
        }}
        onReject={() => {
          if (inCall) {
            endCall();
          } else if (incomingPayload) {
            socket.emit("endCall", {
              to: incomingPayload.from,
              from: user._id,
            });
            setIncomingPayload(null);
          }
        }}
        onCancel={() => {
          // cancel outgoing call
          socket.emit("endCall", { to: selectedChat, from: user._id });
          setOutgoing(false);
          cleanupCall();
        }}
      />

      {/* local/remote video and audio elements */}
      <video
        ref={localVideoRef}
        autoPlay
        muted
        className={
          currentCallIsVideo && inCall ? "w-40 h-28 hidden md:block" : "hidden"
        }
      />
      <video
        ref={remoteVideoRef}
        autoPlay
        className={
          currentCallIsVideo && inCall ? "w-40 h-28 hidden md:block" : "hidden"
        }
      />
      {/* remote audio element for call */}
      <audio ref={remoteAudioRef} autoPlay className="hidden" />
    </div>
  );
}
