import { useState, useEffect } from "react";
import Sidebar from "../components/SideBar/index";
import ChatArea from "../components/ChatArea/index";
import { useAuthStore } from "@/stores/useAuthStore";

const ChatAppPage = () => {
  const [selectedChat, setSelectedChat] = useState<string | null>(null);
  const [isDark, setIsDark] = useState(false);
  const user = useAuthStore((s) => s.user);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDark);
  }, [isDark]);

  return (
    <div className="flex h-screen bg-background text-foreground">
      <Sidebar
        selectedChat={selectedChat}
        onSelectChat={setSelectedChat}
        isDark={isDark}
        onToggleDark={() => setIsDark(!isDark)}
        user={user}
      />
      <ChatArea 
        selectedChat={selectedChat} 
        isDark={isDark} 
        user={user}
        onSelectChat={setSelectedChat}
      />
    </div>
  );
};

export default ChatAppPage;
