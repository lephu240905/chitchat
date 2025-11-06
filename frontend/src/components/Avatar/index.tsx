"use client";

interface AvatarProps {
  initials: string;
  color?: string;
  size?: "sm" | "md" | "lg";
}

export default function Avatar({
  initials,
  color = "purple",
  size = "md",
}: AvatarProps) {
  const sizeClasses = {
    sm: "w-8 h-8 text-xs",
    md: "w-10 h-10 text-sm",
    lg: "w-12 h-12 text-base",
  };

  const colorClasses = {
    purple: "bg-gradient-to-br from-purple-400 to-purple-600",
    pink: "bg-gradient-to-br from-pink-400 to-pink-600",
    blue: "bg-gradient-to-br from-blue-400 to-blue-600",
    red: "bg-gradient-to-br from-red-400 to-red-600",
  };

  return (
    <div
      className={`${sizeClasses[size]} ${
        colorClasses[color as keyof typeof colorClasses]
      } 
      rounded-full flex items-center justify-center text-white font-bold border-2 border-white`}
    >
      {initials}
    </div>
  );
}
