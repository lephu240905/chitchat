"use client";

import React from "react";
import { Phone } from "lucide-react";

interface Props {
  open: boolean;
  callerName?: string;
  isVideo?: boolean;
  outgoing?: boolean;
  inCall?: boolean;
  onAccept?: () => void;
  onReject?: () => void;
  onCancel?: () => void;
}

export default function CallModal({
  open,
  callerName,
  isVideo = false,
  outgoing = false,
  inCall = false,
  onAccept,
  onReject,
  onCancel,
}: Props) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white dark:bg-gray-900 p-6 rounded-lg w-full max-w-sm text-center">
        <div className="mb-4">
          <div className="w-16 h-16 bg-gradient-to-br from-indigo-400 to-purple-400 rounded-full mx-auto flex items-center justify-center text-white font-semibold text-2xl">
            {callerName?.[0]?.toUpperCase() || "?"}
          </div>
        </div>

        <h3 className="text-lg font-semibold mb-1">
          {inCall
            ? "Đang trong cuộc gọi"
            : outgoing
            ? "Đang gọi"
            : "Cuộc gọi đến"}
        </h3>

        <p className="text-sm text-gray-500 mb-2">{callerName || "Ai đó"}</p>
        <p className="text-sm text-gray-500 mb-4">
          {isVideo ? "Cuộc gọi video" : "Cuộc gọi âm thanh"}
        </p>

        <div className="flex justify-center gap-3">
          {inCall ? (
            <button
              onClick={() => onReject && onReject()}
              className="flex items-center gap-2 px-6 py-4 rounded-full bg-red-600 text-white shadow-lg"
            >
              <Phone className="w-5 h-5" />
              <span>Ngắt</span>
            </button>
          ) : !outgoing ? (
            <>
              <button
                onClick={() => onReject && onReject()}
                className="px-4 py-2 rounded-md bg-red-500 text-white"
              >
                Từ chối
              </button>
              <button
                onClick={() => onAccept && onAccept()}
                className="px-4 py-2 rounded-md bg-green-600 text-white"
              >
                Chấp nhận
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => onCancel && onCancel()}
                className="px-4 py-2 rounded-md bg-gray-200 dark:bg-gray-700"
              >
                Huỷ cuộc gọi
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
