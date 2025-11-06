import api from "@/lib/axios";

export const groupService = {
  async createGroup(payload: { name: string; members?: string[] }) {
    console.log("🔵 groupService.createGroup called with:", payload);
    try {
      const res = await api.post("/groups", payload);
      console.log("✅ groupService.createGroup response:", res.data);
      return res.data;
    } catch (error: any) {
      console.error("❌ groupService.createGroup error:", error);
      console.error("❌ Error response:", error.response);
      throw error;
    }
  },

  async listMyGroups() {
    const res = await api.get("/groups");
    return res.data;
  },
};
