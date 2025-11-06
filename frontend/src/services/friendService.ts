import api from "@/lib/axios";

export const friendService = {
  async getFriends() {
    const res = await api.get("/friends");
    return res.data;
  },
};
