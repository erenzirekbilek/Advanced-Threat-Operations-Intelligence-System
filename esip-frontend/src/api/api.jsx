import axios from "axios";

const API_BASE = "http://127.0.0.1:5000/api";

export const getThreats = async (status = "active", severity = "") => {
  const res = await axios.get(`${API_BASE}/threats`, {
    params: { status, severity },
  });
  return res.data;
};

export const getMetrics = async () => {
  const res = await axios.get(`${API_BASE}/metrics`);
  return res.data;
};

export const getTimeline = async (hours = 24) => {
  const res = await axios.get(`${API_BASE}/analytics/timeline`, {
    params: { hours },
  });
  return res.data;
};

export const getCompliance = async () => {
  const res = await axios.get(`${API_BASE}/compliance/status`);
  return res.data;
};

export const simulateAttack = async (type) => {
  const res = await axios.post(`${API_BASE}/simulate/attack`, { type });
  return res.data;
};
