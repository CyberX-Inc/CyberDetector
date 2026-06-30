import axios from 'axios';
const API_BASE = '/api';
export const protectUrl = async (url) => {
  const response = await axios.post(`${API_BASE}/protect`, { url });
  return response.data;
};
export const getHistory = async () => {
  const response = await axios.get(`${API_BASE}/history`);
  return response.data;
};
