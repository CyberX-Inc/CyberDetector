import axios from 'axios';

const API_BASE = '/api';

export const protectUrl = async (url) => {
  try {
    const response = await axios.post(`${API_BASE}/protect`, { url });
    return response.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message || 'Unknown error';
    throw new Error(message);
  }
};

export const getHistory = async () => {
  try {
    const response = await axios.get(`${API_BASE}/history`);
    return response.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message || 'Unknown error';
    throw new Error(message);
  }
};
