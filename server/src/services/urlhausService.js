const axios = require('axios');
const URLHAUS_API_URL = 'https://urlhaus-api.abuse.ch/v1/url/';
const scanUrlhaus = async (url) => {
  try {
    const response = await axios.post(URLHAUS_API_URL, new URLSearchParams({ url }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const data = response.data;
    if (data.query_status === 'ok' && data.url_info && data.url_info.url_status === 'malicious') {
      return { detected: true, message: `URLhaus: ${data.url_info.threat || 'malicious'}` };
    }
    return { detected: false, message: 'URLhaus: Not malicious' };
  } catch (error) {
    if (error.response?.status === 401) return { detected: false, message: 'URLhaus: API key not provided or invalid' };
    console.error('URLhaus error:', error.message);
    return { detected: false, message: 'URLhaus service unavailable' };
  }
};
module.exports = { scanUrlhaus };
