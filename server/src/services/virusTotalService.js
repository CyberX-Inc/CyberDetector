const axios = require('axios');
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_URL = 'https://www.virustotal.com/api/v3/urls';
const scanVirusTotal = async (url) => {
  if (!VIRUSTOTAL_API_KEY) {
    return { detected: false, message: 'VirusTotal API key not configured' };
  }
  try {
    const submitRes = await axios.post(
      VT_URL,
      new URLSearchParams({ url }),
      { headers: { 'x-apikey': VIRUSTOTAL_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const analysisId = submitRes.data.data.id;
    await new Promise(resolve => setTimeout(resolve, 2000));
    const reportRes = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } }
    );
    const stats = reportRes.data.data.attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    if (malicious > 0 || suspicious > 0) {
      return { detected: true, message: `VirusTotal: ${malicious} malicious, ${suspicious} suspicious` };
    }
    return { detected: false, message: 'VirusTotal: No threats found' };
  } catch (error) {
    console.error('VirusTotal error:', error.message);
    return { detected: false, message: 'VirusTotal service unavailable' };
  }
};
module.exports = { scanVirusTotal };
