const axios = require('axios');
const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const SB_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const scanGoogleSafeBrowsing = async (url) => {
  if (!SAFE_BROWSING_KEY) {
    return { detected: false, message: 'Google Safe Browsing API key not configured' };
  }
  try {
    const payload = {
      client: { clientId: 'url-defense', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };
    const response = await axios.post(
      `${SB_URL}?key=${SAFE_BROWSING_KEY}`,
      payload,
      { headers: { 'Content-Type': 'application/json' } }
    );
    if (response.data.matches && response.data.matches.length > 0) {
      const threatTypes = response.data.matches.map(m => m.threatType).join(', ');
      return { detected: true, message: `Google Safe Browsing: ${threatTypes}` };
    }
    return { detected: false, message: 'Google Safe Browsing: No threats' };
  } catch (error) {
    console.error('Google Safe Browsing error:', error.message);
    return { detected: false, message: 'Google Safe Browsing service unavailable' };
  }
};
module.exports = { scanGoogleSafeBrowsing };
