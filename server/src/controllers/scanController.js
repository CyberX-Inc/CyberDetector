const { scanVirusTotal } = require('../services/virusTotalService');
const { scanGoogleSafeBrowsing } = require('../services/googleSafeBrowsingService');
const { scanUrlhaus } = require('../services/urlhausService');
const { runLocalChecks } = require('../services/localChecks');
const { calculateRisk } = require('../services/riskScoring');
const { insertScan } = require('../models/scanModel');
const handleScan = async (req, res, next) => {
  const encodedUrl = req.params[0];
  let originalUrl;
  try {
    originalUrl = decodeURIComponent(encodedUrl);
    new URL(originalUrl);
  } catch (error) {
    return res.status(400).send('Invalid URL');
  }
  const [vtResult, gsbResult, urlhausResult, localFindings] = await Promise.all([
    scanVirusTotal(originalUrl).catch(() => ({ detected: false, message: 'Error' })),
    scanGoogleSafeBrowsing(originalUrl).catch(() => ({ detected: false, message: 'Error' })),
    scanUrlhaus(originalUrl).catch(() => ({ detected: false, message: 'Error' })),
    runLocalChecks(originalUrl),
  ]);
  const results = {
    virusTotal: vtResult,
    googleSafeBrowsing: gsbResult,
    urlhaus: urlhausResult,
    localFindings,
  };
  const { score, decision, reasons } = calculateRisk(results);
  await insertScan({
    originalUrl,
    riskScore: score,
    decision,
    virusTotalResult: vtResult.detected ? 'malicious' : (vtResult.message || 'safe'),
    googleSafeBrowsingResult: gsbResult.detected ? 'malicious' : (gsbResult.message || 'safe'),
    urlhausResult: urlhausResult.detected ? 'malicious' : (urlhausResult.message || 'safe'),
    localChecks: localFindings,
  });
  if (decision === 'redirect') {
    return res.redirect(302, originalUrl);
  } else {
    const blockData = {
      url: originalUrl,
      score,
      reasons,
      apiDetections: [
        vtResult.detected ? 'VirusTotal' : null,
        gsbResult.detected ? 'Google Safe Browsing' : null,
        urlhausResult.detected ? 'URLhaus' : null,
      ].filter(Boolean),
    };
    return res.status(403).render('block', blockData);
  }
};
module.exports = { handleScan };
