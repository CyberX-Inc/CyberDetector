const { scanVirusTotal } = require('../services/virusTotalService');
const { scanGoogleSafeBrowsing } = require('../services/googleSafeBrowsingService');
const { scanUrlhaus } = require('../services/urlhausService');
const { runLocalChecks } = require('../services/localChecks');
const { calculateRisk } = require('../services/riskScoring');
const { insertScan } = require('../models/scanModel');

const handleScan = async (req, res, next) => {
  console.log('📥 Incoming scan request');
  console.log('  req.params:', req.params);
  console.log('  req.url:', req.url);

  // Get the URL from req.params.url (set by the route middleware)
  let originalUrl = req.params.url || req.params[0];
  if (!originalUrl) {
    console.error('❌ No URL found in params');
    return res.status(400).send('Missing URL');
  }

  // Normalize the URL just in case (fix https:/ -> https://)
  originalUrl = originalUrl.replace(/^(https?):\/([^\/])/, '$1://$2');

  console.log(`🔍 Original URL: ${originalUrl}`);

  // Validate URL
  try {
    const parsed = new URL(originalUrl);
    if (!parsed.protocol || !parsed.hostname) {
      throw new Error('Invalid URL structure');
    }
  } catch (error) {
    console.error('❌ Invalid URL:', originalUrl, error);
    return res.status(400).send('Invalid URL: ' + originalUrl);
  }

  console.log('✅ URL valid, starting scans...');

  try {
    const [vtResult, gsbResult, urlhausResult, localFindings] = await Promise.all([
      scanVirusTotal(originalUrl).catch(e => {
        console.error('VT error:', e.message);
        return { detected: false, message: 'Error: ' + e.message };
      }),
      scanGoogleSafeBrowsing(originalUrl).catch(e => {
        console.error('GSB error:', e.message);
        return { detected: false, message: 'Error: ' + e.message };
      }),
      scanUrlhaus(originalUrl).catch(e => {
        console.error('URLhaus error:', e.message);
        return { detected: false, message: 'Error: ' + e.message };
      }),
      runLocalChecks(originalUrl),
    ]);

    console.log('VT result:', vtResult);
    console.log('GSB result:', gsbResult);
    console.log('URLhaus result:', urlhausResult);
    console.log('Local findings:', localFindings);

    const results = {
      virusTotal: vtResult,
      googleSafeBrowsing: gsbResult,
      urlhaus: urlhausResult,
      localFindings,
    };

    const { score, decision, reasons } = calculateRisk(results);
    console.log(`📊 Score: ${score}, Decision: ${decision}`);

    try {
      await insertScan({
        originalUrl,
        riskScore: score,
        decision,
        virusTotalResult: vtResult.detected ? 'malicious' : (vtResult.message || 'safe'),
        googleSafeBrowsingResult: gsbResult.detected ? 'malicious' : (gsbResult.message || 'safe'),
        urlhausResult: urlhausResult.detected ? 'malicious' : (urlhausResult.message || 'safe'),
        localChecks: localFindings,
      });
      console.log('✅ Scan logged to database');
    } catch (dbError) {
      console.error('⚠️  Database insert failed (continuing):', dbError.message);
    }

    if (decision === 'redirect') {
      console.log(`➡️  Redirecting to ${originalUrl}`);
      return res.redirect(302, originalUrl);
    } else {
      console.log('🚫 Blocking URL');
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
  } catch (error) {
    console.error('❌ Scan failed:', error.stack);
    return res.status(500).json({ error: 'Scan failed: ' + error.message });
  }
};

module.exports = { handleScan };
