const { getDB } = require('../database/db');
const insertScan = (scanData) => {
  const db = getDB();
  return new Promise((resolve, reject) => {
    const { originalUrl, riskScore, decision, virusTotalResult, googleSafeBrowsingResult, urlhausResult, localChecks } = scanData;
    const stmt = db.prepare(
      `INSERT INTO scans 
       (original_url, risk_score, decision, virus_total_result, google_safe_browsing_result, urlhaus_result, local_checks)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    stmt.run(
      originalUrl,
      riskScore,
      decision,
      virusTotalResult || null,
      googleSafeBrowsingResult || null,
      urlhausResult || null,
      JSON.stringify(localChecks) || null,
      function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID });
      }
    );
    stmt.finalize();
  });
};
const getAllScans = () => {
  const db = getDB();
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM scans ORDER BY timestamp DESC', (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};
module.exports = { insertScan, getAllScans };
