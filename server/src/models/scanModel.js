const { getDB } = require('../database/db');
const insertScan = async (data) => {
  const db = getDB();
  const { originalUrl, riskScore, decision, virusTotalResult, googleSafeBrowsingResult, urlhausResult, localChecks } = data;
  const res = await db.query(
    `INSERT INTO scans (original_url, risk_score, decision, virus_total_result, google_safe_browsing_result, urlhaus_result, local_checks)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
    [originalUrl, riskScore, decision, virusTotalResult || null, googleSafeBrowsingResult || null, urlhausResult || null, JSON.stringify(localChecks) || null]
  );
  return { id: res.rows[0].id };
};
const getAllScans = async () => {
  const db = getDB();
  const res = await db.query('SELECT * FROM scans ORDER BY timestamp DESC');
  return res.rows;
};
module.exports = { insertScan, getAllScans };
