const { Pool } = require('pg');
let pool = null;
const initDB = async () => {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      original_url TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      risk_score INTEGER NOT NULL,
      decision TEXT NOT NULL,
      virus_total_result TEXT,
      google_safe_browsing_result TEXT,
      urlhaus_result TEXT,
      local_checks TEXT
    )
  `);
  console.log('📋 Scans table ready (PostgreSQL)');
  return pool;
};
const getDB = () => pool;
module.exports = { initDB, getDB };
