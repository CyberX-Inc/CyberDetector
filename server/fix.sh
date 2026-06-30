#!/bin/bash
set -e

cd server

# Reinstall sqlite3 (we removed it earlier)
npm install sqlite3 --save

# Restore SQLite database module (local development)
cat > src/database/db.js << 'DB'
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, '../../data/url_defense.db');
let db = null;

const initDB = () => {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) return reject(err);
      console.log('📦 SQLite database connected');
      const createTableSQL = `
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          original_url TEXT NOT NULL,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          risk_score INTEGER NOT NULL,
          decision TEXT NOT NULL,
          virus_total_result TEXT,
          google_safe_browsing_result TEXT,
          urlhaus_result TEXT,
          local_checks TEXT
        )
      `;
      db.run(createTableSQL, (err) => {
        if (err) return reject(err);
        console.log('📋 Scans table ready');
        resolve();
      });
    });
  });
};

const getDB = () => db;

module.exports = { initDB, getDB };
DB

# Restore SQLite scan model
cat > src/models/scanModel.js << 'MOD'
const { getDB } = require('../database/db');

const insertScan = (scanData) => {
  const db = getDB();
  return new Promise((resolve, reject) => {
    const { originalUrl, riskScore, decision, virusTotalResult, googleSafeBrowsingResult, urlhausResult, localChecks } = scanData;
    const stmt = db.prepare(`
      INSERT INTO scans 
      (original_url, risk_score, decision, virus_total_result, google_safe_browsing_result, urlhaus_result, local_checks)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
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
MOD

# Remove or ignore DATABASE_URL for local dev (we'll keep it in .env but not use it)
echo "✅ Local development restored to SQLite. DATABASE_URL in .env will be ignored."
echo "   You can now run 'npm run dev' and it will work."

# Restart servers (if using concurrently, you can just restart)
cd ..
echo "Now run: concurrently --kill-others --names \"BACKEND,FRONTEND\" --prefix-colors \"blue,magenta\" \"cd server && npm run dev\" \"cd client && npm run dev\""
