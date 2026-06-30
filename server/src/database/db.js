const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const DB_PATH = path.join(__dirname, '../../data/url_defense.db');
let db = null;
const initDB = () => {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) return reject(err);
      console.log('📦 SQLite database connected');
      db.run(`CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_url TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER NOT NULL,
        decision TEXT NOT NULL,
        virus_total_result TEXT,
        google_safe_browsing_result TEXT,
        urlhaus_result TEXT,
        local_checks TEXT
      )`, (err) => {
        if (err) return reject(err);
        console.log('📋 Scans table ready');
        resolve();
      });
    });
  });
};
const getDB = () => db;
module.exports = { initDB, getDB };
