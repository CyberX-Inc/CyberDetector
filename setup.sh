#!/bin/bash
set -e
echo "🚀 URL Defense Project Generator"
mkdir -p server/src/{controllers,routes,services,models,database,middleware,utils,views} server/data
mkdir -p client/src/{pages,components}

cat > server/package.json << 'PKG'
{
  "name": "url-defense-api",
  "version": "1.0.0",
  "description": "URL Defense service with threat intelligence scanning",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "axios": "^1.6.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "ejs": "^3.1.9",
    "express": "^4.18.2",
    "sqlite3": "^5.1.6"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
PKG

cat > server/.env.example << 'ENV'
PORT=3000
VIRUSTOTAL_API_KEY=your_virustotal_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
ENV

cat > server/server.js << 'SRV'
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const apiRoutes = require('./src/routes/apiRoutes');
const urlRoutes = require('./src/routes/urlRoutes');
const errorHandler = require('./src/middleware/errorHandler');
const { initDB } = require('./src/database/db');
const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src/views'));
app.use('/api', apiRoutes);
app.use('/', urlRoutes);
app.use(errorHandler);
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ URL Defense API running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ Failed to initialize database:', err);
    process.exit(1);
  });
SRV

cat > server/src/database/db.js << 'DB'
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

cat > server/src/models/scanModel.js << 'MOD'
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

cat > server/src/services/virusTotalService.js << 'VT'
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
VT

cat > server/src/services/googleSafeBrowsingService.js << 'GSB'
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
GSB

cat > server/src/services/urlhausService.js << 'UH'
const axios = require('axios');
const URLHAUS_API_URL = 'https://urlhaus-api.abuse.ch/v1/url/';
const scanUrlhaus = async (url) => {
  try {
    const response = await axios.post(
      URLHAUS_API_URL,
      new URLSearchParams({ url }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const data = response.data;
    if (data.query_status === 'ok' && data.url_info && data.url_info.url_status === 'malicious') {
      const threat = data.url_info.threat || 'malicious';
      return { detected: true, message: `URLhaus: ${threat}` };
    }
    return { detected: false, message: 'URLhaus: Not malicious' };
  } catch (error) {
    console.error('URLhaus error:', error.message);
    return { detected: false, message: 'URLhaus service unavailable' };
  }
};
module.exports = { scanUrlhaus };
UH

cat > server/src/services/localChecks.js << 'LC'
const runLocalChecks = (urlString) => {
  const findings = [];
  let url;
  try {
    url = new URL(urlString);
  } catch (_) {
    findings.push({ check: 'Invalid URL', points: 0 });
    return findings;
  }
  const hostname = url.hostname;
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  if (ipv4Regex.test(hostname) || ipv6Regex.test(hostname)) {
    findings.push({ check: 'IP address used instead of domain', points: 10 });
  }
  if (urlString.length > 150) {
    findings.push({ check: 'URL length > 150', points: 10 });
  }
  if (urlString.includes('@')) {
    findings.push({ check: 'URL contains "@"', points: 15 });
  }
  const suspiciousTLDs = ['.zip', '.top', '.xyz', '.loan', '.men', '.click', '.date', '.party', '.win', '.bid', '.trade', '.webcam', '.science', '.download', '.review', '.vip', '.work', '.red', '.ooo', '.lol', '.mom', '.gdn', '.网址', '.sexy', '.kim', '.在线', '.中文网'];
  const tld = url.hostname.split('.').pop();
  if (suspiciousTLDs.some(sTLD => tld === sTLD || tld.endsWith(sTLD))) {
    findings.push({ check: `Suspicious TLD: .${tld}`, points: 10 });
  }
  const shorteners = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 't.co', 'tiny.cc',
    'tr.im', 'v.gd', 'cutt.ly', 'dub.sh', 'git.io', 'migre.me', 'tiny.pl', 'qr.net', 'snipurl.com', 'shorturl.at'
  ];
  if (shorteners.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
    findings.push({ check: 'URL shortener detected', points: 10 });
  }
  return findings;
};
module.exports = { runLocalChecks };
LC

cat > server/src/services/riskScoring.js << 'RS'
const calculateRisk = (results) => {
  let score = 0;
  const reasons = [];
  if (results.virusTotal && results.virusTotal.detected) {
    score += 50;
    reasons.push(results.virusTotal.message);
  }
  if (results.googleSafeBrowsing && results.googleSafeBrowsing.detected) {
    score += 50;
    reasons.push(results.googleSafeBrowsing.message);
  }
  if (results.urlhaus && results.urlhaus.detected) {
    score += 50;
    reasons.push(results.urlhaus.message);
  }
  if (results.localFindings) {
    for (const finding of results.localFindings) {
      score += finding.points;
      reasons.push(finding.check);
    }
  }
  const decision = score >= 60 ? 'block' : 'redirect';
  return { score, decision, reasons };
};
module.exports = { calculateRisk };
RS

cat > server/src/controllers/protectController.js << 'PC'
const protectUrl = (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  try {
    new URL(url);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const encoded = encodeURIComponent(url);
  const protectedUrl = `${baseUrl}/url/${encoded}`;
  res.json({ protectedUrl });
};
module.exports = { protectUrl };
PC

cat > server/src/controllers/scanController.js << 'SC'
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
SC

cat > server/src/controllers/healthController.js << 'HC'
const healthCheck = (req, res) => {
  res.json({ status: 'online' });
};
module.exports = { healthCheck };
HC

cat > server/src/routes/apiRoutes.js << 'AR'
const express = require('express');
const router = express.Router();
const { protectUrl } = require('../controllers/protectController');
const { healthCheck } = require('../controllers/healthController');
const { getAllScans } = require('../models/scanModel');
router.post('/protect', protectUrl);
router.get('/health', healthCheck);
router.get('/history', async (req, res) => {
  try {
    const scans = await getAllScans();
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});
module.exports = router;
AR

cat > server/src/routes/urlRoutes.js << 'UR'
const express = require('express');
const router = express.Router();
const { handleScan } = require('../controllers/scanController');
router.get('/url/*', handleScan);
module.exports = router;
UR

cat > server/src/middleware/errorHandler.js << 'EH'
const errorHandler = (err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
};
module.exports = errorHandler;
EH

cat > server/src/utils/logger.js << 'LG'
const log = (message, level = 'info') => {
  console.log(`[${level.toUpperCase()}] ${message}`);
};
module.exports = { log };
LG

cat > server/src/views/block.ejs << 'BL'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dangerous Website Blocked</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
    body { background: #fef2f2; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; }
    .block-card { max-width: 640px; width: 100%; background: white; border-radius: 1.5rem; box-shadow: 0 20px 60px rgba(0,0,0,0.15); padding: 2.5rem 2rem; text-align: center; border-top: 6px solid #dc2626; }
    .icon { font-size: 4.5rem; line-height: 1; margin-bottom: 0.5rem; }
    h1 { font-size: 2rem; font-weight: 700; color: #dc2626; margin-bottom: 0.5rem; }
    .sub { font-size: 1rem; color: #6b7280; margin-bottom: 1.5rem; word-break: break-all; }
    .url-box { background: #f9fafb; border-radius: 0.75rem; padding: 0.75rem 1rem; font-size: 0.9rem; color: #111827; word-break: break-all; border: 1px solid #e5e7eb; margin-bottom: 1.5rem; }
    .score { display: inline-block; background: #fee2e2; color: #991b1b; font-weight: 600; padding: 0.25rem 1rem; border-radius: 999px; font-size: 1.1rem; margin-bottom: 1.5rem; }
    .reason-list { text-align: left; background: #f9fafb; border-radius: 0.75rem; padding: 1rem 1.5rem; margin-bottom: 1.5rem; border: 1px solid #e5e7eb; }
    .reason-list li { list-style: none; padding: 0.25rem 0; font-size: 0.95rem; color: #374151; border-bottom: 1px solid #f3f4f6; }
    .reason-list li:last-child { border-bottom: none; }
    .reason-list li::before { content: "⚠️ "; }
    .footnote { font-size: 0.85rem; color: #9ca3af; margin-top: 1rem; }
    .btn { display: inline-block; background: #dc2626; color: white; font-weight: 600; padding: 0.6rem 2rem; border-radius: 999px; text-decoration: none; transition: background 0.2s; border: none; cursor: default; pointer-events: none; opacity: 0.8; }
  </style>
</head>
<body>
  <div class="block-card">
    <div class="icon">🚫</div>
    <h1>Dangerous Website Blocked</h1>
    <p class="sub">This link has been blocked for your security</p>
    <div class="url-box"><strong>URL:</strong> <%= url %></div>
    <div class="score">Risk Score: <%= score %></div>
    <div class="reason-list">
      <strong>Reasons for blocking:</strong>
      <ul>
        <% reasons.forEach(function(reason) { %>
          <li><%= reason %></li>
        <% }) %>
        <% if (apiDetections && apiDetections.length > 0) { %>
          <li style="margin-top: 0.5rem; font-weight: 500; border-top: 1px solid #e5e7eb; padding-top: 0.5rem;">
            Detected by: <%= apiDetections.join(', ') %>
          </li>
        <% } %>
      </ul>
    </div>
    <button class="btn">Blocked</button>
    <p class="footnote">No bypass option available</p>
  </div>
</body>
</html>
BL

# ----------------------------------------------------------------------
# FRONTEND
# ----------------------------------------------------------------------

cat > client/package.json << 'CPKG'
{
  "name": "url-defense-client",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.1",
    "axios": "^1.6.2"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "vite": "^4.5.0"
  }
}
CPKG

cat > client/vite.config.js << 'VITE'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:3000',
      '/url': 'http://localhost:3000',
    },
  },
});
VITE

cat > client/tailwind.config.js << 'TW'
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: { extend: {} },
  plugins: [],
};
TW

cat > client/postcss.config.js << 'PCSS'
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
PCSS

cat > client/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>URL Defense</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
HTML

cat > client/src/main.jsx << 'MAIN'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
MAIN

cat > client/src/index.css << 'CSS'
@tailwind base;
@tailwind components;
@tailwind utilities;
CSS

cat > client/src/App.jsx << 'APP'
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import History from './pages/History';
import Layout from './components/Layout';
function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
export default App;
APP

cat > client/src/api.js << 'API'
import axios from 'axios';
const API_BASE = '/api';
export const protectUrl = async (url) => {
  const response = await axios.post(`${API_BASE}/protect`, { url });
  return response.data;
};
export const getHistory = async () => {
  const response = await axios.get(`${API_BASE}/history`);
  return response.data;
};
API

cat > client/src/components/Layout.jsx << 'LAY'
import { Link } from 'react-router-dom';
function Layout({ children }) {
  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-2">
              <span className="text-2xl font-bold text-indigo-600">🛡️ URL Defense</span>
            </div>
            <div className="flex space-x-4">
              <Link to="/" className="text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-md text-sm font-medium">Home</Link>
              <Link to="/history" className="text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-md text-sm font-medium">History</Link>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}
export default Layout;
LAY

cat > client/src/pages/Home.jsx << 'HOME'
import { useState } from 'react';
import { protectUrl } from '../api';
function Home() {
  const [url, setUrl] = useState('');
  const [protectedUrl, setProtectedUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setProtectedUrl('');
    try {
      const data = await protectUrl(url);
      setProtectedUrl(data.protectedUrl);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to generate protected link');
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-3xl font-bold text-gray-900 mb-4">Protect a URL</h1>
      <p className="text-gray-600 mb-6">
        Enter a link to generate a protected URL that will be scanned for threats before redirecting.
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="url" className="block text-sm font-medium text-gray-700">Destination URL</label>
          <input
            type="url"
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
        >
          {loading ? 'Generating...' : 'Generate Protected Link'}
        </button>
      </form>
      {error && (
        <div className="mt-4 text-red-600 text-sm bg-red-50 border border-red-200 rounded-md p-3">
          {error}
        </div>
      )}
      {protectedUrl && (
        <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-md">
          <p className="text-sm font-medium text-green-800">Protected URL:</p>
          <div className="mt-1 flex items-center justify-between">
            <code className="text-sm bg-white px-3 py-2 rounded border border-gray-200 flex-1 mr-2 overflow-x-auto">
              {protectedUrl}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(protectedUrl)}
              className="text-indigo-600 hover:text-indigo-800 text-sm font-medium"
            >
              Copy
            </button>
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Anyone opening this link will be scanned for threats.
          </p>
        </div>
      )}
    </div>
  );
}
export default Home;
HOME

cat > client/src/pages/History.jsx << 'HIST'
import { useEffect, useState } from 'react';
import { getHistory } from '../api';
function History() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await getHistory();
        setScans(data);
      } catch (err) {
        setError('Failed to load history');
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);
  if (loading) {
    return <div className="text-center text-gray-600">Loading history...</div>;
  }
  if (error) {
    return <div className="text-red-600 text-center">{error}</div>;
  }
  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-4">Scan History</h2>
      {scans.length === 0 ? (
        <p className="text-gray-500">No scans yet.</p>
      ) : (
        <div className="overflow-x-auto shadow ring-1 ring-black ring-opacity-5 rounded-lg">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Decision</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">API Results</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="px-6 py-4 text-sm text-gray-900 truncate max-w-xs">{scan.original_url}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{new Date(scan.timestamp).toLocaleString()}</td>
                  <td className="px-6 py-4 text-sm">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${scan.risk_score >= 60 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                      {scan.risk_score}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm capitalize">{scan.decision}</td>
                  <td className="px-6 py-4 text-sm">
                    <div className="flex flex-wrap gap-1">
                      {scan.virus_total_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">VT</span>}
                      {scan.google_safe_browsing_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">GSB</span>}
                      {scan.urlhaus_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">URLhaus</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
export default History;
HIST

# ----------------------------------------------------------------------
# ROOT README
# ----------------------------------------------------------------------
cat > README.md << 'RD'
# URL Defense API

Complete URL scanning and protection service.

## Setup

1. `cd server && npm install`
2. `cp .env.example .env` and add your API keys
3. `npm run dev`
4. In another terminal: `cd client && npm install && npm run dev`
5. Open http://localhost:5173

See full documentation in the project.
RD

echo "✅ Project created successfully!"
echo ""
echo "Next steps:"
echo "  cd server && npm install && cp .env.example .env && npm run dev"
echo "  (in another terminal) cd client && npm install && npm run dev"
echo ""
echo "Then visit http://localhost:5173"
