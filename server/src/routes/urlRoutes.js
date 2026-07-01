const express = require('express');
const router = express.Router();
const { handleScan } = require('../controllers/scanController');

// Capture everything after /url/ – including slashes and dots
router.get('/url/*', (req, res, next) => {
  // The wildcard puts everything after /url/ into req.params[0]
  // But Express decodes it, so we need to rebuild the original path
  const fullPath = req.originalUrl || req.url;
  const prefix = '/url/';
  if (fullPath.startsWith(prefix)) {
    req.params.url = fullPath.substring(prefix.length);
  } else {
    req.params.url = req.params[0] || '';
  }
  next();
}, handleScan);

module.exports = router;
