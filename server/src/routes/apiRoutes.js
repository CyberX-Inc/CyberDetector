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
