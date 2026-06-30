const express = require('express');
const router = express.Router();
const { handleScan } = require('../controllers/scanController');
router.get('/url/*', handleScan);
module.exports = router;
