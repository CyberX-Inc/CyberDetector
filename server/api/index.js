const express = require('express');
const cors = require('cors');
const path = require('path');
const apiRoutes = require('../src/routes/apiRoutes');
const urlRoutes = require('../src/routes/urlRoutes');
const errorHandler = require('../src/middleware/errorHandler');
const { initDB } = require('../src/database/db');
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../src/views'));
app.use('/api', apiRoutes);
app.use('/', urlRoutes);
app.use(errorHandler);
let dbReady = false;
app.use(async (req, res, next) => {
  if (!dbReady) {
    try { await initDB(); dbReady = true; } catch (e) { return res.status(500).json({ error: 'Database error' }); }
  }
  next();
});
module.exports = app;
