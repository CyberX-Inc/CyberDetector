const express = require('express');
const cors = require('cors');
const path = require('path');
const apiRoutes = require('../server/src/routes/apiRoutes');
const urlRoutes = require('../server/src/routes/urlRoutes');
const errorHandler = require('../server/src/middleware/errorHandler');
const { initDB } = require('../server/src/database/db');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../server/src/views'));

app.use('/api', apiRoutes);
app.use('/', urlRoutes);
app.use(errorHandler);

let dbInitialized = false;
app.use(async (req, res, next) => {
  if (!dbInitialized) {
    try {
      await initDB();
      dbInitialized = true;
      console.log('✅ Database initialized');
    } catch (err) {
      console.error('❌ Database init failed:', err.stack);
      // Continue – we will still process requests, but DB inserts will fail gracefully
    }
  }
  next();
});

module.exports = app;
