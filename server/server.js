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
