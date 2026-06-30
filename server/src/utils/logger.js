const log = (message, level = 'info') => {
  console.log(`[${level.toUpperCase()}] ${message}`);
};
module.exports = { log };
