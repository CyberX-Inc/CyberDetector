const healthCheck = (req, res) => {
  res.json({ status: 'online' });
};
module.exports = { healthCheck };
