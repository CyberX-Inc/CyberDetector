const protectUrl = (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try { new URL(url); } catch (_) { return res.status(400).json({ error: 'Invalid URL format' }); }
  // For development, always use localhost:3000
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  const protectedUrl = `${baseUrl}/url/${encodeURIComponent(url)}`;
  res.json({ protectedUrl });
};
module.exports = { protectUrl };
