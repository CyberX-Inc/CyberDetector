const protectUrl = (req, res) => {
  let { url } = req.body;
  console.log('📥 Protect request:', url);
  if (!url) return res.status(400).json({ error: 'URL is required' });

  // Normalize URL: if it starts with http:/ or https:/ (single slash), fix it
  url = url.replace(/^(https?):\/([^\/])/, '$1://$2');

  try { new URL(url); } catch (_) { return res.status(400).json({ error: 'Invalid URL format' }); }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:3000';
  const baseUrl = `${protocol}://${host}`;

  const protectedUrl = `${baseUrl}/url/${url}`;
  console.log('🔗 Protected URL:', protectedUrl);
  res.json({ protectedUrl });
};
module.exports = { protectUrl };
