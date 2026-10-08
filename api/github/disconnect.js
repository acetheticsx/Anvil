'use strict';

const { clearSession } = require('./_auth');

module.exports = async function disconnect(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const origin = req.headers.origin;
  const host = req.headers.host;
  if (!origin || !host) return res.status(403).json({ error: 'Origin required' });
  try {
    if (new URL(origin).host !== host) return res.status(403).json({ error: 'Invalid origin' });
  } catch {
    return res.status(403).json({ error: 'Invalid origin' });
  }

  clearSession(res);
  return res.status(200).json({ connected: false });
};