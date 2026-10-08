'use strict';

const { getSession, githubFetch } = require('./_auth');

async function countEndpoint(path, token) {
  const response = await githubFetch(path, token);
  if (!response.ok) return { count: 0, available: false };
  const data = await response.json();
  if (Array.isArray(data)) return { count: data.length, available: true };
  if (typeof data.total_count === 'number') return { count: data.total_count, available: true };
  return { count: 0, available: false };
}

module.exports = async function session(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const session = getSession(req);
  if (!session) return res.status(401).json({ connected: false });

  try {
    const login = session.user.login;
    const [stars, gists, issues, prs] = await Promise.all([
      countEndpoint('/user/starred?per_page=100', session.accessToken),
      countEndpoint('/gists?per_page=100', session.accessToken),
      countEndpoint(`/search/issues?q=${encodeURIComponent(`author:${login}+is:issue`)}&per_page=1`, session.accessToken),
      countEndpoint(`/search/issues?q=${encodeURIComponent(`author:${login}+is:pr`)}&per_page=1`, session.accessToken)
    ]);

    return res.status(200).json({
      connected: true,
      user: session.user,
      stars,
      gists,
      issues,
      pullRequests: prs,
      discussions: { count: 0, available: false },
      syncedAt: new Date().toISOString()
    });
  } catch {
    return res.status(502).json({ connected: true, error: 'GitHub data sync failed' });
  }
};