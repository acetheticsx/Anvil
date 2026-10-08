'use strict';

const { getSession, setSession, githubFetch, requiredEnv } = require('./_auth');

async function countEndpoint(path, token) {
  const response = await githubFetch(path, token);
  if (!response.ok) return { count: 0, available: false };
  const data = await response.json();
  if (typeof data.total_count === 'number') {
    return { count: data.total_count, available: true };
  }
  if (!Array.isArray(data)) return { count: 0, available: false };

  const link = response.headers.get('link') || '';
  const lastMatch = link.match(/<[^>]+[?&]page=(\d+)[^>]*>;\s*rel="last"/i);
  if (lastMatch) {
    const pages = Number(lastMatch[1]);
    if (Number.isSafeInteger(pages) && pages >= 1) {
      return { count: (pages - 1) * 100 + data.length, available: true };
    }
  }
  return { count: data.length, available: true };
}

async function refreshAccessToken(session) {
  if (!session.refreshToken || (session.refreshExpiresAt && Date.now() >= session.refreshExpiresAt)) return null;
  const params = new URLSearchParams({
    client_id: requiredEnv('GITHUB_APP_CLIENT_ID'),
    client_secret: requiredEnv('GITHUB_APP_CLIENT_SECRET'),
    grant_type: 'refresh_token',
    refresh_token: session.refreshToken
  });
  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'X-GitHub-Api-Version': '2022-11-28' },
    body: params.toString()
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) return null;
  return {
    ...session,
    accessToken: data.access_token,
    refreshToken: data.refresh_token || session.refreshToken,
    expiresAt: Number(data.expires_in) > 0 ? Date.now() + Number(data.expires_in) * 1000 : null,
    refreshExpiresAt: Number(data.refresh_token_expires_in) > 0 ? Date.now() + Number(data.refresh_token_expires_in) * 1000 : session.refreshExpiresAt
  };
}

module.exports = async function session(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let session = getSession(req, { allowExpired: true });
  if (!session) return res.status(401).json({ connected: false });

  if (session.expiresAt && Date.now() >= session.expiresAt) {
    session = await refreshAccessToken(session);
    if (!session) return res.status(401).json({ connected: false, error: 'github_session_expired' });
    setSession(res, session);
  }

  try {
    const login = session.user.login;
    const [stars, gists, issues, prs] = await Promise.all([
      countEndpoint('/user/starred?per_page=100', session.accessToken),
      countEndpoint('/gists?per_page=100', session.accessToken),
      countEndpoint('/search/issues?q=' + encodeURIComponent('author:' + login + '+is:issue') + '&per_page=1', session.accessToken),
      countEndpoint('/search/issues?q=' + encodeURIComponent('author:' + login + '+is:pr') + '&per_page=1', session.accessToken)
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
    return res.status(502).json({ connected: true, error: 'github_data_sync_failed' });
  }
};
