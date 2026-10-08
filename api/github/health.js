'use strict';

const { requiredEnv } = require('./_auth');

module.exports = async function health(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const clientId = requiredEnv('GITHUB_APP_CLIENT_ID');
    const clientSecret = requiredEnv('GITHUB_APP_CLIENT_SECRET');
    const redirectUri = requiredEnv('GITHUB_APP_REDIRECT_URI');
    requiredEnv('GITHUB_APP_COOKIE_SECRET');

    const params = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code: '__anvil_health_check__',
      redirect_uri: redirectUri
    });

    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'X-GitHub-Api-Version': '2022-11-28' },
      body: params.toString()
    });
    const data = await response.json().catch(() => ({}));

    return res.status(200).json({
      ok: true,
      credentialsConfigured: true,
      github: { httpStatus: response.status, error: data.error || null },
      redirectUri
    });
  } catch (error) {
    return res.status(500).json({ ok: false, credentialsConfigured: false, error: error.message || 'configuration_error' });
  }
};
