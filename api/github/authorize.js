'use strict';

const crypto = require('node:crypto');
const { requiredEnv, setOAuthState, safeReturnTo } = require('./_auth');

module.exports = async function authorize(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const clientId = requiredEnv('GITHUB_APP_CLIENT_ID');
    const redirectUri = requiredEnv('GITHUB_APP_REDIRECT_URI');
    const state = crypto.randomBytes(24).toString('hex');
    const returnTo = safeReturnTo(req.query?.return_to || '/');

    setOAuthState(res, {
      state,
      returnTo,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('allow_signup', 'false');

    return res.redirect(302, url.toString());
  } catch (error) {
    return res.status(500).json({ error: error.message || 'OAuth configuration error' });
  }
};