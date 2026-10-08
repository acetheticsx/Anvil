'use strict';

const { requiredEnv, consumeOAuthState, setSession, safeReturnTo } = require('./_auth');

module.exports = async function callback(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).send('Method not allowed');
  }

  try {
    const state = String(req.query?.state || '');
    const code = String(req.query?.code || '');
    const oauthState = consumeOAuthState(req, res, state);

    if (!oauthState || !code) {
      return res.redirect(302, '/?github_auth=error&reason=invalid_state');
    }

    if (req.query?.error) {
      const returnTo = safeReturnTo(oauthState.returnTo);
      return res.redirect(302, `${returnTo}${returnTo.includes('?') ? '&' : '?'}github_auth=cancelled`);
    }

    const clientId = requiredEnv('GITHUB_APP_CLIENT_ID');
    const clientSecret = requiredEnv('GITHUB_APP_CLIENT_SECRET');
    const redirectUri = requiredEnv('GITHUB_APP_REDIRECT_URI');

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error('GitHub OAuth token exchange failed');
    }

    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${tokenData.access_token}`,
        'X-GitHub-Api-Version': '2022-11-28'
      }
    });

    if (!userResponse.ok) throw new Error('Unable to verify the GitHub account');
    const user = await userResponse.json();

    setSession(res, {
      accessToken: tokenData.access_token,
      user: {
        id: user.id,
        login: user.login,
        name: user.name || user.login,
        avatarUrl: user.avatar_url || ''
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    const returnTo = safeReturnTo(oauthState.returnTo);
    return res.redirect(302, `${returnTo}${returnTo.includes('?') ? '&' : '?'}github_auth=connected`);
  } catch (error) {
    return res.redirect(302, `/?github_auth=error&reason=${encodeURIComponent(error.message || 'oauth_failed')}`);
  }
};