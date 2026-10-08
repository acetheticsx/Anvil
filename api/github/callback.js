'use strict';

const { requiredEnv, consumeOAuthState, setSession, safeReturnTo } = require('./_auth');

function redirectWithStatus(res, returnTo, params) {
  const target = safeReturnTo(returnTo);
  const url = new URL(target, 'https://anvil.local');
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return res.redirect(302, url.pathname + url.search + url.hash);
}

module.exports = async function callback(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).send('Method not allowed');
  }

  const state = String(req.query?.state || '');
  const code = String(req.query?.code || '');
  const error = String(req.query?.error || '');
  const oauthState = consumeOAuthState(req, res, state);

  if (!oauthState) return res.redirect(302, '/?github_auth=error&reason=invalid_state');
  if (error) return redirectWithStatus(res, oauthState.returnTo, { github_auth: error === 'access_denied' ? 'cancelled' : 'error', reason: error });
  if (!code) return redirectWithStatus(res, oauthState.returnTo, { github_auth: 'error', reason: 'missing_code' });

  try {
    const clientId = requiredEnv('GITHUB_APP_CLIENT_ID');
    const clientSecret = requiredEnv('GITHUB_APP_CLIENT_SECRET');
    const redirectUri = requiredEnv('GITHUB_APP_REDIRECT_URI');

    const params = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri
    });

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token?' + params.toString(), {
      method: 'POST',
      headers: { Accept: 'application/json', 'X-GitHub-Api-Version': '2022-11-28' }
    });
    const tokenData = await tokenResponse.json().catch(() => ({}));

    if (!tokenResponse.ok || !tokenData.access_token) {
      return redirectWithStatus(res, oauthState.returnTo, {
        github_auth: 'error',
        reason: tokenData.error || ('token_exchange_http_' + tokenResponse.status)
      });
    }

    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: 'Bearer ' + tokenData.access_token,
        'X-GitHub-Api-Version': '2026-03-10'
      }
    });

    if (!userResponse.ok) {
      return redirectWithStatus(res, oauthState.returnTo, {
        github_auth: 'error',
        reason: 'github_user_http_' + userResponse.status
      });
    }

    const user = await userResponse.json();
    const expiresIn = Number(tokenData.expires_in);
    const refreshExpiresIn = Number(tokenData.refresh_token_expires_in);

    setSession(res, {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || null,
      user: {
        id: user.id,
        login: user.login,
        name: user.name || user.login,
        avatarUrl: user.avatar_url || ''
      },
      createdAt: Date.now(),
      expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : null,
      refreshExpiresAt: Number.isFinite(refreshExpiresIn) && refreshExpiresIn > 0 ? Date.now() + refreshExpiresIn * 1000 : null
    });

    return redirectWithStatus(res, oauthState.returnTo, { github_auth: 'connected' });
  } catch {
    return redirectWithStatus(res, oauthState.returnTo, { github_auth: 'error', reason: 'token_exchange_failed' });
  }
};
