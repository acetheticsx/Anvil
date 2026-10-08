'use strict';

const crypto = require('node:crypto');

const COOKIE_NAME = 'anvil_github_session';
const OAUTH_COOKIE = 'anvil_github_oauth';
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
const OAUTH_MAX_AGE = 60 * 10;

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function cookieSecret() {
  return requiredEnv('GITHUB_APP_COOKIE_SECRET');
}

function key() {
  return crypto.createHash('sha256').update(cookieSecret()).digest();
}

function b64(value) {
  return Buffer.from(value).toString('base64url');
}

function unb64(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function sign(value) {
  return crypto.createHmac('sha256', cookieSecret()).update(value).digest('base64url');
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function encrypt(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final()
  ]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64url')).join('.');
}

function decrypt(value) {
  try {
    const [ivText, tagText, ciphertextText] = String(value).split('.');
    if (!ivText || !tagText || !ciphertextText) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(ivText, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(ciphertextText, 'base64url')),
      decipher.final()
    ]).toString('utf8');
    return JSON.parse(plaintext);
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const cookies = {};
  for (const pair of raw.split(';')) {
    const index = pair.indexOf('=');
    if (index < 0) continue;
    cookies[pair.slice(0, index).trim()] = decodeURIComponent(pair.slice(index + 1).trim());
  }
  return cookies;
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge != null) parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  parts.push(`Path=${options.path || '/'}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  parts.push(`SameSite=${options.sameSite || 'Lax'}`);
  if (process.env.NODE_ENV === 'production') parts.push('Secure');
  return parts.join('; ');
}

function appendSetCookie(res, cookie) {
  const current = res.getHeader('Set-Cookie');
  const values = Array.isArray(current) ? current : current ? [current] : [];
  res.setHeader('Set-Cookie', [...values, cookie]);
}

function setSession(res, payload) {
  appendSetCookie(res, serializeCookie(COOKIE_NAME, encrypt(payload), { maxAge: SESSION_MAX_AGE }));
}

function clearSession(res) {
  appendSetCookie(res, serializeCookie(COOKIE_NAME, '', { maxAge: 0 }));
}

function getSession(req) {
  const value = parseCookies(req)[COOKIE_NAME];
  if (!value) return null;
  const session = decrypt(value);
  if (!session || !session.accessToken || !session.user?.login) return null;
  if (session.expiresAt && Date.now() > session.expiresAt) return null;
  return session;
}

function setOAuthState(res, payload) {
  const encoded = b64(JSON.stringify(payload));
  const value = `${encoded}.${sign(encoded)}`;
  appendSetCookie(res, serializeCookie(OAUTH_COOKIE, value, { maxAge: OAUTH_MAX_AGE }));
}

function consumeOAuthState(req, res, expectedState) {
  const value = parseCookies(req)[OAUTH_COOKIE];
  appendSetCookie(res, serializeCookie(OAUTH_COOKIE, '', { maxAge: 0 }));
  if (!value || !expectedState) return null;
  const dot = value.lastIndexOf('.');
  if (dot < 1) return null;
  const encoded = value.slice(0, dot);
  const signature = value.slice(dot + 1);
  if (!timingSafeEqual(signature, sign(encoded))) return null;
  try {
    const payload = JSON.parse(unb64(encoded));
    if (payload.state !== expectedState) return null;
    if (!payload.expiresAt || Date.now() > payload.expiresAt) return null;
    return payload;
  } catch {
    return null;
  }
}

function safeReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return '/';
  if (value.startsWith('//') || value.includes('\\')) return '/';
  try {
    const url = new URL(value, 'https://anvil.local');
    if (url.origin !== 'https://anvil.local') return '/';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
}

function githubHeaders(token) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28'
  };
}

async function githubFetch(path, token, options = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    ...options,
    headers: { ...githubHeaders(token), ...(options.headers || {}) }
  });
  return response;
}

module.exports = {
  COOKIE_NAME,
  SESSION_MAX_AGE,
  requiredEnv,
  parseCookies,
  serializeCookie,
  appendSetCookie,
  setSession,
  clearSession,
  getSession,
  setOAuthState,
  consumeOAuthState,
  safeReturnTo,
  githubFetch
};