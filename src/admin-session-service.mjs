import { normalizeSupabaseAuthUrl } from './auth-endpoint.mjs';
import { createSupabaseAdminAuthorizer } from './admin-authz.mjs';

export class SessionError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'SessionError';
    this.status = status;
    this.code = code;
  }
}

const invalid = () => new SessionError(400, 'AUTH_FLOW_ERROR', 'Operação de autenticação inválida');
const unauthenticated = () => new SessionError(401, 'UNAUTHENTICATED', 'Autenticação necessária');
const forbidden = () => new SessionError(403, 'FORBIDDEN', 'Acesso negado');
const limited = () => new SessionError(429, 'RATE_LIMITED', 'Muitas tentativas');
const unavailable = () => new SessionError(503, 'AUTH_UNAVAILABLE', 'Serviço de autenticação indisponível');
const invalidFactor = (code) => new SessionError(503, code, 'Serviço de autenticação indisponível');
const factorLimit = () => new SessionError(409, 'MFA_FACTOR_LIMIT', 'Limite de fatores atingido');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeSession(payload, next, maxAccessTokenLifetime) {
  if (typeof payload?.access_token !== 'string' || !payload.access_token
    || typeof payload?.refresh_token !== 'string' || !payload.refresh_token
    || !Number.isInteger(payload?.expires_in) || payload.expires_in <= 0
    || payload.expires_in > maxAccessTokenLifetime) throw unavailable();
  let claims;
  try {
    const parts = payload.access_token.split('.');
    if (parts.length !== 3) throw new TypeError();
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw unavailable();
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)
    || !Number.isInteger(claims.iat) || !Number.isInteger(claims.exp)
    || claims.exp <= claims.iat || claims.exp - claims.iat > maxAccessTokenLifetime) throw unavailable();
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresIn: payload.expires_in,
    next
  };
}

export function createSupabaseAdminSessionService({
  authUrl,
  anonKey,
  fetchImpl = globalThis.fetch,
  maxAccessTokenLifetime = 3_600,
  maxTotpFactors = 2
}) {
  if (typeof anonKey !== 'string' || !anonKey || typeof fetchImpl !== 'function') {
    throw new TypeError('Configuração de autenticação inválida');
  }
  if (!Number.isInteger(maxAccessTokenLifetime) || maxAccessTokenLifetime < 60 || maxAccessTokenLifetime > 3_600
    || !Number.isInteger(maxTotpFactors) || maxTotpFactors < 1 || maxTotpFactors > 10) {
    throw new TypeError('Configuração de autenticação inválida');
  }
  const endpoint = normalizeSupabaseAuthUrl(authUrl);
  const authorizeAdmin = createSupabaseAdminAuthorizer({
    authUrl: endpoint,
    anonKey,
    expectedIssuer: endpoint,
    fetchImpl
  });

  async function request(path, { bearer, body, method = 'POST', login = false } = {}) {
    let response;
    try {
      response = await fetchImpl(`${endpoint}${path}`, {
        method,
        headers: {
          apikey: anonKey,
          ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
          ...(body ? { 'content-type': 'application/json' } : {})
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(5_000)
      });
    } catch {
      throw unavailable();
    }
    if (!response || typeof response.ok !== 'boolean') throw unavailable();
    if (!response.ok) {
      if (response.status >= 500) throw unavailable();
      if (response.status === 429) throw limited();
      if (response.status === 401 || (login && response.status === 400)) throw unauthenticated();
      throw invalid();
    }
    if (response.status === 204) return null;
    try { return await response.json(); } catch { throw unavailable(); }
  }

  async function ensureAdmin(accessToken) {
    const user = await request('/user', { bearer: accessToken, method: 'GET' });
    if (user?.app_metadata?.role !== 'admin') throw forbidden();
    if (typeof user?.email_confirmed_at !== 'string' || !Number.isFinite(Date.parse(user.email_confirmed_at))) throw forbidden();
    return user;
  }

  async function revokeQuietly(accessToken) {
    try { await request('/logout', { bearer: accessToken }); } catch { /* negação principal prevalece */ }
  }

  async function requireReadyAdmin(accessToken) {
    try {
      const principal = await authorizeAdmin(`Bearer ${accessToken}`);
      return principal.userId;
    } catch (error) {
      if (error?.status === 401) throw unauthenticated();
      if (error?.status === 403) throw forbidden();
      throw unavailable();
    }
  }

  function allTotpFactors(user) {
    const values = user?.factors === undefined ? [] : user.factors;
    if (!Array.isArray(values)) throw unavailable();
    return values.map((factor) => {
      const type = factor?.factor_type ?? factor?.type;
      if (!UUID.test(factor?.id ?? '') || type !== 'totp' || !['verified', 'unverified'].includes(factor?.status)) throw unavailable();
      const friendlyName = typeof factor.friendly_name === 'string'
        && factor.friendly_name.length <= 64
        && !/[\u0000-\u001f\u007f]/.test(factor.friendly_name)
        ? factor.friendly_name
        : null;
      return { factorId: factor.id, friendlyName, status: factor.status };
    });
  }

  return {
    async resolveRateLimitSubject({ accessToken, factorId }) {
      const user = await ensureAdmin(accessToken);
      if (!UUID.test(user?.id ?? '')) throw unavailable();
      if (factorId !== undefined && !allTotpFactors(user).some((factor) => factor.factorId === factorId)) throw forbidden();
      return user.id;
    },

    async login({ email, password }) {
      const session = normalizeSession(await request('/token?grant_type=password', {
        body: { email, password }, login: true
      }), 'mfa', maxAccessTokenLifetime);
      try { await ensureAdmin(session.accessToken); } catch (error) {
        await revokeQuietly(session.accessToken);
        if (error?.status === 403) throw unauthenticated();
        throw error;
      }
      return session;
    },

    async listFactors({ accessToken }) {
      const user = await ensureAdmin(accessToken);
      const factors = allTotpFactors(user);
      return { factors: factors.filter((factor) => factor.status === 'verified').map(({ status, ...factor }) => factor) };
    },

    async enroll({ accessToken, friendlyName }) {
      const user = await ensureAdmin(accessToken);
      const factors = allTotpFactors(user);
      const verified = factors.filter((factor) => factor.status === 'verified');
      if (verified.length >= maxTotpFactors) throw factorLimit();
      if (verified.length > 0) await requireReadyAdmin(accessToken);
      for (const factor of factors.filter((value) => value.status === 'unverified')) {
        await request(`/factors/${factor.factorId}`, { bearer: accessToken, method: 'DELETE' });
      }
      const factor = await request('/factors', {
        bearer: accessToken,
        body: { factor_type: 'totp', friendly_name: friendlyName }
      });
      if (!UUID.test(factor?.id ?? '')) throw invalidFactor('AUTH_FACTOR_ID_INVALID');
      if (typeof factor?.totp?.uri !== 'string' || factor.totp.uri.length > 4_096 || !factor.totp.uri.startsWith('otpauth://totp/')) {
        throw invalidFactor('AUTH_FACTOR_URI_INVALID');
      }
      return { factorId: factor.id, uri: factor.totp.uri };
    },

    async challenge({ accessToken, factorId }) {
      await ensureAdmin(accessToken);
      const result = await request(`/factors/${factorId}/challenge`, { bearer: accessToken, body: {} });
      if (!UUID.test(result?.id ?? '')) throw unavailable();
      return { challengeId: result.id };
    },

    async verify({ accessToken, factorId, challengeId, code }) {
      const session = normalizeSession(await request(`/factors/${factorId}/verify`, {
        bearer: accessToken,
        body: { challenge_id: challengeId, code }
      }), 'ready', maxAccessTokenLifetime);
      const subject = await requireReadyAdmin(session.accessToken);
      return { ...session, subject };
    },

    async refresh({ refreshToken }) {
      const session = normalizeSession(await request('/token?grant_type=refresh_token', {
        body: { refresh_token: refreshToken }, login: true
      }), 'ready', maxAccessTokenLifetime);
      const subject = await requireReadyAdmin(session.accessToken);
      return { ...session, subject };
    },

    async logout({ accessToken }) {
      await request('/logout', { bearer: accessToken });
    }
  };
}
