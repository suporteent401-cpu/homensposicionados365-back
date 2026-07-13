import { normalizeSupabaseAuthUrl } from './auth-endpoint.mjs';

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

export class AuthorizationError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AuthorizationError';
    this.status = status;
    this.code = code;
  }
}

const unauthenticated = () => new AuthorizationError(401, 'UNAUTHENTICATED', 'Autenticação necessária');
const forbidden = () => new AuthorizationError(403, 'FORBIDDEN', 'Acesso negado');
const unavailable = () => new AuthorizationError(503, 'AUTH_UNAVAILABLE', 'Serviço de autenticação indisponível');

function decodePayload(accessToken) {
  try {
    const [, encoded] = accessToken.split('.');
    const claims = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new TypeError();
    return claims;
  } catch {
    throw unauthenticated();
  }
}

function hasAudience(audience, expectedAudience) {
  return audience === expectedAudience || (Array.isArray(audience) && audience.includes(expectedAudience));
}

function hasTotp(claims) {
  return Array.isArray(claims.amr) && claims.amr.some((entry) => entry?.method === 'totp');
}

/**
 * Cria uma policy reutilizável para rotas administrativas.
 * O payload só é usado depois que o Supabase Auth aceita o mesmo bearer em /user.
 */
export function createSupabaseAdminAuthorizer({
  authUrl,
  anonKey,
  expectedIssuer,
  expectedAudience = 'authenticated',
  fetchImpl = globalThis.fetch,
  now = () => Math.floor(Date.now() / 1000)
}) {
  if (typeof authUrl !== 'string' || typeof anonKey !== 'string' || !anonKey || typeof expectedIssuer !== 'string') {
    throw new TypeError('Configuração de autenticação inválida');
  }
  if (typeof fetchImpl !== 'function' || typeof now !== 'function') throw new TypeError('Configuração de autenticação inválida');

  const normalizedAuthUrl = normalizeSupabaseAuthUrl(authUrl, expectedIssuer);
  const userEndpoint = `${normalizedAuthUrl}/user`;

  return async function authorizeAdmin(authorization) {
    if (typeof authorization !== 'string') throw unauthenticated();
    const match = BEARER.exec(authorization);
    if (!match) throw unauthenticated();

    const accessToken = match[1];
    const claims = decodePayload(accessToken);

    let response;
    try {
      response = await fetchImpl(userEndpoint, {
        method: 'GET',
        headers: { apikey: anonKey, authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(5_000)
      });
    } catch {
      throw unavailable();
    }

    if (!response || typeof response.ok !== 'boolean') throw unavailable();
    if (!response.ok) {
      if (response.status >= 500) throw unavailable();
      throw unauthenticated();
    }

    let authUser;
    try {
      authUser = await response.json();
    } catch {
      throw unavailable();
    }

    const validIdentity = typeof claims.sub === 'string' && claims.sub.length > 0 && claims.sub === authUser?.id;
    const validClaims = claims.iss === expectedIssuer
      && hasAudience(claims.aud, expectedAudience)
      && Number.isInteger(claims.exp)
      && claims.exp > now();
    if (!validIdentity || !validClaims) throw unauthenticated();

    if (authUser?.app_metadata?.role !== 'admin') throw forbidden();
    if (typeof authUser?.email_confirmed_at !== 'string' || !Number.isFinite(Date.parse(authUser.email_confirmed_at))) throw forbidden();
    if (claims.aal !== 'aal2' || !hasTotp(claims)) throw forbidden();

    return { userId: authUser.id, role: 'admin', aal: 'aal2' };
  };
}
