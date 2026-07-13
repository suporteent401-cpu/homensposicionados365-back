import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { SessionError } from './admin-session-service.mjs';

const BASE_PATH = '/v1/admin/session';
const REFRESH_COOKIE = '__Host-hp365-refresh';
const CSRF_COOKIE = '__Host-hp365-csrf';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER = /^Bearer ([^\s]{1,8192})$/;
const CSRF = /^[A-Za-z0-9_-]{20,128}$/;
const COOKIE_VALUE = /^[A-Za-z0-9._~-]{1,4096}$/;
const MAX_BODY_BYTES = 8_192;
const ROUTES = new Set(['/login', '/mfa/factors', '/mfa/enroll', '/mfa/challenge', '/mfa/verify', '/refresh', '/logout']);

function normalizeOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Origin inválida'); }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (url.origin !== value || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) throw new TypeError('Origin inválida');
  return value;
}

function httpError(status, code, message) {
  return new SessionError(status, code, message);
}

function rateLimitError(retryAfter) {
  const error = httpError(429, 'RATE_LIMITED', 'Muitas tentativas');
  error.retryAfter = retryAfter;
  return error;
}

async function readLimitedText(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    throw httpError(413, 'PAYLOAD_TOO_LARGE', 'Solicitação muito grande');
  }
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw httpError(413, 'PAYLOAD_TOO_LARGE', 'Solicitação muito grande');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

async function readJson(request, fields) {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
  const text = await readLimitedText(request);
  let value;
  try { value = JSON.parse(text); } catch { throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
  if (Object.keys(value).some((key) => !fields.includes(key))) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
  return value;
}

async function requireEmptyBody(request) {
  const text = await readLimitedText(request);
  if (text.length > 0) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
}

function requireString(value, { min = 1, max, pattern } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max || (pattern && !pattern.test(value))) {
    throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
  }
  return value;
}

function accessToken(request) {
  const match = BEARER.exec(request.headers.get('authorization') ?? '');
  if (!match) throw httpError(401, 'UNAUTHENTICATED', 'Autenticação necessária');
  return match[1];
}

function parseCookies(request) {
  const values = new Map();
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
    const name = trimmed.slice(0, separator);
    if (values.has(name)) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
    values.set(name, trimmed.slice(separator + 1));
  }
  return values;
}

function requireCsrf(request) {
  const cookies = parseCookies(request);
  const cookie = cookies.get(CSRF_COOKIE);
  const header = request.headers.get('x-csrf-token');
  if (!CSRF.test(cookie ?? '') || !CSRF.test(header ?? '')) throw httpError(400, 'CSRF_INVALID', 'Solicitação inválida');
  const left = Buffer.from(cookie);
  const right = Buffer.from(header);
  if (left.length !== right.length || !timingSafeEqual(left, right)) throw httpError(400, 'CSRF_INVALID', 'Solicitação inválida');
  return cookies;
}

function securityHeaders(origin, requestUrl) {
  const headers = new Headers({
    'access-control-allow-credentials': 'true',
    'access-control-allow-origin': origin,
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'referrer-policy': 'no-referrer',
    vary: 'Origin',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY'
  });
  if (new URL(requestUrl).protocol === 'https:') headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  return headers;
}

function appendSessionCookies(headers, refreshToken, csrfToken, maxAge) {
  if (typeof refreshToken !== 'string' || refreshToken.length < 1 || refreshToken.length > 4096) {
    throw httpError(503, 'SESSION_COOKIE_INVALID_LENGTH', 'Serviço de autenticação indisponível');
  }
  if (!COOKIE_VALUE.test(refreshToken)) throw httpError(503, 'SESSION_COOKIE_INVALID', 'Serviço de autenticação indisponível');
  headers.append('set-cookie', `${REFRESH_COOKIE}=${refreshToken}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`);
  headers.append('set-cookie', `${CSRF_COOKIE}=${csrfToken}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`);
}

function appendClearedCookies(headers) {
  headers.append('set-cookie', `${REFRESH_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
  headers.append('set-cookie', `${CSRF_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
}

function sessionBody(session, csrfToken) {
  if (typeof session?.accessToken !== 'string' || !Number.isInteger(session?.expiresIn) || !['mfa', 'ready'].includes(session?.next)) {
    throw httpError(503, 'AUTH_UNAVAILABLE', 'Serviço de autenticação indisponível');
  }
  if (!CSRF.test(csrfToken ?? '')) throw httpError(503, 'SESSION_COOKIE_INVALID', 'Serviço de autenticação indisponível');
  return { accessToken: session.accessToken, expiresIn: session.expiresIn, next: session.next, csrfToken };
}

function safeError(error) {
  const known = new Map([
    ['VALIDATION_ERROR', [400, 'Solicitação inválida']],
    ['CSRF_INVALID', [400, 'Solicitação inválida']],
    ['AUTH_FLOW_ERROR', [400, 'Operação de autenticação inválida']],
    ['PAYLOAD_TOO_LARGE', [413, 'Solicitação muito grande']],
    ['UNAUTHENTICATED', [401, 'Autenticação necessária']],
    ['FORBIDDEN', [403, 'Acesso negado']],
    ['RATE_LIMITED', [429, 'Muitas tentativas']],
    ['MFA_FACTOR_LIMIT', [409, 'Limite de fatores atingido']],
    ['AUTH_UNAVAILABLE', [503, 'Serviço de autenticação indisponível']],
    ['AUTH_FACTOR_ID_INVALID', [503, 'Serviço de autenticação indisponível']],
    ['AUTH_FACTOR_URI_INVALID', [503, 'Serviço de autenticação indisponível']],
    ['SESSION_COOKIE_INVALID', [503, 'Serviço de autenticação indisponível']],
    ['SESSION_COOKIE_INVALID_LENGTH', [503, 'Serviço de autenticação indisponível']],
    ['RATE_LIMIT_UNAVAILABLE', [503, 'Serviço indisponível']]
  ]);
  const value = error instanceof SessionError ? known.get(error.code) : undefined;
  return value ? { status: value[0], code: error.code, message: value[1] } : { status: 500, code: 'INTERNAL_ERROR', message: 'Erro interno' };
}

export function createAdminSessionHandler({
  sessionService,
  allowedOrigins,
  rateLimiter,
  getClientKey,
  logger,
  randomToken = () => randomBytes(32).toString('base64url'),
  createRequestId = randomUUID,
  refreshCookieMaxAge = 28_800
}) {
  if (!sessionService || !(allowedOrigins instanceof Set) || allowedOrigins.size === 0
    || typeof sessionService.resolveRateLimitSubject !== 'function'
    || typeof rateLimiter?.consume !== 'function' || typeof getClientKey !== 'function'
    || typeof logger?.info !== 'function' || typeof randomToken !== 'function' || typeof createRequestId !== 'function') {
    throw new TypeError('Configuração HTTP inválida');
  }
  if (!Number.isInteger(refreshCookieMaxAge) || refreshCookieMaxAge < 1 || refreshCookieMaxAge > 604_800) {
    throw new TypeError('Configuração HTTP inválida');
  }
  const origins = new Set([...allowedOrigins].map(normalizeOrigin));

  return async function handleAdminSession(request) {
    const requestId = createRequestId();
    const url = new URL(request.url);
    const route = url.pathname.startsWith(BASE_PATH) ? url.pathname.slice(BASE_PATH.length) : '';
    let response;

    const logRoute = ROUTES.has(route) ? route : 'unknown';
    const finish = (result) => {
      try { logger.info({ event: 'admin_session_request', route: logRoute, status: result.status, requestId }); } catch { /* logger não altera rotação/sessão */ }
      return result;
    };

    if (url.search) {
      const headers = new Headers({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
      return finish(new Response(JSON.stringify({ error: { code: 'VALIDATION_ERROR', message: 'Solicitação inválida', requestId } }), { status: 400, headers }));
    }

    if (!ROUTES.has(route)) {
      const headers = new Headers({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
      return finish(new Response(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Rota não encontrada', requestId } }), { status: 404, headers }));
    }

    const origin = request.headers.get('origin');
    if (!origin || !origins.has(origin)) {
      const headers = new Headers({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
      return finish(new Response(JSON.stringify({ error: { code: 'FORBIDDEN', message: 'Acesso negado', requestId } }), { status: 403, headers }));
    }
    const headers = securityHeaders(origin, request.url);

    if (request.method === 'OPTIONS') {
      const requestedMethod = request.headers.get('access-control-request-method');
      const requestedHeaders = (request.headers.get('access-control-request-headers') ?? '')
        .split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
      const allowedHeaders = new Set(['authorization', 'content-type', 'x-csrf-token']);
      if (requestedMethod !== 'POST' || requestedHeaders.some((value) => !allowedHeaders.has(value))) {
        return finish(new Response(null, { status: 403, headers }));
      }
      headers.set('access-control-allow-methods', 'POST, OPTIONS');
      headers.set('access-control-allow-headers', 'Authorization, Content-Type, X-CSRF-Token');
      headers.set('access-control-max-age', '600');
      return finish(new Response(null, { status: 204, headers }));
    }
    if (request.method !== 'POST') return finish(new Response(null, { status: 405, headers }));

    try {
      let clientKey;
      try { clientKey = getClientKey(request); } catch { throw httpError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível'); }
      if (typeof clientKey !== 'string' || !clientKey) throw httpError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível');
      const enforceRateLimit = async (scope, subject) => {
        let decision;
        try { decision = await rateLimiter.consume({ route, clientKey, scope, ...(subject ? { subject } : {}) }); }
        catch { throw httpError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível'); }
        if (!decision || typeof decision.allowed !== 'boolean' || !Number.isInteger(decision.retryAfter)
          || decision.retryAfter < 1 || decision.retryAfter > 3_600) {
          throw httpError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível');
        }
        if (!decision.allowed) throw rateLimitError(decision.retryAfter);
      };
      await enforceRateLimit('ip');

      let result;
      if (route === '/login') {
        const value = await readJson(request, ['email', 'password']);
        const email = requireString(value.email, { max: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ });
        const password = requireString(value.password, { max: 1024 });
        await enforceRateLimit('subject', email.toLowerCase());
        const session = await sessionService.login({ email, password });
        const csrfToken = randomToken();
        const body = sessionBody(session, csrfToken);
        appendSessionCookies(headers, session.refreshToken, csrfToken, refreshCookieMaxAge);
        result = new Response(JSON.stringify(body), { status: 200, headers });
      } else if (route === '/mfa/factors') {
        await requireEmptyBody(request);
        const token = accessToken(request);
        await enforceRateLimit('subject', await sessionService.resolveRateLimitSubject({ accessToken: token }));
        const factors = await sessionService.listFactors({ accessToken: token });
        result = new Response(JSON.stringify(factors), { status: 200, headers });
      } else if (route === '/mfa/enroll') {
        const value = await readJson(request, ['friendlyName']);
        const rawFriendlyName = value.friendlyName === undefined
          ? 'HP365 Authenticator'
          : requireString(value.friendlyName, { max: 64 });
        const friendlyName = rawFriendlyName.trim();
        if (!friendlyName || /[\u0000-\u001f\u007f]/.test(friendlyName)) throw httpError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
        const token = accessToken(request);
        await enforceRateLimit('subject', await sessionService.resolveRateLimitSubject({ accessToken: token }));
        const enrolled = await sessionService.enroll({ accessToken: token, friendlyName });
        result = new Response(JSON.stringify(enrolled), { status: 200, headers });
      } else if (route === '/mfa/challenge') {
        const value = await readJson(request, ['factorId']);
        const factorId = requireString(value.factorId, { max: 36, pattern: UUID });
        const token = accessToken(request);
        await enforceRateLimit('subject', await sessionService.resolveRateLimitSubject({ accessToken: token, factorId }));
        const challenged = await sessionService.challenge({ accessToken: token, factorId });
        result = new Response(JSON.stringify(challenged), { status: 200, headers });
      } else if (route === '/mfa/verify') {
        const value = await readJson(request, ['factorId', 'challengeId', 'code']);
        const factorId = requireString(value.factorId, { max: 36, pattern: UUID });
        const challengeId = requireString(value.challengeId, { max: 36, pattern: UUID });
        const code = requireString(value.code, { min: 6, max: 6, pattern: /^\d{6}$/ });
        const token = accessToken(request);
        await enforceRateLimit('subject', await sessionService.resolveRateLimitSubject({ accessToken: token, factorId }));
        const session = await sessionService.verify({ accessToken: token, factorId, challengeId, code });
        const csrfToken = randomToken();
        const body = sessionBody(session, csrfToken);
        appendSessionCookies(headers, session.refreshToken, csrfToken, refreshCookieMaxAge);
        result = new Response(JSON.stringify(body), { status: 200, headers });
      } else if (route === '/refresh') {
        await requireEmptyBody(request);
        const cookies = requireCsrf(request);
        const refreshToken = requireString(cookies.get(REFRESH_COOKIE), { max: 4096 });
        const session = await sessionService.refresh({ refreshToken });
        try {
          await enforceRateLimit('subject', session.subject);
        } catch (error) {
          try { await sessionService.logout({ accessToken: session.accessToken }); } catch { /* sessão nova permanece negada */ }
          appendClearedCookies(headers);
          throw error;
        }
        const csrfToken = randomToken();
        const body = sessionBody(session, csrfToken);
        appendSessionCookies(headers, session.refreshToken, csrfToken, refreshCookieMaxAge);
        result = new Response(JSON.stringify(body), { status: 200, headers });
      } else {
        await requireEmptyBody(request);
        requireCsrf(request);
        const token = accessToken(request);
        await enforceRateLimit('subject', await sessionService.resolveRateLimitSubject({ accessToken: token }));
        try {
          await sessionService.logout({ accessToken: token });
          appendClearedCookies(headers);
          result = new Response(null, { status: 204, headers });
        } catch (error) {
          appendClearedCookies(headers);
          throw error;
        }
      }
      if (result.body !== null) result.headers.set('content-type', 'application/json; charset=utf-8');
      response = result;
    } catch (error) {
      const { status, code, message } = safeError(error);
      if (route === '/refresh' && (status === 401 || status === 403)) appendClearedCookies(headers);
      if (code === 'RATE_LIMITED' && Number.isInteger(error?.retryAfter)) headers.set('retry-after', String(error.retryAfter));
      headers.set('content-type', 'application/json; charset=utf-8');
      response = new Response(JSON.stringify({ error: { code, message, requestId } }), { status, headers });
    }
    return finish(response);
  };
}
