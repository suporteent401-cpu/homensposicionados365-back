import { randomUUID } from 'node:crypto';
import { ContentError } from './admin-content.mjs';
import { validateIdempotencyKey } from './request-validation.mjs';

const PATH = '/v1/admin/devotionals';
const MAX_BODY_BYTES = 8_192;
const BEARER = /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function normalizeOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Origem inválida'); }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (url.origin !== value || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) throw new TypeError('Origem inválida');
  return value;
}

function securityHeaders(origin, requestUrl) {
  const headers = new Headers({
    'access-control-allow-origin': origin, 'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'referrer-policy': 'no-referrer', vary: 'Origin', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY'
  });
  if (new URL(requestUrl).protocol === 'https:') headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  return headers;
}

async function readJson(request) {
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    throw new ContentError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
  }
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    throw new ContentError(413, 'PAYLOAD_TOO_LARGE', 'Solicitação muito grande');
  }
  const text = await request.text();
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) throw new ContentError(413, 'PAYLOAD_TOO_LARGE', 'Solicitação muito grande');
  try { return JSON.parse(text); } catch { throw new ContentError(400, 'VALIDATION_ERROR', 'Solicitação inválida'); }
}

function safeError(error) {
  const known = new Map([
    ['VALIDATION_ERROR', [400, 'Solicitação inválida']], ['PAYLOAD_TOO_LARGE', [413, 'Solicitação muito grande']],
    ['UNAUTHENTICATED', [401, 'Autenticação necessária']], ['FORBIDDEN', [403, 'Acesso negado']],
    ['IDEMPOTENCY_CONFLICT', [409, 'Conflito de idempotência']], ['CONTENT_CONFLICT', [409, 'Conteúdo já existente']],
    ['RATE_LIMITED', [429, 'Muitas tentativas']], ['AUTH_UNAVAILABLE', [503, 'Serviço de autenticação indisponível']],
    ['DATA_UNAVAILABLE', [503, 'Serviço de dados indisponível']], ['RATE_LIMIT_UNAVAILABLE', [503, 'Serviço indisponível']]
  ]);
  const value = error && typeof error.code === 'string' ? known.get(error.code) : undefined;
  return value ? { status: value[0], code: error.code, message: value[1] } : { status: 500, code: 'INTERNAL_ERROR', message: 'Erro interno' };
}

export function createAdminContentHandler({ allowedOrigins, authorizeAdmin, contentService, rateLimiter, getClientKey, logger, createRequestId = randomUUID } = {}) {
  if (!(allowedOrigins instanceof Set) || allowedOrigins.size === 0 || typeof authorizeAdmin !== 'function'
    || typeof contentService?.createDraft !== 'function' || typeof rateLimiter?.consume !== 'function'
    || typeof getClientKey !== 'function' || typeof logger?.info !== 'function' || typeof createRequestId !== 'function') {
    throw new TypeError('Configuração HTTP inválida');
  }
  const origins = new Set([...allowedOrigins].map(normalizeOrigin));
  return async function handleAdminContent(request) {
    const requestId = createRequestId();
    const url = new URL(request.url);
    const route = url.pathname === PATH ? 'create_draft' : 'unknown';
    const finish = (response) => {
      try { logger.info({ event: 'admin_content_request', route, status: response.status, requestId }); } catch { /* observabilidade não altera resposta */ }
      return response;
    };
    const plainHeaders = () => new Headers({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
    const errorResponse = (status, code, message, headers = plainHeaders()) => finish(new Response(JSON.stringify({ error: { code, message, requestId } }), { status, headers }));
    if (url.pathname !== PATH) return errorResponse(404, 'NOT_FOUND', 'Rota não encontrada');
    if (url.search) return errorResponse(400, 'VALIDATION_ERROR', 'Solicitação inválida');
    const origin = request.headers.get('origin');
    if (!origin || !origins.has(origin)) return errorResponse(403, 'FORBIDDEN', 'Acesso negado');
    const headers = securityHeaders(origin, request.url);
    if (request.method === 'OPTIONS') {
      const requestedHeaders = (request.headers.get('access-control-request-headers') ?? '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
      if (request.headers.get('access-control-request-method') !== 'POST'
        || requestedHeaders.some((value) => !['authorization', 'content-type', 'idempotency-key'].includes(value))) return finish(new Response(null, { status: 403, headers }));
      headers.set('access-control-allow-methods', 'POST, OPTIONS');
      headers.set('access-control-allow-headers', 'Authorization, Content-Type, Idempotency-Key');
      headers.set('access-control-max-age', '600');
      return finish(new Response(null, { status: 204, headers }));
    }
    if (request.method !== 'POST') return finish(new Response(null, { status: 405, headers }));
    try {
      let clientKey;
      try { clientKey = getClientKey(request); } catch { throw new ContentError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível'); }
      if (typeof clientKey !== 'string' || !clientKey) throw new ContentError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível');
      const consume = async (scope, subject) => {
        let decision;
        try { decision = await rateLimiter.consume({ route: '/devotionals/create', scope, clientKey, ...(subject ? { subject } : {}) }); }
        catch { throw new ContentError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível'); }
        if (!decision || typeof decision.allowed !== 'boolean' || !Number.isInteger(decision.retryAfter) || decision.retryAfter < 1 || decision.retryAfter > 3_600) {
          throw new ContentError(503, 'RATE_LIMIT_UNAVAILABLE', 'Serviço indisponível');
        }
        if (!decision.allowed) {
          const error = new ContentError(429, 'RATE_LIMITED', 'Muitas tentativas');
          error.retryAfter = decision.retryAfter;
          throw error;
        }
      };
      await consume('ip');
      const authorization = request.headers.get('authorization') ?? '';
      if (!BEARER.test(authorization)) throw new ContentError(401, 'UNAUTHENTICATED', 'Autenticação necessária');
      const principal = await authorizeAdmin(authorization);
      await consume('subject', principal.userId);
      let idempotencyKey;
      try { idempotencyKey = validateIdempotencyKey(request.headers.get('idempotency-key')); } catch { throw new ContentError(400, 'VALIDATION_ERROR', 'Solicitação inválida'); }
      const input = await readJson(request);
      const result = await contentService.createDraft({ principal, input, idempotencyKey, requestId });
      headers.set('content-type', 'application/json; charset=utf-8');
      headers.set('idempotency-replayed', String(result.kind === 'replayed'));
      return finish(new Response(JSON.stringify(result.body), { status: result.status, headers }));
    } catch (error) {
      const safe = safeError(error);
      if (safe.code === 'RATE_LIMITED' && Number.isInteger(error?.retryAfter)) headers.set('retry-after', String(error.retryAfter));
      headers.set('content-type', 'application/json; charset=utf-8');
      return finish(new Response(JSON.stringify({ error: { code: safe.code, message: safe.message, requestId } }), { status: safe.status, headers }));
    }
  };
}
