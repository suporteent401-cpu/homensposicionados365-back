import { createAdminSessionHandler } from './admin-session-http.mjs';
import { createSupabaseAdminSessionService } from './admin-session-service.mjs';
import { createUpstashAdminRateLimiter } from './admin-rate-limiter.mjs';
import { createVercelClientKey } from './vercel-client-key.mjs';

function exactOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Origem de runtime inválida'); }
  if (url.origin !== value || url.protocol !== 'https:') throw new TypeError('Origem de runtime inválida');
  return value;
}

function assertCookieSite(value, origins) {
  if (typeof value !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value)) {
    throw new TypeError('Domínio de cookie inválido');
  }
  if (!origins.every((origin) => {
    const hostname = new URL(origin).hostname;
    return hostname === value || hostname.endsWith(`.${value}`);
  })) throw new TypeError('Topologia cross-site inválida');
}

export function createVercelAdminSessionApp({ env, fetchImpl = globalThis.fetch, rateLimiter, logger } = {}) {
  if (!env || env.VERCEL !== '1' || env.VERCEL_ENV !== 'preview' || env.HP365_ENV !== 'preview') {
    throw new TypeError('Runtime Vercel inválido');
  }
  const allowedOrigin = exactOrigin(env.ADMIN_ALLOWED_ORIGIN);
  const publicOrigin = exactOrigin(env.PUBLIC_API_ORIGIN);
  assertCookieSite(env.ADMIN_COOKIE_SITE_DOMAIN, [allowedOrigin, publicOrigin]);
  if ([allowedOrigin, publicOrigin].some((origin) => new URL(origin).hostname.endsWith('.vercel.app'))
    || new URL(env.SUPABASE_AUTH_URL).hostname === 'ckebvvcxibpnvjwqsjtm.supabase.co'
    || !/^hp365:preview:[a-z0-9_-]{8,32}$/.test(env.RATE_LIMIT_NAMESPACE ?? '')) {
    throw new TypeError('Ambiente preview inválido');
  }
  const getClientKey = createVercelClientKey({ hmacKey: env.RATE_LIMIT_HMAC_KEY });
  const resolvedRateLimiter = rateLimiter ?? createUpstashAdminRateLimiter({
    url: env.UPSTASH_REDIS_REST_URL,
    token: env.UPSTASH_REDIS_REST_TOKEN,
    namespace: env.RATE_LIMIT_NAMESPACE,
    hmacKey: env.RATE_LIMIT_HMAC_KEY
  });
  const resolvedLogger = logger ?? { info: (event) => console.info(JSON.stringify(event)) };
  const service = createSupabaseAdminSessionService({
    authUrl: env.SUPABASE_AUTH_URL,
    anonKey: env.SUPABASE_ANON_KEY,
    fetchImpl,
    maxAccessTokenLifetime: 900
  });
  const handler = createAdminSessionHandler({
    sessionService: service,
    allowedOrigins: new Set([allowedOrigin]),
    rateLimiter: resolvedRateLimiter,
    getClientKey,
    logger: resolvedLogger,
    refreshCookieMaxAge: 28_800
  });
  return {
    async fetch(request) {
      if (new URL(request.url).origin !== publicOrigin) return new Response(null, { status: 403, headers: { 'cache-control': 'no-store' } });
      return handler(request);
    }
  };
}
