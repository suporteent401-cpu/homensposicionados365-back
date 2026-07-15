import { createSupabaseAdminAuthorizer } from './admin-authz.mjs';
import { createAdminContentHandler } from './admin-content-http.mjs';
import { createAdminContentService } from './admin-content.mjs';
import { createSupabaseAdminContentRepository } from './supabase-admin-content-repository.mjs';
import { createUpstashAdminRateLimiter } from './admin-rate-limiter.mjs';
import { createVercelClientKey } from './vercel-client-key.mjs';

const PREVIEW_REF = 'ymbzsidruqqkdihrxdjg';
const PRODUCTION_REF = 'ckebvvcxibpnvjwqsjtm';
const PREVIEW_BRANCH = 'preview/002-auth';

function exactHttpsOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Ambiente Preview inválido'); }
  if (url.origin !== value || url.protocol !== 'https:' || url.username || url.password) throw new TypeError('Ambiente Preview inválido');
  return url;
}

function assertPreviewEnv(env) {
  if (!env || env.VERCEL !== '1' || env.VERCEL_ENV !== 'preview' || env.HP365_ENV !== 'preview'
    || env.HP365_PREVIEW_ORIGIN_MODE !== 'same-origin-vercel' || env.HP365_PREVIEW_BRANCH !== PREVIEW_BRANCH
    || env.VERCEL_GIT_COMMIT_REF !== PREVIEW_BRANCH || env.VERCEL_GIT_PROVIDER !== 'github'
    || env.VERCEL_GIT_REPO_OWNER !== 'suporteent401-cpu' || env.VERCEL_GIT_REPO_SLUG !== 'homensposicionados365-back') {
    throw new TypeError('Ambiente Preview inválido');
  }
  const publicUrl = exactHttpsOrigin(env.PUBLIC_API_ORIGIN);
  const allowedUrl = exactHttpsOrigin(env.ADMIN_ALLOWED_ORIGIN);
  const supabaseUrl = exactHttpsOrigin(env.SUPABASE_URL);
  const authUrl = new URL(env.SUPABASE_AUTH_URL);
  if (publicUrl.origin !== allowedUrl.origin || publicUrl.hostname !== env.VERCEL_BRANCH_URL
    || env.ADMIN_COOKIE_SITE_DOMAIN !== publicUrl.hostname || env.VERCEL_PROJECT_PRODUCTION_URL === publicUrl.hostname
    || supabaseUrl.hostname !== `${PREVIEW_REF}.supabase.co`
    || supabaseUrl.hostname === `${PRODUCTION_REF}.supabase.co`
    || authUrl.href !== `${supabaseUrl.origin}/auth/v1`
    || typeof env.SUPABASE_SECRET_KEY !== 'string' || !env.SUPABASE_SECRET_KEY.startsWith('sb_secret_')
    || !/^hp365:preview:[a-z0-9_-]{8,32}$/.test(env.RATE_LIMIT_NAMESPACE ?? '')) {
    throw new TypeError('Ambiente Preview inválido');
  }
  return { publicOrigin: publicUrl.origin, allowedOrigin: allowedUrl.origin, supabaseUrl: supabaseUrl.origin };
}

export function createVercelAdminContentApp({ env, fetchImpl = globalThis.fetch, rateLimiter, logger } = {}) {
  const { publicOrigin, allowedOrigin, supabaseUrl } = assertPreviewEnv(env);
  const resolvedRateLimiter = rateLimiter ?? createUpstashAdminRateLimiter({
    url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN,
    namespace: env.RATE_LIMIT_NAMESPACE, hmacKey: env.RATE_LIMIT_HMAC_KEY
  });
  const resolvedLogger = logger ?? { info: (event) => console.info(JSON.stringify(event)) };
  const authorizeAdmin = createSupabaseAdminAuthorizer({
    authUrl: env.SUPABASE_AUTH_URL, anonKey: env.SUPABASE_ANON_KEY,
    expectedIssuer: env.SUPABASE_AUTH_URL, fetchImpl
  });
  const repository = createSupabaseAdminContentRepository({
    supabaseUrl, serverKey: env.SUPABASE_SECRET_KEY, fetchImpl
  });
  const handler = createAdminContentHandler({
    allowedOrigins: new Set([allowedOrigin]), authorizeAdmin,
    contentService: createAdminContentService({ repository }), rateLimiter: resolvedRateLimiter,
    getClientKey: createVercelClientKey({ hmacKey: env.RATE_LIMIT_HMAC_KEY }), logger: resolvedLogger
  });
  return {
    async fetch(request) {
      if (new URL(request.url).origin !== publicOrigin) return new Response(null, { status: 403, headers: { 'cache-control': 'no-store' } });
      return handler(request);
    }
  };
}
