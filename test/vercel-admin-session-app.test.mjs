import test from 'node:test';
import assert from 'node:assert/strict';
import { createVercelAdminSessionApp } from '../src/vercel-admin-session-app.mjs';

const hmacKey = Buffer.alloc(32, 3).toString('base64url');
const baseEnv = {
  VERCEL: '1', VERCEL_ENV: 'preview', HP365_ENV: 'preview',
  SUPABASE_AUTH_URL: 'https://auth.example.test/auth/v1', SUPABASE_ANON_KEY: 'public-key',
  ADMIN_ALLOWED_ORIGIN: 'https://admin.example.test', PUBLIC_API_ORIGIN: 'https://api.example.test',
  ADMIN_COOKIE_SITE_DOMAIN: 'example.test',
  RATE_LIMIT_HMAC_KEY: hmacKey, RATE_LIMIT_NAMESPACE: 'hp365:preview:harness001',
  UPSTASH_REDIS_REST_URL: 'https://redis.example.test', UPSTASH_REDIS_REST_TOKEN: 'x'.repeat(16)
};

const branchHostname = 'hp365-back-git-preview-002-auth-team.vercel.app';
const vercelSameOriginEnv = {
  ...baseEnv,
  HP365_PREVIEW_ORIGIN_MODE: 'same-origin-vercel',
  HP365_PREVIEW_BRANCH: 'preview/002-auth',
  ADMIN_ALLOWED_ORIGIN: `https://${branchHostname}`,
  PUBLIC_API_ORIGIN: `https://${branchHostname}`,
  ADMIN_COOKIE_SITE_DOMAIN: branchHostname,
  VERCEL_BRANCH_URL: branchHostname,
  VERCEL_PROJECT_PRODUCTION_URL: 'homensposicionados365-back.vercel.app',
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'suporteent401-cpu',
  VERCEL_GIT_REPO_SLUG: 'homensposicionados365-back',
  VERCEL_GIT_COMMIT_REF: 'preview/002-auth'
};

test('falha no startup sem runtime e configuração server-side completos', () => {
  assert.throws(() => createVercelAdminSessionApp({ env: {} }));
});

test('compõe fetch Vercel sem confiar em headers de IP do cliente', async () => {
  const calls = [];
  const app = createVercelAdminSessionApp({
    env: baseEnv,
    rateLimiter: { consume: async (value) => { calls.push(value); return { allowed: false, retryAfter: 60 }; } },
    logger: { info: () => undefined }
  });
  const response = await app.fetch(new Request('https://api.example.test/v1/admin/session/login', {
    method: 'POST', headers: {
      origin: 'https://admin.example.test', 'content-type': 'application/json',
      'x-vercel-forwarded-for': '203.0.113.7', 'x-forwarded-for': '198.51.100.2'
    }, body: JSON.stringify({ email: 'admin@example.test', password: 'private' })
  }));
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '60');
  assert.equal(calls[0].scope, 'ip');
  assert.doesNotMatch(calls[0].clientKey, /203\.0\.113\.7|198\.51\.100\.2/);
});

test('valida runtime, origens HTTPS e domínio same-site explícito', () => {
  for (const env of [
    undefined,
    { ...baseEnv, VERCEL: '0' },
    { ...baseEnv, VERCEL_ENV: 'development' },
    { ...baseEnv, VERCEL_ENV: 'production' },
    { ...baseEnv, HP365_ENV: 'production' },
    { ...baseEnv, RATE_LIMIT_NAMESPACE: 'hp365:preview' },
    { ...baseEnv, RATE_LIMIT_NAMESPACE: undefined },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'https://api-preview.vercel.app', ADMIN_ALLOWED_ORIGIN: 'https://admin-preview.vercel.app', ADMIN_COOKIE_SITE_DOMAIN: 'vercel.app' },
    { ...baseEnv, SUPABASE_AUTH_URL: 'https://ckebvvcxibpnvjwqsjtm.supabase.co/auth/v1' },
    { ...baseEnv, ADMIN_ALLOWED_ORIGIN: 'not-a-url' },
    { ...baseEnv, ADMIN_ALLOWED_ORIGIN: 'http://admin.example.test' },
    { ...baseEnv, ADMIN_ALLOWED_ORIGIN: 'https://admin.example.test/path' },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'not-a-url' },
    { ...baseEnv, ADMIN_COOKIE_SITE_DOMAIN: undefined },
    { ...baseEnv, ADMIN_COOKIE_SITE_DOMAIN: 'Example.Test' },
    { ...baseEnv, ADMIN_COOKIE_SITE_DOMAIN: 'other.test' },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'https://api.other.test' }
  ]) assert.throws(() => createVercelAdminSessionApp({ env }));
  assert.doesNotThrow(() => createVercelAdminSessionApp({
    env: { ...baseEnv, PUBLIC_API_ORIGIN: 'https://example.test' },
    rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 1 }) },
    logger: { info: () => undefined }
  }));
});

test('aceita vercel.app somente em preview de branch e origem única fixada', async () => {
  const create = (env) => createVercelAdminSessionApp({
    env,
    rateLimiter: { consume: async () => ({ allowed: false, retryAfter: 1 }) },
    logger: { info: () => undefined }
  });
  assert.doesNotThrow(() => create(vercelSameOriginEnv));

  for (const env of [
    { ...vercelSameOriginEnv, VERCEL_ENV: 'production' },
    { ...vercelSameOriginEnv, HP365_PREVIEW_ORIGIN_MODE: undefined },
    { ...vercelSameOriginEnv, HP365_PREVIEW_BRANCH: 'main', VERCEL_GIT_COMMIT_REF: 'main' },
    { ...vercelSameOriginEnv, VERCEL_GIT_COMMIT_REF: 'preview/other' },
    { ...vercelSameOriginEnv, ADMIN_ALLOWED_ORIGIN: `https://${branchHostname}:8443`, PUBLIC_API_ORIGIN: `https://${branchHostname}:8443` },
    { ...vercelSameOriginEnv, VERCEL_BRANCH_URL: 'other-preview.vercel.app' },
    { ...vercelSameOriginEnv, VERCEL_PROJECT_PRODUCTION_URL: undefined },
    { ...vercelSameOriginEnv, VERCEL_PROJECT_PRODUCTION_URL: 'invalid' },
    { ...vercelSameOriginEnv, VERCEL_PROJECT_PRODUCTION_URL: 'production.example.test' },
    { ...vercelSameOriginEnv, VERCEL_PROJECT_PRODUCTION_URL: branchHostname },
    { ...vercelSameOriginEnv, ADMIN_ALLOWED_ORIGIN: 'https://admin-preview.vercel.app' },
    { ...vercelSameOriginEnv, ADMIN_ALLOWED_ORIGIN: 'https://admin-preview.vercel.app', ADMIN_COOKIE_SITE_DOMAIN: 'vercel.app' },
    { ...vercelSameOriginEnv, ADMIN_COOKIE_SITE_DOMAIN: 'vercel.app' },
    { ...vercelSameOriginEnv, VERCEL_GIT_PROVIDER: 'gitlab' },
    { ...vercelSameOriginEnv, VERCEL_GIT_REPO_OWNER: 'other' },
    { ...vercelSameOriginEnv, VERCEL_GIT_REPO_SLUG: 'other' }
  ]) assert.throws(() => create(env));

  const app = create(vercelSameOriginEnv);
  const wrongAlias = await app.fetch(new Request('https://hp365-back.vercel.app/v1/admin/session/login'));
  assert.equal(wrongAlias.status, 403);
  assert.equal(wrongAlias.headers.get('cache-control'), 'no-store');
});

test('usa composição persistente padrão, logger seguro e fixa a origem pública', async () => {
  const events = [];
  const originalInfo = console.info;
  console.info = (value) => events.push(value);
  try {
    const app = createVercelAdminSessionApp({ env: baseEnv, fetchImpl: async () => { throw new Error('não deveria chamar Auth'); } });
    const wrongOrigin = await app.fetch(new Request('https://evil.example.test/v1/admin/session/login'));
    assert.equal(wrongOrigin.status, 403);
    assert.equal(wrongOrigin.headers.get('cache-control'), 'no-store');

    const missingIp = await app.fetch(new Request('https://api.example.test/v1/admin/session/login', {
      method: 'POST', headers: { origin: 'https://admin.example.test', 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@example.test', password: 'private' })
    }));
    assert.equal(missingIp.status, 503);
    assert.equal(events.length, 1);
    assert.doesNotMatch(events[0], /private|admin@example\.test|public-key|redis/);
  } finally {
    console.info = originalInfo;
  }
});

test('rejeita query antes de alcançar limiter ou Auth', async () => {
  let limiterCalls = 0;
  let authCalls = 0;
  const app = createVercelAdminSessionApp({
    env: baseEnv,
    rateLimiter: { consume: async () => { limiterCalls += 1; return { allowed: true, retryAfter: 1 }; } },
    fetchImpl: async () => { authCalls += 1; throw new Error('não deve chamar'); },
    logger: { info: () => undefined }
  });
  const response = await app.fetch(new Request('https://api.example.test/v1/admin/session/login?token=private', {
    method: 'POST', headers: { origin: 'https://admin.example.test', 'x-vercel-forwarded-for': '203.0.113.9' }
  }));
  assert.equal(response.status, 400);
  assert.equal(limiterCalls, 0);
  assert.equal(authCalls, 0);
  assert.doesNotMatch(await response.text(), /token|private/);
});
