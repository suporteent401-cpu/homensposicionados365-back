import test from 'node:test';
import assert from 'node:assert/strict';
import { createVercelAdminContentApp } from '../src/vercel-admin-content-app.mjs';

const hostname = 'homensposicionados365-back-git-f2006f-israels-projects-03a12359.vercel.app';
const origin = `https://${hostname}`;
const baseEnv = {
  VERCEL: '1', VERCEL_ENV: 'preview', HP365_ENV: 'preview',
  HP365_PREVIEW_ORIGIN_MODE: 'same-origin-vercel', HP365_PREVIEW_BRANCH: 'preview/002-auth',
  VERCEL_GIT_COMMIT_REF: 'preview/002-auth', VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'suporteent401-cpu', VERCEL_GIT_REPO_SLUG: 'homensposicionados365-back',
  VERCEL_BRANCH_URL: hostname, VERCEL_PROJECT_PRODUCTION_URL: 'homensposicionados365-back.vercel.app',
  ADMIN_ALLOWED_ORIGIN: origin, PUBLIC_API_ORIGIN: origin, ADMIN_COOKIE_SITE_DOMAIN: hostname,
  SUPABASE_URL: 'https://ymbzsidruqqkdihrxdjg.supabase.co',
  SUPABASE_AUTH_URL: 'https://ymbzsidruqqkdihrxdjg.supabase.co/auth/v1',
  SUPABASE_ANON_KEY: 'public-key', SUPABASE_SECRET_KEY: 'sb_secret_preview_only',
  UPSTASH_REDIS_REST_URL: 'https://redis.example.test', UPSTASH_REDIS_REST_TOKEN: 'x'.repeat(16),
  RATE_LIMIT_HMAC_KEY: Buffer.alloc(32, 4).toString('base64url'), RATE_LIMIT_NAMESPACE: 'hp365:preview:harness001'
};

const dependencies = {
  rateLimiter: { consume: async () => ({ allowed: false, retryAfter: 7 }) },
  logger: { info: () => undefined }
};

test('content app aceita somente runtime, branch e Supabase Preview fixados', () => {
  assert.doesNotThrow(() => createVercelAdminContentApp({ env: baseEnv, ...dependencies }));
  for (const env of [
    {},
    { ...baseEnv, VERCEL: '0' },
    { ...baseEnv, VERCEL_ENV: 'production' },
    { ...baseEnv, HP365_ENV: 'production' },
    { ...baseEnv, HP365_PREVIEW_ORIGIN_MODE: 'other' },
    { ...baseEnv, HP365_PREVIEW_BRANCH: 'main' },
    { ...baseEnv, VERCEL_GIT_COMMIT_REF: 'main' },
    { ...baseEnv, VERCEL_GIT_PROVIDER: 'gitlab' },
    { ...baseEnv, VERCEL_GIT_REPO_OWNER: 'other' },
    { ...baseEnv, VERCEL_GIT_REPO_SLUG: 'other' },
    { ...baseEnv, ADMIN_ALLOWED_ORIGIN: 'https://other.example.test' },
    { ...baseEnv, ADMIN_ALLOWED_ORIGIN: 'not-a-url' },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'http://preview.example.test' },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'https://user@preview.example.test' },
    { ...baseEnv, VERCEL_BRANCH_URL: 'other.vercel.app' },
    { ...baseEnv, ADMIN_COOKIE_SITE_DOMAIN: 'vercel.app' },
    { ...baseEnv, VERCEL_PROJECT_PRODUCTION_URL: hostname },
    { ...baseEnv, SUPABASE_URL: 'https://ckebvvcxibpnvjwqsjtm.supabase.co' },
    { ...baseEnv, SUPABASE_URL: 'not-a-url' },
    { ...baseEnv, SUPABASE_AUTH_URL: 'https://ckebvvcxibpnvjwqsjtm.supabase.co/auth/v1' },
    { ...baseEnv, SUPABASE_AUTH_URL: 'not-a-url' },
    { ...baseEnv, SUPABASE_SECRET_KEY: '' },
    { ...baseEnv, SUPABASE_SECRET_KEY: 1 },
    { ...baseEnv, RATE_LIMIT_NAMESPACE: 'wrong' },
    { ...baseEnv, PUBLIC_API_ORIGIN: 'https://other.vercel.app' }
  ]) assert.throws(() => createVercelAdminContentApp({ env, ...dependencies }));
});

test('content app fixa origem e compõe authorizer, limiter e repositório sem vazar configuração', async () => {
  const calls = [];
  const app = createVercelAdminContentApp({
    env: baseEnv,
    fetchImpl: async (url, init) => { calls.push({ url, init }); throw new Error('não deve chegar ao Auth'); },
    ...dependencies
  });
  const wrongHost = await app.fetch(new Request('https://evil.example.test/v1/admin/devotionals'));
  assert.equal(wrongHost.status, 403);
  const response = await app.fetch(new Request(`${origin}/v1/admin/devotionals`, {
    method: 'POST', headers: { origin, authorization: 'Bearer a.b.c', 'x-vercel-forwarded-for': '203.0.113.8' }
  }));
  assert.equal(response.status, 429);
  assert.equal(calls.length, 0);
  assert.doesNotMatch(await response.text(), /supabase|secret|redis/i);
});

test('defaults de fetch, limiter e logger permanecem fail-closed e sanitizados', async () => {
  const events = [];
  const originalInfo = console.info;
  console.info = (value) => events.push(value);
  try {
    const app = createVercelAdminContentApp({ env: baseEnv });
    const response = await app.fetch(new Request(`${origin}/v1/admin/devotionals`, {
      method: 'POST', headers: { origin }
    }));
    assert.equal(response.status, 503);
    assert.equal(events.length, 1);
    assert.doesNotMatch(events[0], /secret|public-key|redis/i);
  } finally {
    console.info = originalInfo;
  }
});
