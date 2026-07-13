import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ADMIN_RATE_POLICIES,
  createAdminRateLimiter,
  createUpstashAdminRateLimiter
} from '../src/admin-rate-limiter.mjs';

const hmacKey = Buffer.alloc(32, 9).toString('base64url');

test('aplica buckets de IP e sujeito com identificadores opacos', async () => {
  const seen = [];
  const allow = { limit: async (key) => { seen.push(key); return { success: true, reset: 61_000 }; } };
  const limiter = createAdminRateLimiter({
    namespace: 'hp365:test', hmacKey, now: () => 1_000,
    limiters: new Map([['/login:ip', allow], ['/login:subject', allow]])
  });
  assert.deepEqual(await limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:opaque' }), { allowed: true, retryAfter: 60 });
  assert.deepEqual(await limiter.consume({ route: '/login', scope: 'subject', clientKey: 'ip:opaque', subject: 'Admin@Example.test' }), { allowed: true, retryAfter: 60 });
  assert.equal(seen.length, 2);
  assert.ok(seen.every((value) => !value.includes('Admin@') && !value.includes('ip:opaque')));
});

test('nega excesso e falha fechada em timeout ou resposta inválida', async () => {
  for (const response of [
    { success: false, reset: 31_000 },
    { success: true, reset: 31_000, reason: 'timeout' },
    { success: 'yes', reset: 31_000 },
    { success: true, reset: 'later' }
  ]) {
    const limiter = createAdminRateLimiter({
      namespace: 'hp365:test', hmacKey, now: () => 1_000,
      limiters: new Map([['/login:ip', { limit: async () => response }]])
    });
    if (response.success === false) assert.deepEqual(await limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:key' }), { allowed: false, retryAfter: 30 });
    else await assert.rejects(() => limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:key' }));
  }
});

test('rejeita rota, escopo, sujeito ou configuração desconhecida', async () => {
  const limiter = createAdminRateLimiter({
    namespace: 'hp365:test', hmacKey,
    limiters: new Map([['/login:subject', { limit: async () => ({ success: true, reset: Date.now() + 1000 }) }]])
  });
  await assert.rejects(() => limiter.consume({ route: '/unknown', scope: 'ip', clientKey: 'ip:key' }));
  await assert.rejects(() => limiter.consume({ route: '/login', scope: 'subject', clientKey: 'ip:key' }));
  assert.throws(() => createAdminRateLimiter({ namespace: 'bad namespace', hmacKey, limiters: new Map() }));
});

test('valida todo contexto e limita Retry-After a uma faixa segura', async () => {
  const responses = [
    { success: true, reset: -10_000 },
    { success: true, reset: 10_000_000 }
  ];
  const limiter = createAdminRateLimiter({
    namespace: 'hp365:test', hmacKey, now: () => 0,
    limiters: new Map([['/login:ip', { limit: async () => responses.shift() }]])
  });
  assert.equal((await limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:key' })).retryAfter, 1);
  assert.equal((await limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:key' })).retryAfter, 3_600);

  const valid = { route: '/login', scope: 'ip', clientKey: 'ip:key' };
  for (const context of [
    { ...valid, scope: 'other' }, { ...valid, route: 1 }, { ...valid, clientKey: 1 },
    { ...valid, clientKey: '' }, { ...valid, scope: 'subject' },
    { ...valid, scope: 'subject', subject: '' },
    { ...valid, scope: 'subject', subject: 'x'.repeat(8_193) }
  ]) await assert.rejects(() => limiter.consume(context));

  const noPolicy = createAdminRateLimiter({ namespace: 'hp365:test', hmacKey, limiters: new Map([['/login:ip', {}]]) });
  await assert.rejects(() => noPolicy.consume(valid));
  assert.throws(() => createAdminRateLimiter({ namespace: 1, hmacKey, limiters: new Map() }));
  assert.throws(() => createAdminRateLimiter({ namespace: 'hp365:test', hmacKey, limiters: {}, now: Date.now }));
  assert.throws(() => createAdminRateLimiter({ namespace: 'hp365:test', hmacKey, limiters: new Map(), now: 1 }));
});

test('compõe todos os buckets persistentes com SDK fixado e sem cache local', async () => {
  const redisOptions = [];
  const limiterOptions = [];
  class FakeRedis {
    constructor(options) { redisOptions.push(options); }
  }
  class FakeRatelimit {
    static slidingWindow(limit, window) { return { limit, window }; }
    constructor(options) { limiterOptions.push(options); }
    async limit() { return { success: true, reset: Date.now() + 1_000 }; }
  }
  const limiter = createUpstashAdminRateLimiter({
    url: 'https://redis.example.test', token: 'x'.repeat(16), namespace: 'hp365:test', hmacKey,
    timeout: 500, RedisClass: FakeRedis, RatelimitClass: FakeRatelimit
  });
  assert.deepEqual(redisOptions, [{ url: 'https://redis.example.test', token: 'x'.repeat(16) }]);
  assert.equal(limiterOptions.length, Object.keys(ADMIN_RATE_POLICIES).length);
  assert.ok(limiterOptions.every((options) => options.analytics === false
    && options.ephemeralCache === false && options.timeout === 500 && options.prefix.includes(':v1:')));
  assert.equal((await limiter.consume({ route: '/login', scope: 'ip', clientKey: 'ip:key' })).allowed, true);

  // Também exercita os defaults do SDK oficial sem efetuar chamada remota.
  assert.doesNotThrow(() => createUpstashAdminRateLimiter({
    url: 'https://redis.example.test', token: 'x'.repeat(16), namespace: 'hp365:test', hmacKey
  }));
});

test('rejeita endpoint e configuração Upstash inseguros antes de criar cliente', () => {
  const valid = { url: 'https://redis.example.test', token: 'x'.repeat(16), namespace: 'hp365:test', hmacKey };
  for (const url of [undefined, 'not-a-url', 'http://redis.example.test', 'https://user@redis.example.test', 'https://redis.example.test/path']) {
    assert.throws(() => createUpstashAdminRateLimiter({ ...valid, url }));
  }
  for (const override of [
    { token: 1 }, { token: 'short' }, { token: 'x'.repeat(4_097) },
    { timeout: 1.5 }, { timeout: 99 }, { timeout: 3_001 },
    { RedisClass: {} }, { RatelimitClass: {} }
  ]) assert.throws(() => createUpstashAdminRateLimiter({ ...valid, ...override }));
});
