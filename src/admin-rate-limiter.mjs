import { createHmac } from 'node:crypto';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';
import { decodeHmacKey } from './vercel-client-key.mjs';

export const ADMIN_RATE_POLICIES = Object.freeze({
  '/login:ip': [10, 600], '/login:subject': [5, 900],
  '/mfa/factors:ip': [30, 600], '/mfa/factors:subject': [30, 600],
  '/mfa/enroll:ip': [30, 600], '/mfa/enroll:subject': [5, 3_600],
  '/mfa/challenge:ip': [30, 600], '/mfa/challenge:subject': [10, 600],
  '/mfa/verify:ip': [30, 600], '/mfa/verify:subject': [6, 300],
  '/refresh:ip': [60, 600], '/refresh:subject': [20, 600],
  '/logout:ip': [60, 600], '/logout:subject': [20, 600],
  '/devotionals/create:ip': [30, 600], '/devotionals/create:subject': [20, 600]
});

function normalizeNamespace(value) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9:_-]{2,63}$/.test(value)) throw new TypeError('Namespace de rate limit inválido');
  return value;
}

function opaqueIdentifier(key, namespace, route, scope, value) {
  return createHmac('sha256', key).update(namespace).update('\0').update(route).update('\0').update(scope).update('\0').update(value).digest('base64url');
}

export function createAdminRateLimiter({ namespace, hmacKey, limiters, now = Date.now }) {
  const normalizedNamespace = normalizeNamespace(namespace);
  const key = decodeHmacKey(hmacKey);
  if (!(limiters instanceof Map) || typeof now !== 'function') throw new TypeError('Configuração de rate limit inválida');

  return {
    async consume({ route, scope, clientKey, subject }) {
      if (!['ip', 'subject'].includes(scope) || typeof route !== 'string' || typeof clientKey !== 'string' || !clientKey) {
        throw new TypeError('Contexto de rate limit inválido');
      }
      const raw = scope === 'ip' ? clientKey : subject;
      if (typeof raw !== 'string' || !raw || raw.length > 8_192) throw new TypeError('Contexto de rate limit inválido');
      const limiter = limiters.get(`${route}:${scope}`);
      if (!limiter || typeof limiter.limit !== 'function') throw new TypeError('Política de rate limit ausente');
      const result = await limiter.limit(opaqueIdentifier(key, normalizedNamespace, route, scope, raw));
      if (!result || typeof result.success !== 'boolean' || !Number.isFinite(result.reset) || result.reason === 'timeout') {
        throw new TypeError('Resposta de rate limit inválida');
      }
      const retryAfter = Math.max(1, Math.min(3_600, Math.ceil((result.reset - now()) / 1_000)));
      return { allowed: result.success, retryAfter };
    }
  };
}

function normalizeRedisUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Endpoint Redis inválido'); }
  if (url.origin !== value || url.protocol !== 'https:' || url.username || url.password) throw new TypeError('Endpoint Redis inválido');
  return value;
}

export function createUpstashAdminRateLimiter({
  url, token, namespace, hmacKey, timeout = 750,
  RedisClass = Redis, RatelimitClass = Ratelimit
}) {
  const endpoint = normalizeRedisUrl(url);
  if (typeof token !== 'string' || token.length < 16 || token.length > 4_096
    || !Number.isInteger(timeout) || timeout < 100 || timeout > 3_000
    || typeof RedisClass !== 'function' || typeof RatelimitClass !== 'function') {
    throw new TypeError('Configuração Upstash inválida');
  }
  const redis = new RedisClass({ url: endpoint, token });
  const limiters = new Map(Object.entries(ADMIN_RATE_POLICIES).map(([policy, [limit, windowSeconds]]) => [
    policy,
    new RatelimitClass({
      redis,
      limiter: RatelimitClass.slidingWindow(limit, `${windowSeconds} s`),
      prefix: `${normalizeNamespace(namespace)}:v1:${policy.replaceAll('/', '_').replace(':', '_')}`,
      analytics: false,
      ephemeralCache: false,
      timeout
    })
  ]));
  return createAdminRateLimiter({ namespace, hmacKey, limiters });
}
