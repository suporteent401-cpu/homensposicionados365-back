import { randomUUID } from 'node:crypto';
import { Redis } from '@upstash/redis';

const fail = () => {
  console.error('upstash_preview=fail');
  process.exitCode = 1;
};

const urlValue = process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.UPSTASH_REDIS_REST_TOKEN;

let url;
if (typeof urlValue === 'string') {
  try { url = new URL(urlValue); } catch { /* configuração inválida */ }
}

if (url?.protocol !== 'https:'
  || !url.hostname.endsWith('.upstash.io')
  || url.origin !== urlValue
  || typeof token !== 'string'
  || token.length < 32
  || /\s/.test(token)) {
  fail();
} else {
  const redis = new Redis({ url: urlValue, token });
  const key = `hp365:preview:auth002a:harness:${randomUUID()}`;
  let created = false;

  try {
    const write = await redis.set(key, 'ok', { ex: 60, nx: true });
    if (write !== 'OK') throw new Error('write rejected');
    created = true;
    if (await redis.get(key) !== 'ok') throw new Error('roundtrip mismatch');
    console.log('upstash_preview=pass');
  } catch {
    fail();
  } finally {
    if (created) {
      try {
        await redis.del(key);
        console.log('upstash_cleanup=pass');
      } catch {
        console.error('upstash_cleanup=fail');
        process.exitCode = 1;
      }
    }
  }
}
