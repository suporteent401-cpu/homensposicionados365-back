import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('entrypoint Vercel é lazy, fail-closed e rewrite é estrito', async () => {
  const module = await import('../api/admin-session.mjs');
  assert.equal(typeof module.default?.fetch, 'function');
  const response = await module.default.fetch(new Request('https://api.example.test/v1/admin/session/login'));
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.doesNotMatch(await response.text(), /env|token|secret|supabase|upstash/i);

  const config = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  const sessionPaths = ['login', 'mfa/factors', 'mfa/enroll', 'mfa/challenge', 'mfa/verify', 'refresh', 'logout'];
  assert.deepEqual(config.rewrites, sessionPaths.map((path) => ({
    source: `/v1/admin/session/${path}`,
    destination: '/api/admin-session'
  })));
  assert.ok(config.rewrites.every(({ source, destination }) => !source.includes(':') && !destination.includes('?')));
  assert.equal(config.framework, null);
  assert.equal(config.rewrites.length, sessionPaths.length);
});

test('entrypoint inicializa uma vez na primeira request e preserva Response/cookies', async () => {
  const { createEntrypoint } = await import('../api/admin-session.mjs');
  let creations = 0;
  const expected = new Response('ok', { status: 202 });
  expected.headers.append('set-cookie', 'a=1');
  expected.headers.append('set-cookie', 'b=2');
  const entrypoint = createEntrypoint({
    env: {},
    createApp: () => { creations += 1; return { fetch: async () => expected }; }
  });
  assert.equal(creations, 0);
  assert.equal(await entrypoint.fetch(new Request('https://api.example.test/one')), expected);
  assert.equal(await entrypoint.fetch(new Request('https://api.example.test/two')), expected);
  assert.equal(creations, 1);
  assert.deepEqual(expected.headers.getSetCookie(), ['a=1', 'b=2']);
});
