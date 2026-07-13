import test from 'node:test';
import assert from 'node:assert/strict';
import { createVercelClientKey } from '../src/vercel-client-key.mjs';

const hmacKey = Buffer.alloc(32, 7).toString('base64url');

test('deriva chave opaca somente do IP fornecido pela borda Vercel', () => {
  const getClientKey = createVercelClientKey({ hmacKey });
  const first = getClientKey(new Request('https://api.example.test', {
    headers: { 'x-vercel-forwarded-for': '203.0.113.10', 'x-forwarded-for': '198.51.100.1' }
  }));
  const second = getClientKey(new Request('https://api.example.test', {
    headers: { 'x-vercel-forwarded-for': '203.0.113.10', 'x-forwarded-for': '192.0.2.1' }
  }));
  assert.equal(first, second);
  assert.match(first, /^ip:[A-Za-z0-9_-]{43}$/);
  assert.doesNotMatch(first, /203\.0\.113\.10/);
});

test('falha fechada para IP ausente, lista, porta, zone id ou inválido', () => {
  const getClientKey = createVercelClientKey({ hmacKey });
  for (const value of [undefined, '203.0.113.1, 198.51.100.1', '203.0.113.1:443', 'fe80::1%eth0', 'invalid']) {
    const headers = value === undefined ? {} : { 'x-vercel-forwarded-for': value };
    assert.throws(() => getClientKey(new Request('https://api.example.test', { headers })));
  }
  assert.throws(() => getClientKey({ headers: { get: () => ' 203.0.113.1 ' } }));
  assert.match(getClientKey(new Request('https://api.example.test', {
    headers: { 'x-vercel-forwarded-for': '2001:db8::1' }
  })), /^ip:/);
});

test('rejeita chave HMAC fraca ou malformada', () => {
  for (const value of [undefined, '', 'not-base64url', 'A'.repeat(45), Buffer.alloc(31).toString('base64url')]) {
    assert.throws(() => createVercelClientKey({ hmacKey: value }));
  }
  const getClientKey = createVercelClientKey({ hmacKey });
  assert.throws(() => getClientKey());
  assert.throws(() => getClientKey({}));
});

test('canonicaliza representações IPv6 equivalentes no mesmo bucket', () => {
  const getClientKey = createVercelClientKey({ hmacKey });
  const request = (ip) => new Request('https://api.example.test', { headers: { 'x-vercel-forwarded-for': ip } });
  assert.equal(
    getClientKey(request('2001:db8:0:0:0:0:0:1')),
    getClientKey(request('2001:db8::1'))
  );
});
