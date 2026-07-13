import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeSupabaseAuthUrl } from '../src/auth-endpoint.mjs';

test('normaliza apenas endpoint Auth fixado e transporte seguro', () => {
  assert.equal(normalizeSupabaseAuthUrl('http://localhost:54321/auth/v1/'), 'http://localhost:54321/auth/v1');
  assert.equal(normalizeSupabaseAuthUrl('https://auth.example.test/auth/v1'), 'https://auth.example.test/auth/v1');
  for (const args of [
    [null], ['https://auth.example.test/auth/v1', null], ['not a url'],
    ['http://auth.example.test/auth/v1'], ['https://user@auth.example.test/auth/v1'],
    ['https://user:pass@auth.example.test/auth/v1'], ['https://auth.example.test/auth/v1?x=1'],
    ['https://auth.example.test/auth/v1#x'], ['https://auth.example.test/other'],
    ['https://auth.example.test/auth/v1', 'https://other.example.test/auth/v1']
  ]) assert.throws(() => normalizeSupabaseAuthUrl(...args));
});
