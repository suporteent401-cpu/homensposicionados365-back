import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePagination, validateIdempotencyKey } from '../src/request-validation.mjs';

test('paginação aplica limite padrão e máximo', () => {
  assert.deepEqual(parsePagination(new URLSearchParams()), { limit: 20, cursor: null });
  assert.deepEqual(parsePagination(new URLSearchParams('limit=50&cursor=abc_DEF-1')), { limit: 50, cursor: 'abc_DEF-1' });
  for (const query of ['limit=0', 'limit=51', 'limit=1.5', 'limit=01&limit=02', 'cursor=not+safe']) {
    assert.throws(() => parsePagination(new URLSearchParams(query)));
  }
});

test('chave de idempotência precisa ser UUID', () => {
  assert.equal(validateIdempotencyKey('550e8400-e29b-41d4-a716-446655440000'), '550e8400-e29b-41d4-a716-446655440000');
  assert.throws(() => validateIdempotencyKey('duplicate-click'));
});

test('rejeita tipos, duplicidade e limites/cursor inválidos', () => {
  assert.throws(() => parsePagination({}));
  assert.throws(() => parsePagination(new URLSearchParams('limit=1&limit=2')));
  assert.throws(() => parsePagination(new URLSearchParams('cursor=a&cursor=b')));
  assert.throws(() => parsePagination(new URLSearchParams('limit=0')));
  assert.throws(() => parsePagination(new URLSearchParams('cursor=%20')));
  assert.deepEqual(parsePagination(new URLSearchParams('limit=50&cursor=abc_-')), { limit: 50, cursor: 'abc_-' });
  assert.throws(() => validateIdempotencyKey(null));
  assert.throws(() => validateIdempotencyKey('not-a-uuid'));
});
