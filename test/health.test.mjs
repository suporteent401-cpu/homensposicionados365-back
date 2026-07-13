import test from 'node:test';
import assert from 'node:assert/strict';
import { healthResponse } from '../src/health.mjs';

test('health check não expõe configuração interna', () => {
  const response = healthResponse();
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), { status: 'ok' });
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
});
