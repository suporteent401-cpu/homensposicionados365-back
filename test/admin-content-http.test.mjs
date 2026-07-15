import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdminContentHandler } from '../src/admin-content-http.mjs';
import { ContentError } from '../src/admin-content.mjs';

const origin = 'https://admin.example.com';
const principal = { userId: '11111111-1111-4111-8111-111111111111', role: 'admin', aal: 'aal2' };
const body = { title: 'Teste', occurredAt: '2026-07-14', youtubeUrl: 'https://youtu.be/WuW3C2bFcHc' };
const headers = { origin, authorization: 'Bearer a.b.c', 'content-type': 'application/json', 'idempotency-key': '550e8400-e29b-41d4-a716-446655440000' };

function setup(overrides = {}) {
  const calls = { auth: 0, service: 0, limits: [], logs: [] };
  const handler = createAdminContentHandler({
    allowedOrigins: new Set([origin]),
    authorizeAdmin: async () => { calls.auth += 1; return principal; },
    contentService: { createDraft: async (value) => { calls.service += 1; calls.value = value; return { kind: 'created', status: 201, body: { id: 'draft-id', status: 'draft' } }; } },
    rateLimiter: { consume: async (value) => { calls.limits.push(value); return { allowed: true, retryAfter: 1 }; } },
    getClientKey: () => 'opaque-ip',
    logger: { info: (value) => calls.logs.push(value) },
    createRequestId: () => '99999999-9999-4999-8999-999999999999',
    ...overrides
  });
  return { handler, calls };
}

test('POST cria rascunho após rate limit IP, auth e rate limit por usuário', async () => {
  const { handler, calls } = setup();
  const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
  assert.equal(response.status, 201);
  assert.equal(response.headers.get('idempotency-replayed'), 'false');
  assert.deepEqual(await response.json(), { id: 'draft-id', status: 'draft' });
  assert.equal(calls.auth, 1);
  assert.equal(calls.service, 1);
  assert.deepEqual(calls.limits.map(({ scope, subject }) => [scope, subject]), [['ip', undefined], ['subject', principal.userId]]);
  assert.equal(calls.value.requestId, '99999999-9999-4999-8999-999999999999');
  assert.deepEqual(calls.logs, [{ event: 'admin_content_request', route: 'create_draft', status: 201, requestId: calls.value.requestId }]);
});

test('replay mantém resposta e sinaliza header', async () => {
  const { handler } = setup({ contentService: { createDraft: async () => ({ kind: 'replayed', status: 201, body: { id: 'same' } }) } });
  const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
  assert.equal(response.status, 201);
  assert.equal(response.headers.get('idempotency-replayed'), 'true');
});

test('nega rota/query/origin/método e preflight incompatível antes do domínio', async () => {
  const { handler, calls } = setup();
  const cases = [
    new Request('https://api.example.com/v1/admin/other', { method: 'POST', headers }),
    new Request('https://api.example.com/v1/admin/devotionals?x=1', { method: 'POST', headers }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { ...headers, origin: 'https://evil.example' } }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'GET', headers }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'DELETE' } })
  ];
  const statuses = [];
  for (const request of cases) statuses.push((await handler(request)).status);
  assert.deepEqual(statuses, [404, 400, 403, 405, 403]);
  assert.equal(calls.auth, 0);
  assert.equal(calls.service, 0);
});

test('preflight permitido declara somente headers necessários', async () => {
  const { handler } = setup();
  const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'OPTIONS', headers: {
    origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type, idempotency-key'
  } }));
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-origin'), origin);
  assert.match(response.headers.get('access-control-allow-headers'), /Idempotency-Key/);
});

test('rejeita JSON e headers inválidos sem persistir', async () => {
  const { handler, calls } = setup();
  const requests = [
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { ...headers, 'content-type': 'text/plain' }, body: '{}' }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: '{' }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { ...headers, 'idempotency-key': 'bad' }, body: '{}' }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { ...headers, authorization: '' }, body: '{}' }),
    new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { origin, 'content-type': 'application/json', 'idempotency-key': headers['idempotency-key'] }, body: '{}' })
  ];
  for (const request of requests) assert.ok([400, 401].includes((await handler(request)).status));
  assert.equal(calls.service, 0);
});

test('mapeia erros conhecidos, rate limit e falha inesperada sem vazar detalhe', async () => {
  for (const [error, status, code] of [
    [new ContentError(409, 'IDEMPOTENCY_CONFLICT', 'segredo sql'), 409, 'IDEMPOTENCY_CONFLICT'],
    [new Error('database password leaked'), 500, 'INTERNAL_ERROR']
  ]) {
    const { handler } = setup({ contentService: { createDraft: async () => { throw error; } } });
    const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
    assert.equal(response.status, status);
    const text = await response.text();
    assert.match(text, new RegExp(code));
    assert.doesNotMatch(text, /segredo|sql|database|password/i);
  }
  const { handler } = setup({ rateLimiter: { consume: async () => ({ allowed: false, retryAfter: 7 }) } });
  const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '7');
});

test('cobre configuração, origem loopback, tamanho, limiter e logger fail-safe', async () => {
  for (const value of [{}, { allowedOrigins: new Set() }, { allowedOrigins: new Set([origin]) },
    { allowedOrigins: new Set([origin]), authorizeAdmin: async () => principal },
    { allowedOrigins: new Set([origin]), authorizeAdmin: async () => principal, contentService: { createDraft() {} } }]) {
    assert.throws(() => createAdminContentHandler(value));
  }
  for (const badOrigin of ['not-url', 'http://remote.example', 'https://admin.example.com/path']) {
    assert.throws(() => setup({ allowedOrigins: new Set([badOrigin]) }));
  }
  const loopback = setup({ allowedOrigins: new Set(['http://127.0.0.1:3000']), logger: { info() { throw new Error('ignored'); } } }).handler;
  const loopbackResponse = await loopback(new Request('http://127.0.0.1:3000/v1/admin/devotionals', { method: 'POST', headers: { ...headers, origin: 'http://127.0.0.1:3000' }, body: JSON.stringify(body) }));
  assert.equal(loopbackResponse.status, 201);
  assert.equal(loopbackResponse.headers.get('strict-transport-security'), null);
  assert.doesNotThrow(() => setup({ allowedOrigins: new Set(['http://localhost:3000']) }));

  for (const contentLength of ['bad', '8193']) {
    const { handler } = setup();
    const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers: { ...headers, 'content-length': contentLength }, body: '{}' }));
    assert.equal(response.status, 413);
  }
  const { handler: oversized } = setup();
  assert.equal((await oversized(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify({ title: 'x'.repeat(8200) }) }))).status, 413);

  for (const overrides of [
    { getClientKey: () => { throw new Error('no edge'); } }, { getClientKey: () => '' },
    { rateLimiter: { consume: async () => { throw new Error('down'); } } },
    { rateLimiter: { consume: async () => null } },
    { rateLimiter: { consume: async () => ({ allowed: 'yes', retryAfter: 1 }) } },
    { rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 0 }) } },
    { rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 3601 }) } }
  ]) {
    const { handler } = setup(overrides);
    assert.equal((await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }))).status, 503);
  }
});

test('mapeia todos os erros seguros e usa request id padrão', async () => {
  for (const [code, status] of [['VALIDATION_ERROR', 400], ['PAYLOAD_TOO_LARGE', 413], ['UNAUTHENTICATED', 401],
    ['FORBIDDEN', 403], ['CONTENT_CONFLICT', 409], ['AUTH_UNAVAILABLE', 503], ['DATA_UNAVAILABLE', 503]]) {
    const { handler } = setup({ contentService: { createDraft: async () => { throw new ContentError(status, code, 'detalhe privado'); } } });
    const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
    assert.equal(response.status, status);
    assert.doesNotMatch(await response.text(), /detalhe privado/);
  }
  const handler = createAdminContentHandler({
    allowedOrigins: new Set([origin]), authorizeAdmin: async () => principal,
    contentService: { createDraft: async () => { throw null; } },
    rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 1 }) }, getClientKey: () => 'ip', logger: { info() {} }
  });
  const response = await handler(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
  assert.match((await response.json()).error.requestId, /^[0-9a-f-]{36}$/i);
  const noRetry = setup({ contentService: { createDraft: async () => { throw new ContentError(429, 'RATE_LIMITED', 'privado'); } } }).handler;
  const noRetryResponse = await noRetry(new Request('https://api.example.com/v1/admin/devotionals', { method: 'POST', headers, body: JSON.stringify(body) }));
  assert.equal(noRetryResponse.status, 429);
  assert.equal(noRetryResponse.headers.get('retry-after'), null);
});
