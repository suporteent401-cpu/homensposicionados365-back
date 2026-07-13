import test from 'node:test';
import assert from 'node:assert/strict';
import { SessionError } from '../src/admin-session-service.mjs';
import { createAdminSessionHandler } from '../src/admin-session-http.mjs';

const origin = 'https://admin.example.test';
const base = 'https://api.example.test/v1/admin/session';

function makeService(overrides = {}) {
  return {
    resolveRateLimitSubject: async () => '11111111-1111-4111-8111-111111111111',
    login: async () => ({ accessToken: 'access-aal1', refreshToken: 'refresh-private-value-123456', expiresIn: 3600, next: 'mfa' }),
    listFactors: async () => ({ factors: [] }),
    enroll: async () => ({ factorId: 'factor-id', uri: 'otpauth://private' }),
    challenge: async () => ({ challengeId: 'challenge-id' }),
    verify: async () => ({ accessToken: 'access-aal2', refreshToken: 'refresh-rotated-value-123456', expiresIn: 3600, next: 'ready' }),
    refresh: async () => ({ accessToken: 'access-new', refreshToken: 'refresh-refreshed-value-123456', expiresIn: 3600, next: 'ready', subject: '11111111-1111-4111-8111-111111111111' }),
    logout: async () => undefined,
    ...overrides
  };
}

function makeHandler({ service = makeService(), allowed = true, loggerEvents = [], limiter = true } = {}) {
  return createAdminSessionHandler({
    sessionService: service,
    allowedOrigins: new Set(allowed ? [origin] : ['https://other.example.test']),
    rateLimiter: { consume: async () => ({ allowed: limiter, retryAfter: limiter ? 1 : 60 }) },
    getClientKey: () => 'trusted-client-key',
    logger: { info: (event) => loggerEvents.push(event) },
    randomToken: () => 'csrf-safe-value-1234567890',
    createRequestId: () => '11111111-1111-4111-8111-111111111111'
  });
}

function jsonRequest(path, body, headers = {}) {
  return new Request(`${base}${path}`, {
    method: 'POST',
    headers: { origin, 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function body(response) {
  return JSON.parse(await response.text());
}

test('login devolve access apenas e grava refresh/CSRF em cookies seguros', async () => {
  const loggerEvents = [];
  const response = await makeHandler({ loggerEvents })(jsonRequest('/login', { email: 'admin@example.test', password: 'private-value' }));
  assert.equal(response.status, 200);
  assert.deepEqual(await body(response), { accessToken: 'access-aal1', expiresIn: 3600, next: 'mfa', csrfToken: 'csrf-safe-value-1234567890' });
  const cookies = response.headers.getSetCookie();
  assert.equal(cookies.length, 2);
  assert.match(cookies[0], /__Host-hp365-refresh=refresh-private-value-123456;.*HttpOnly;.*Secure;.*SameSite=Strict/);
  assert.match(cookies[1], /__Host-hp365-csrf=csrf-safe-value-1234567890;.*Secure;.*SameSite=Strict/);
  assert.match(cookies[1], /HttpOnly/);
  assert.doesNotMatch(JSON.stringify(await Promise.resolve(loggerEvents)), /private-value|refresh-private|access-aal1|admin@example/i);
  assert.equal(response.headers.get('access-control-allow-origin'), origin);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
});

test('lista fatores com bearer e rejeita corpo mesmo em streaming', async () => {
  const handler = makeHandler();
  const listed = await handler(jsonRequest('/mfa/factors', undefined, { authorization: 'Bearer access-aal1' }));
  assert.equal(listed.status, 200);
  assert.deepEqual(await body(listed), { factors: [] });
  const oversized = await handler(new Request(`${base}/refresh`, {
    method: 'POST', headers: { origin }, body: 'x'.repeat(8_193)
  }));
  assert.equal(oversized.status, 413);
});

test('limpa cookies quando logout upstream falha e quando refresh perde autenticacao', async () => {
  const headers = {
    authorization: 'Bearer access-aal2',
    cookie: '__Host-hp365-refresh=refresh-private-value-123456; __Host-hp365-csrf=csrf-safe-value-1234567890',
    'x-csrf-token': 'csrf-safe-value-1234567890'
  };
  const failedLogout = await makeHandler({ service: makeService({ logout: async () => { throw new Error('private'); } }) })(jsonRequest('/logout', undefined, headers));
  assert.equal(failedLogout.status, 500);
  assert.ok(failedLogout.headers.getSetCookie().every((cookie) => cookie.includes('Max-Age=0')));
  const failedRefresh = await makeHandler({ service: makeService({ refresh: async () => { throw new SessionError(401, 'UNAUTHENTICATED', 'private'); } }) })(jsonRequest('/refresh', undefined, headers));
  assert.equal(failedRefresh.status, 401);
  assert.equal(failedRefresh.headers.getSetCookie().length, 2);
});

test('bloqueia Origin inválida, payload desconhecido/excessivo e rate limit', async () => {
  const invalidOrigin = await makeHandler({ allowed: false })(jsonRequest('/login', { email: 'a@b.c', password: 'x' }));
  assert.equal(invalidOrigin.status, 403);
  const unknown = await makeHandler()(jsonRequest('/login', { email: 'a@b.c', password: 'x', role: 'admin' }));
  assert.equal(unknown.status, 400);
  const oversized = await makeHandler()(jsonRequest('/login', { email: 'a@b.c', password: 'x'.repeat(9_000) }));
  assert.equal(oversized.status, 413);
  const limited = await makeHandler({ limiter: false })(jsonRequest('/login', { email: 'a@b.c', password: 'x' }));
  assert.equal(limited.status, 429);
  const unavailableLimiter = createAdminSessionHandler({
    sessionService: makeService(), allowedOrigins: new Set([origin]),
    rateLimiter: { consume: async () => { throw new Error('private limiter detail'); } },
    getClientKey: () => 'trusted', logger: { info: () => undefined }
  });
  assert.equal((await unavailableLimiter(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 503);
});

test('rejeita valor de cookie inseguro sem refletir conteúdo', async () => {
  const handler = makeHandler({ service: makeService({
    login: async () => ({ accessToken: 'access', refreshToken: 'bad; Domain=evil.example', expiresIn: 3600, next: 'mfa' })
  }) });
  const response = await handler(jsonRequest('/login', { email: 'a@b.c', password: 'private' }));
  assert.equal(response.status, 503);
  assert.equal(response.headers.getSetCookie().length, 0);
  assert.doesNotMatch(await response.text(), /evil|Domain|bad;/i);
});

test('media MFA com bearer e rotaciona cookies apenas no verify', async () => {
  const seen = [];
  const service = makeService({
    enroll: async (value) => { seen.push(value); return { factorId: 'factor-id', uri: 'otpauth://uri' }; },
    challenge: async (value) => { seen.push(value); return { challengeId: 'challenge-id' }; },
    verify: async (value) => { seen.push(value); return { accessToken: 'aal2', refreshToken: 'refresh-rotated-value-123456', expiresIn: 3600, next: 'ready' }; }
  });
  const handler = makeHandler({ service });
  const auth = { authorization: 'Bearer access-aal1' };
  assert.equal((await handler(jsonRequest('/mfa/enroll', { friendlyName: 'App' }, auth))).status, 200);
  assert.equal((await handler(jsonRequest('/mfa/challenge', { factorId: '11111111-1111-4111-8111-111111111111' }, auth))).status, 200);
  const verified = await handler(jsonRequest('/mfa/verify', {
    factorId: '11111111-1111-4111-8111-111111111111',
    challengeId: '22222222-2222-4222-8222-222222222222',
    code: '123456'
  }, auth));
  assert.equal(verified.status, 200);
  assert.equal(verified.headers.getSetCookie().length, 2);
  assert.equal(seen.length, 3);
  assert.ok(seen.every((value) => value.accessToken === 'access-aal1'));
});

test('refresh exige cookie e double-submit CSRF e nunca devolve refresh', async () => {
  const handler = makeHandler();
  const missing = await handler(jsonRequest('/refresh', undefined));
  assert.equal(missing.status, 400);
  const headers = {
    cookie: '__Host-hp365-refresh=refresh-private-value-123456; __Host-hp365-csrf=csrf-safe-value-1234567890',
    'x-csrf-token': 'csrf-safe-value-1234567890'
  };
  const response = await handler(jsonRequest('/refresh', undefined, headers));
  assert.equal(response.status, 200);
  const payload = await body(response);
  assert.deepEqual(payload, { accessToken: 'access-new', expiresIn: 3600, next: 'ready', csrfToken: 'csrf-safe-value-1234567890' });
  assert.doesNotMatch(JSON.stringify(payload), /refresh/i);
  assert.equal(response.headers.getSetCookie().length, 2);
});

test('logout exige bearer/CSRF, chama Auth e limpa cookies', async () => {
  let accessToken;
  const handler = makeHandler({ service: makeService({ logout: async (value) => { accessToken = value.accessToken; } }) });
  const response = await handler(jsonRequest('/logout', undefined, {
    authorization: 'Bearer access-aal2',
    cookie: '__Host-hp365-refresh=refresh-private-value-123456; __Host-hp365-csrf=csrf-safe-value-1234567890',
    'x-csrf-token': 'csrf-safe-value-1234567890'
  }));
  assert.equal(response.status, 204);
  assert.equal(accessToken, 'access-aal2');
  assert.equal(response.headers.getSetCookie().length, 2);
  assert.ok(response.headers.getSetCookie().every((cookie) => cookie.includes('Max-Age=0')));
});

test('erros do serviço têm envelope seguro e preflight é restrito', async () => {
  const handler = makeHandler({ service: makeService({ login: async () => { throw new SessionError(503, 'AUTH_UNAVAILABLE', 'Serviço indisponível'); } }) });
  const failed = await handler(jsonRequest('/login', { email: 'a@b.c', password: 'private' }));
  assert.equal(failed.status, 503);
  assert.deepEqual(await body(failed), { error: { code: 'AUTH_UNAVAILABLE', message: 'Serviço de autenticação indisponível', requestId: '11111111-1111-4111-8111-111111111111' } });

  const preflight = await makeHandler()(new Request(`${base}/login`, {
    method: 'OPTIONS',
    headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' }
  }));
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
  assert.notEqual(preflight.headers.get('access-control-allow-origin'), '*');
});

test('usa identidade Auth estável como sujeito e não bearer, refresh ou factorId', async () => {
  const subjects = [];
  const resolved = [];
  const handler = createAdminSessionHandler({
    sessionService: makeService({
      resolveRateLimitSubject: async (value) => { resolved.push(value); return 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; },
      refresh: async () => ({
        accessToken: 'new-access', refreshToken: 'new-refresh-value-123456', expiresIn: 900, next: 'ready',
        subject: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
      })
    }),
    allowedOrigins: new Set([origin]),
    rateLimiter: { consume: async (value) => { if (value.scope === 'subject') subjects.push(value.subject); return { allowed: true, retryAfter: 1 }; } },
    getClientKey: () => 'trusted', logger: { info: () => undefined },
    randomToken: () => 'csrf-safe-value-1234567890'
  });
  const auth = { authorization: 'Bearer rotating-bearer' };
  assert.equal((await handler(jsonRequest('/mfa/challenge', { factorId: '11111111-1111-4111-8111-111111111111' }, auth))).status, 200);
  assert.equal((await handler(jsonRequest('/refresh', undefined, {
    cookie: '__Host-hp365-refresh=rotating-refresh; __Host-hp365-csrf=csrf-safe-value-1234567890',
    'x-csrf-token': 'csrf-safe-value-1234567890'
  }))).status, 200);
  assert.deepEqual(subjects, ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']);
  assert.deepEqual(resolved, [{ accessToken: 'rotating-bearer', factorId: '11111111-1111-4111-8111-111111111111' }]);
  assert.doesNotMatch(subjects.join(' '), /rotating|11111111-1111-4111-8111-111111111111/);
});

test('revoga sessão rotacionada e limpa cookies quando bucket pós-refresh nega ou falha', async () => {
  for (const logoutFails of [false, true]) {
    let revoked;
    let calls = 0;
    const service = makeService({
      logout: async ({ accessToken: value }) => { revoked = value; if (logoutFails) throw new Error('private'); }
    });
    const handler = createAdminSessionHandler({
      sessionService: service, allowedOrigins: new Set([origin]),
      rateLimiter: { consume: async () => {
        calls += 1;
        if (calls === 1) return { allowed: true, retryAfter: 1 };
        return { allowed: false, retryAfter: 30 };
      } },
      getClientKey: () => 'trusted', logger: { info: () => undefined }
    });
    const response = await handler(jsonRequest('/refresh', undefined, {
      cookie: '__Host-hp365-refresh=old-refresh; __Host-hp365-csrf=csrf-safe-value-1234567890',
      'x-csrf-token': 'csrf-safe-value-1234567890'
    }));
    assert.equal(response.status, 429);
    assert.equal(revoked, 'access-new');
    assert.equal(response.headers.get('retry-after'), '30');
    assert.ok(response.headers.getSetCookie().every((cookie) => cookie.includes('Max-Age=0')));
  }
});

test('falha do logger não altera resposta nem cookies rotacionados', async () => {
  const handler = createAdminSessionHandler({
    sessionService: makeService(),
    allowedOrigins: new Set([origin]),
    rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 1 }) },
    getClientKey: () => 'trusted-client-key',
    logger: { info: () => { throw new Error('logger unavailable'); } },
    randomToken: () => 'csrf-safe-value-1234567890',
    createRequestId: () => '11111111-1111-4111-8111-111111111111'
  });
  const response = await handler(jsonRequest('/login', { email: 'admin@example.test', password: 'private-value' }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.getSetCookie().length, 2);
});

test('cobre configuração, rota, preflight e validações defensivas do handler', async () => {
  const required = {
    sessionService: makeService(), allowedOrigins: new Set([origin]),
    rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 1 }) }, getClientKey: () => 'key', logger: { info: () => undefined }
  };
  assert.throws(() => createAdminSessionHandler({ ...required, allowedOrigins: new Set() }));
  assert.throws(() => createAdminSessionHandler({ ...required, allowedOrigins: new Set(['http://evil.example']) }));
  assert.throws(() => createAdminSessionHandler({ ...required, refreshCookieMaxAge: 0 }));

  const handler = makeHandler();
  assert.equal((await handler(new Request(`${base}/unknown`, { method: 'POST', headers: { origin } }))).status, 404);
  assert.equal((await handler(new Request(`${base}/login`, {
    method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'DELETE' }
  }))).status, 403);
  assert.equal((await handler(jsonRequest('/login', { email: 'invalid', password: 'x' }))).status, 400);
  assert.equal((await handler(new Request(`${base}/login`, {
    method: 'POST', headers: { origin, 'content-type': 'application/json', 'content-length': 'invalid' }, body: '{}'
  }))).status, 413);

  const cookieHeaders = {
    cookie: `__Host-hp365-refresh=${'x'.repeat(4097)}; __Host-hp365-csrf=csrf-safe-value-1234567890`,
    'x-csrf-token': 'csrf-safe-value-1234567890'
  };
  assert.equal((await handler(jsonRequest('/refresh', undefined, cookieHeaders))).status, 400);
  const malformed = makeHandler({ service: makeService({ login: async () => ({ refreshToken: 'valid-refresh', expiresIn: 3600, next: 'mfa' }) }) });
  assert.equal((await malformed(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 503);
  const longRefresh = makeHandler({ service: makeService({
    login: async () => ({ accessToken: 'access', refreshToken: 'x'.repeat(4097), expiresIn: 3600, next: 'mfa' })
  }) });
  assert.equal((await longRefresh(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 503);

  const defaults = createAdminSessionHandler({ ...required });
  assert.equal((await defaults(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 200);
});

test('exercita guardas restantes de parsing, CSRF, cookies e CORS', async () => {
  const handler = makeHandler();
  const raw = (path, { method = 'POST', headers = {}, body: requestBody } = {}) => handler(new Request(`${base}${path}`, {
    method, headers: { origin, ...headers }, body: requestBody
  }));
  assert.equal((await raw('/login', { headers: { 'content-type': 'text/plain' }, body: '{}' })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json' }, body: '{' })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json' }, body: '[]' })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json' }, body: 'null' })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json', 'content-length': '9000' }, body: '{}' })).status, 413);
  assert.equal((await raw('/mfa/factors', { body: 'x' })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'a@b.c', password: '' }) })).status, 400);
  assert.equal((await raw('/login', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'a@b.c', password: 'x'.repeat(1025) }) })).status, 400);

  for (const cookie of ['broken', 'a=1; a=2']) {
    assert.equal((await raw('/refresh', { headers: { cookie, 'x-csrf-token': 'csrf-safe-value-1234567890' } })).status, 400);
  }
  const csrfCookie = '__Host-hp365-refresh=refresh; __Host-hp365-csrf=csrf-safe-value-1234567890';
  assert.equal((await raw('/refresh', { headers: { cookie: csrfCookie, 'x-csrf-token': 'short' } })).status, 400);
  assert.equal((await raw('/refresh', { headers: { cookie: csrfCookie, 'x-csrf-token': 'csrf-other-value-1234567890' } })).status, 400);
  assert.equal((await raw('/refresh', { headers: { cookie: csrfCookie, 'x-csrf-token': 'csrf-safe-value-1234567899' } })).status, 400);

  assert.equal((await handler(new Request(`${base}/login`, { method: 'GET', headers: { origin } }))).status, 405);
  assert.equal((await handler(new Request(`${base}/login`, { method: 'POST' }))).status, 403);
  assert.equal((await handler(new Request('https://api.example.test/other', { method: 'POST', headers: { origin } }))).status, 404);
  const deniedHeaders = await handler(new Request(`${base}/login`, {
    method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type, x-evil' }
  }));
  assert.equal(deniedHeaders.status, 403);
});

test('falha fechada para dependências HTTP e cobre defaults/erros de sessão', async () => {
  const baseConfig = {
    sessionService: makeService(), allowedOrigins: new Set([origin]),
    rateLimiter: { consume: async () => ({ allowed: true, retryAfter: 1 }) }, getClientKey: () => 'key', logger: { info: () => undefined }
  };
  for (const override of [
    { sessionService: null }, { allowedOrigins: [] }, { rateLimiter: null },
    { getClientKey: null }, { logger: null }, { randomToken: null }, { createRequestId: null },
    { refreshCookieMaxAge: 604801 }, { refreshCookieMaxAge: 1.5 }
  ]) assert.throws(() => createAdminSessionHandler({ ...baseConfig, ...override }));
  assert.throws(() => createAdminSessionHandler({ ...baseConfig, allowedOrigins: new Set(['not an origin']) }));

  const request = jsonRequest('/login', { email: 'a@b.c', password: 'x' });
  for (const getClientKey of [() => { throw new Error('x'); }, () => '', () => 1]) {
    const handler = createAdminSessionHandler({ ...baseConfig, getClientKey });
    assert.equal((await handler(request.clone())).status, 503);
  }
  const nonBoolean = createAdminSessionHandler({ ...baseConfig, rateLimiter: { consume: async () => 'yes' } });
  assert.equal((await nonBoolean(request.clone())).status, 503);

  const invalidCsrf = createAdminSessionHandler({ ...baseConfig, randomToken: () => 'bad' });
  assert.equal((await invalidCsrf(request.clone())).status, 503);
  const absentCsrf = createAdminSessionHandler({ ...baseConfig, randomToken: () => undefined });
  assert.equal((await absentCsrf(request.clone())).status, 503);
  for (const session of [
    null,
    { accessToken: null, refreshToken: 'refresh', expiresIn: 3600, next: 'mfa' },
    { accessToken: 'access', refreshToken: 'refresh', expiresIn: 1.5, next: 'mfa' },
    { accessToken: 'access', refreshToken: 'refresh', expiresIn: 3600, next: 'bad' }
  ]) {
    const malformed = makeHandler({ service: makeService({ login: async () => session }) });
    assert.equal((await malformed(request.clone())).status, 503);
  }
  const unsafeRefresh = makeHandler({ service: makeService({
    login: async () => ({ accessToken: 'access', refreshToken: 'bad value', expiresIn: 3600, next: 'mfa' })
  }) });
  assert.equal((await unsafeRefresh(request.clone())).status, 503);
});

test('distingue bearer e componentes CSRF ausentes de valores malformados', async () => {
  const handler = makeHandler();
  assert.equal((await handler(jsonRequest('/mfa/factors', undefined))).status, 401);
  assert.equal((await handler(jsonRequest('/mfa/factors', undefined, { authorization: 'Basic value' }))).status, 401);
  assert.equal((await handler(jsonRequest('/refresh', undefined, {
    cookie: '__Host-hp365-refresh=refresh', 'x-csrf-token': 'csrf-safe-value-1234567890'
  }))).status, 400);
  assert.equal((await handler(jsonRequest('/refresh', undefined, {
    cookie: '__Host-hp365-refresh=refresh; __Host-hp365-csrf=csrf-safe-value-1234567890'
  }))).status, 400);
});

test('valida DTOs MFA, friendlyName e mapeamentos seguros restantes', async () => {
  const handler = makeHandler();
  assert.equal((await handler(jsonRequest('/mfa/enroll', {}, { authorization: 'Bearer access' }))).status, 200);
  assert.equal((await handler(jsonRequest('/mfa/enroll', { friendlyName: '  App  ' }, { authorization: 'Bearer access' }))).status, 200);
  assert.equal((await handler(jsonRequest('/mfa/enroll', { friendlyName: 'bad\nname' }, { authorization: 'Bearer access' }))).status, 400);
  assert.equal((await handler(jsonRequest('/mfa/challenge', { factorId: 'bad' }, { authorization: 'Bearer access' }))).status, 400);
  assert.equal((await handler(jsonRequest('/mfa/verify', {
    factorId: '11111111-1111-4111-8111-111111111111', challengeId: '22222222-2222-4222-8222-222222222222', code: 'abc123'
  }, { authorization: 'Bearer access' }))).status, 400);
  const conflict = makeHandler({ service: makeService({ login: async () => { throw new SessionError(409, 'MFA_FACTOR_LIMIT', 'private'); } }) });
  assert.equal((await conflict(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 409);
  const unknown = makeHandler({ service: makeService({ login: async () => { throw new SessionError(418, 'UNKNOWN', 'private'); } }) });
  assert.equal((await unknown(jsonRequest('/login', { email: 'a@b.c', password: 'x' }))).status, 500);
});
