import test from 'node:test';
import assert from 'node:assert/strict';
import { createSupabaseAdminSessionService } from '../src/admin-session-service.mjs';

const authUrl = 'http://127.0.0.1:54321/auth/v1';
const admin = { id: '11111111-1111-4111-8111-111111111111', email_confirmed_at: '2026-07-13T00:00:00Z', app_metadata: { role: 'admin' }, factors: [] };
const factorId = '33333333-3333-4333-8333-333333333333';

function token(aal = 'aal2') {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'HS256' })}.${encode({
    sub: admin.id, iss: authUrl, aud: 'authenticated', exp: 2_000_000_000, aal,
    amr: aal === 'aal2' ? [{ method: 'password' }, { method: 'totp' }] : [{ method: 'password' }]
  })}.test-signature`;
}

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function service(fetchImpl) {
  return createSupabaseAdminSessionService({ authUrl, anonKey: 'local-public-key', fetchImpl });
}

test('login confirma papel admin no Auth e normaliza sessão sem confiar no cliente', async () => {
  const calls = [];
  const api = service(async (url, options) => {
    calls.push({ url, options });
    if (url.includes('/token?grant_type=password')) {
      return response(200, { access_token: token('aal1'), refresh_token: 'refresh-private-value-123456', expires_in: 3600 });
    }
    return response(200, admin);
  });

  assert.deepEqual(await api.login({ email: 'admin@local.invalid', password: 'not-logged' }), {
    accessToken: token('aal1'), refreshToken: 'refresh-private-value-123456', expiresIn: 3600, next: 'mfa'
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].options.headers.authorization, `Bearer ${token('aal1')}`);
});

test('login revoga sessão de não-admin e usa erro genérico contra enumeração', async () => {
  const urls = [];
  const api = service(async (url) => {
    urls.push(url);
    if (url.includes('/token?grant_type=password')) return response(200, { access_token: token('aal1'), refresh_token: 'refresh-private-value-123456', expires_in: 3600 });
    if (url.endsWith('/user')) return response(200, { ...admin, app_metadata: {} });
    return response(204);
  });
  await assert.rejects(() => api.login({ email: 'user@local.invalid', password: 'private' }), (error) => {
    assert.equal(error.status, 401);
    assert.equal(error.code, 'UNAUTHENTICATED');
    return true;
  });
  assert.ok(urls.some((url) => url.endsWith('/logout')));
});

test('login revoga sessão de admin sem confirmação de e-mail válida', async () => {
  for (const emailConfirmedAt of [undefined, 'invalid-date']) {
    const urls = [];
    const api = service(async (url) => {
      urls.push(url);
      if (url.includes('/token?grant_type=password')) return response(200, { access_token: token('aal1'), refresh_token: 'refresh-private-value-123456', expires_in: 3600 });
      if (url.endsWith('/user')) return response(200, { ...admin, email_confirmed_at: emailConfirmedAt });
      return response(204);
    });
    await assert.rejects(() => api.login({ email: 'admin@local.invalid', password: 'private' }), (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, 'UNAUTHENTICATED');
      return true;
    });
    assert.ok(urls.some((url) => url.endsWith('/logout')));
  }
});

test('media enrollment, challenge, verify, refresh e logout com payload mínimo', async () => {
  const calls = [];
  const api = service(async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/user')) return response(200, admin);
    if (url.endsWith('/factors')) return response(200, { id: factorId, totp: { qr_code: 'data:image/svg+xml,test', uri: 'otpauth://totp/test?secret=SAFE' } });
    if (url.endsWith('/challenge')) return response(200, { id: '66666666-6666-4666-8666-666666666666' });
    if (url.endsWith('/verify')) return response(200, { access_token: token(), refresh_token: 'refresh-rotated-value-123456', expires_in: 3600 });
    if (url.includes('grant_type=refresh_token')) return response(200, { access_token: token(), refresh_token: 'refresh-refreshed-value-123456', expires_in: 3600 });
    if (url.endsWith('/logout')) return response(204);
    throw new Error('unexpected request');
  });

  assert.deepEqual(await api.enroll({ accessToken: token('aal1'), friendlyName: 'Authenticator' }), {
    factorId, uri: 'otpauth://totp/test?secret=SAFE'
  });
  assert.deepEqual(await api.challenge({ accessToken: token('aal1'), factorId }), { challengeId: '66666666-6666-4666-8666-666666666666' });
  assert.deepEqual(await api.verify({ accessToken: token('aal1'), factorId, challengeId: '66666666-6666-4666-8666-666666666666', code: '123456' }), {
    accessToken: token(), refreshToken: 'refresh-rotated-value-123456', expiresIn: 3600, next: 'ready', subject: admin.id
  });
  assert.deepEqual(await api.refresh({ refreshToken: 'refresh-private-value-123456' }), {
    accessToken: token(), refreshToken: 'refresh-refreshed-value-123456', expiresIn: 3600, next: 'ready', subject: admin.id
  });
  await api.logout({ accessToken: token() });
  assert.ok(calls.some(({ url }) => url.endsWith('/logout')));
});

test('falha fechada sem propagar detalhe do Auth', async () => {
  for (const fetchImpl of [
    async () => { throw new Error('leaked upstream'); },
    async () => response(503, { message: 'internal secret' })
  ]) {
    await assert.rejects(() => service(fetchImpl).login({ email: 'a@b.c', password: 'private' }), (error) => {
      assert.equal(error.status, 503);
      assert.equal(error.code, 'AUTH_UNAVAILABLE');
      assert.doesNotMatch(error.message, /upstream|secret|token|password/i);
      return true;
    });
  }
});

test('verify e refresh rejeitam sessão que não alcançou AAL2/TOTP', async () => {
  const api = service(async (url) => {
    if (url.endsWith('/verify') || url.includes('grant_type=refresh_token')) {
      return response(200, { access_token: token('aal1'), refresh_token: 'refresh-private-value-123456', expires_in: 3600 });
    }
    return response(200, admin);
  });
  await assert.rejects(() => api.verify({
    accessToken: token('aal1'), factorId: 'factor', challengeId: 'challenge', code: '123456'
  }), (error) => error.status === 403 && error.code === 'FORBIDDEN');
  await assert.rejects(() => api.refresh({ refreshToken: 'refresh-private-value-123456' }), (error) => error.status === 403 && error.code === 'FORBIDDEN');
});

test('rejeita endpoint Auth inseguro antes de enviar credenciais', () => {
  assert.throws(() => createSupabaseAdminSessionService({ authUrl: 'http://auth.example/auth/v1', anonKey: 'public', fetchImpl: async () => response(200, {}) }));
});

test('lista somente fatores verificados e exige AAL2 para adicionar outro', async () => {
  const existing = { id: factorId, factor_type: 'totp', status: 'verified', friendly_name: 'Principal' };
  const api = service(async (url) => {
    if (url.endsWith('/user')) return response(200, { ...admin, factors: [existing] });
    throw new Error('endpoint nao deveria ser chamado');
  });
  assert.deepEqual(await api.listFactors({ accessToken: token('aal1') }), {
    factors: [{ factorId, friendlyName: 'Principal' }]
  });
  await assert.rejects(() => api.enroll({ accessToken: token('aal1'), friendlyName: 'Segundo' }),
    (error) => error.status === 403 && error.code === 'FORBIDDEN');
});

test('limita fatores e remove enrollment abandonado antes de criar outro', async () => {
  const secondId = '44444444-4444-4444-8444-444444444444';
  const abandonedId = '55555555-5555-4555-8555-555555555555';
  const factors = [
    { id: factorId, factor_type: 'totp', status: 'verified' },
    { id: secondId, factor_type: 'totp', status: 'verified' }
  ];
  const limitedApi = service(async (url) => url.endsWith('/user') ? response(200, { ...admin, factors }) : response(200, admin));
  await assert.rejects(() => limitedApi.enroll({ accessToken: token(), friendlyName: 'Terceiro' }),
    (error) => error.status === 409 && error.code === 'MFA_FACTOR_LIMIT');

  const calls = [];
  const cleanupApi = service(async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/user')) return response(200, { ...admin, factors: [{ id: abandonedId, factor_type: 'totp', status: 'unverified' }] });
    if (url.endsWith(`/factors/${abandonedId}`)) return response(204);
    return response(200, { id: factorId, totp: { uri: 'otpauth://totp/test?secret=SAFE' } });
  });
  await cleanupApi.enroll({ accessToken: token('aal1'), friendlyName: 'Novo' });
  assert.equal(calls[1].options.method, 'DELETE');
  assert.ok(calls[2].url.endsWith('/factors'));
});

test('rejeita metadados e respostas MFA malformadas', async () => {
  const malformedFactors = service(async (url) => url.endsWith('/user') ? response(200, { ...admin, factors: {} }) : response(200, {}));
  await assert.rejects(() => malformedFactors.listFactors({ accessToken: token() }), (error) => error.code === 'AUTH_UNAVAILABLE');

  for (const factor of [{ id: 'bad', totp: { uri: 'otpauth://totp/x' } }, { id: factorId, totp: { uri: 'https://evil.example' } }]) {
    const api = service(async (url) => url.endsWith('/user') ? response(200, admin) : response(200, factor));
    await assert.rejects(() => api.enroll({ accessToken: token('aal1'), friendlyName: 'Novo' }), (error) => error.status === 503);
  }
  const badChallenge = service(async (url) => url.endsWith('/user') ? response(200, admin) : response(200, { id: 'not-a-uuid' }));
  await assert.rejects(() => badChallenge.challenge({ accessToken: token(), factorId }), (error) => error.code === 'AUTH_UNAVAILABLE');
});

test('valida configuração, lifetime e mapeia respostas upstream sem detalhes', async () => {
  assert.throws(() => createSupabaseAdminSessionService({ authUrl, anonKey: '', fetchImpl: async () => response(200, {}) }));
  assert.throws(() => createSupabaseAdminSessionService({ authUrl, anonKey: 'public', maxAccessTokenLifetime: 3601, fetchImpl: async () => response(200, {}) }));
  assert.throws(() => createSupabaseAdminSessionService({ authUrl, anonKey: 'public', maxTotpFactors: 0, fetchImpl: async () => response(200, {}) }));

  const tooLong = service(async () => response(200, {
    access_token: token('aal1'), refresh_token: 'refresh', expires_in: 3601
  }));
  await assert.rejects(() => tooLong.login({ email: 'a@b.c', password: 'x' }), (error) => error.code === 'AUTH_UNAVAILABLE');

  for (const [status, code] of [[429, 'RATE_LIMITED'], [422, 'AUTH_FLOW_ERROR']]) {
    const api = service(async () => response(status, { detail: 'private' }));
    await assert.rejects(() => api.logout({ accessToken: token() }), (error) => error.code === code && !error.message.includes('private'));
  }
  const invalidResponse = service(async () => ({}));
  await assert.rejects(() => invalidResponse.logout({ accessToken: token() }), (error) => error.code === 'AUTH_UNAVAILABLE');
  const invalidJson = service(async () => ({ ok: true, status: 200, json: async () => { throw new Error('private'); } }));
  await assert.rejects(() => invalidJson.listFactors({ accessToken: token() }), (error) => error.code === 'AUTH_UNAVAILABLE');
});

test('falha fechada quando validação pós-login ou pós-verify fica indisponível', async () => {
  const postLogin = service(async (url) => {
    if (url.includes('grant_type=password')) return response(200, { access_token: token('aal1'), refresh_token: 'refresh', expires_in: 3600 });
    return response(503, {});
  });
  await assert.rejects(() => postLogin.login({ email: 'a@b.c', password: 'x' }), (error) => error.code === 'AUTH_UNAVAILABLE');

  const postVerify = service(async (url) => {
    if (url.endsWith('/verify')) return response(200, { access_token: token(), refresh_token: 'refresh', expires_in: 3600 });
    throw new Error('auth unavailable');
  });
  await assert.rejects(() => postVerify.verify({ accessToken: token('aal1'), factorId, challengeId: factorId, code: '123456' }),
    (error) => error.code === 'AUTH_UNAVAILABLE');
});

test('exercita todas as guardas de configuração e formato de sessão', async () => {
  const base = { authUrl, anonKey: 'public', fetchImpl: async () => response(200, {}) };
  for (const override of [
    { anonKey: null }, { fetchImpl: null }, { maxAccessTokenLifetime: 59 },
    { maxAccessTokenLifetime: 60.5 }, { maxTotpFactors: 11 }, { maxTotpFactors: 1.5 }
  ]) assert.throws(() => createSupabaseAdminSessionService({ ...base, ...override }));

  const invalidSessions = [
    {}, { access_token: '', refresh_token: 'r', expires_in: 3600 },
    { access_token: 'a', refresh_token: null, expires_in: 3600 },
    { access_token: 'a', refresh_token: '', expires_in: 3600 },
    { access_token: 'a', refresh_token: 'r', expires_in: 1.5 },
    { access_token: 'a', refresh_token: 'r', expires_in: 0 }
  ];
  for (const payload of invalidSessions) {
    const api = service(async () => response(200, payload));
    await assert.rejects(() => api.login({ email: 'a@b.c', password: 'x' }), (error) => error.code === 'AUTH_UNAVAILABLE');
  }
});

test('mapeia 400 de login, 401 comum e 401 na validação da sessão pronta', async () => {
  await assert.rejects(() => service(async () => response(400, {})).login({ email: 'a@b.c', password: 'x' }),
    (error) => error.code === 'UNAUTHENTICATED');
  await assert.rejects(() => service(async () => response(401, {})).logout({ accessToken: token() }),
    (error) => error.code === 'UNAUTHENTICATED');
  const api = service(async (url) => {
    if (url.endsWith('/verify')) return response(200, { access_token: token(), refresh_token: 'r', expires_in: 3600 });
    return response(401, {});
  });
  await assert.rejects(() => api.verify({ accessToken: token('aal1'), factorId, challengeId: factorId, code: '123456' }),
    (error) => error.code === 'UNAUTHENTICATED');
});

test('normaliza variantes e rejeita cada campo inválido de fator', async () => {
  const alternate = { id: factorId, type: 'totp', status: 'verified', friendly_name: null };
  const api = service(async () => response(200, { ...admin, factors: [alternate] }));
  assert.deepEqual(await api.listFactors({ accessToken: token() }), { factors: [{ factorId, friendlyName: null }] });

  const badFactors = [
    null,
    { id: 'bad', factor_type: 'totp', status: 'verified' },
    { id: factorId, factor_type: 'phone', status: 'verified' },
    { id: factorId, factor_type: 'totp', status: 'bad' },
    { id: factorId, factor_type: 'totp', status: 'verified', friendly_name: 'x'.repeat(65) },
    { id: factorId, factor_type: 'totp', status: 'verified', friendly_name: 'bad\nname' }
  ];
  for (const factor of badFactors) {
    const malformed = service(async () => response(200, { ...admin, factors: [factor] }));
    if (factor?.friendly_name?.length > 64 || factor?.friendly_name?.includes('\n')) {
      assert.deepEqual(await malformed.listFactors({ accessToken: token() }), { factors: [{ factorId, friendlyName: null }] });
    } else {
      await assert.rejects(() => malformed.listFactors({ accessToken: token() }), (error) => error.code === 'AUTH_UNAVAILABLE');
    }
  }
});

test('cobre fatores ausentes e todas as negativas de URI TOTP', async () => {
  const noFactors = service(async () => response(200, { id: admin.id, email_confirmed_at: admin.email_confirmed_at, app_metadata: { role: 'admin' } }));
  assert.deepEqual(await noFactors.listFactors({ accessToken: token() }), { factors: [] });
  for (const totp of [{}, { uri: `otpauth://totp/${'x'.repeat(4090)}` }]) {
    const api = service(async (url) => url.endsWith('/user') ? response(200, admin) : response(200, { id: factorId, totp }));
    await assert.rejects(() => api.enroll({ accessToken: token('aal1'), friendlyName: 'App' }), (error) => error.code === 'AUTH_FACTOR_URI_INVALID');
  }
  for (const operation of ['enroll', 'challenge']) {
    const api = service(async (url) => url.endsWith('/user') ? response(200, admin) : response(200, null));
    await assert.rejects(() => operation === 'enroll'
      ? api.enroll({ accessToken: token('aal1'), friendlyName: 'App' })
      : api.challenge({ accessToken: token(), factorId }), (error) => error.status === 503);
  }
});

test('usa fetch global padrão sem alterar o contrato', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(204);
  try {
    const api = createSupabaseAdminSessionService({ authUrl, anonKey: 'public' });
    await api.logout({ accessToken: token() });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('resolve sujeito estável e confirma ownership do fator no Auth', async () => {
  const owned = { id: factorId, factor_type: 'totp', status: 'unverified' };
  const api = service(async () => response(200, { ...admin, factors: [owned] }));
  assert.equal(await api.resolveRateLimitSubject({ accessToken: token('aal1') }), admin.id);
  assert.equal(await api.resolveRateLimitSubject({ accessToken: token('aal1'), factorId }), admin.id);
  await assert.rejects(() => api.resolveRateLimitSubject({
    accessToken: token('aal1'), factorId: '44444444-4444-4444-8444-444444444444'
  }), (error) => error.status === 403 && error.code === 'FORBIDDEN');
  for (const user of [{ ...admin, id: 'not-a-uuid' }, { ...admin, id: undefined }]) {
    const invalidUser = service(async () => response(200, user));
    await assert.rejects(() => invalidUser.resolveRateLimitSubject({ accessToken: token('aal1') }),
      (error) => error.status === 503 && error.code === 'AUTH_UNAVAILABLE');
  }
});
