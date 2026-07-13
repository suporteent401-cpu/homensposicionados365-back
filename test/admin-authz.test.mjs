import test from 'node:test';
import assert from 'node:assert/strict';
import { createSupabaseAdminAuthorizer } from '../src/admin-authz.mjs';

const issuer = 'http://127.0.0.1:54321/auth/v1';
const user = { id: '11111111-1111-4111-8111-111111111111', email_confirmed_at: '2026-07-13T00:00:00Z', app_metadata: { role: 'admin' } };

function token(claims = {}) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    sub: user.id,
    iss: issuer,
    aud: 'authenticated',
    exp: 2_000_000_000,
    aal: 'aal2',
    amr: [{ method: 'password' }, { method: 'totp' }],
    ...claims
  })}.test-signature`;
}

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function authorizer({ authUser = user, status = 200, fetchImpl } = {}) {
  return createSupabaseAdminAuthorizer({
    authUrl: issuer,
    anonKey: 'local-public-key-for-test',
    expectedIssuer: issuer,
    expectedAudience: 'authenticated',
    now: () => 1_900_000_000,
    fetchImpl: fetchImpl ?? (async () => response(authUser, status))
  });
}

async function rejectsWith(auth, authorization, status, code) {
  await assert.rejects(() => auth(authorization), (error) => {
    assert.equal(error.status, status);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /token|jwt|secret|key/i);
    return true;
  });
}

test('rejeita token ausente ou malformado sem consultar Auth', async () => {
  let calls = 0;
  const auth = authorizer({ fetchImpl: async () => { calls += 1; return response(user); } });
  for (const header of [undefined, '', 'Basic abc', 'Bearer', 'Bearer a.b', 'Bearer a.b.c extra']) {
    await rejectsWith(auth, header, 401, 'UNAUTHENTICATED');
  }
  assert.equal(calls, 0);
});

test('rejeita token não aceito pelo Supabase Auth', async () => {
  await rejectsWith(authorizer({ status: 401 }), `Bearer ${token()}`, 401, 'UNAUTHENTICATED');
});

test('rejeita configuração que poderia enviar bearer a endpoint inseguro ou divergente', () => {
  const base = {
    anonKey: 'local-public-key-for-test',
    expectedIssuer: issuer,
    fetchImpl: async () => response(user)
  };
  assert.throws(() => createSupabaseAdminAuthorizer({ ...base, authUrl: 'http://auth.example/auth/v1' }));
  assert.throws(() => createSupabaseAdminAuthorizer({ ...base, authUrl: 'https://auth.example/auth/v1' }));
  assert.throws(() => createSupabaseAdminAuthorizer({ ...base, authUrl: 'http://user:pass@127.0.0.1:54321/auth/v1' }));
});

test('rejeita token expirado ou com issuer/audience inválido', async () => {
  const auth = authorizer();
  for (const claims of [
    { exp: 1_899_999_999 },
    { iss: 'https://issuer.invalid/auth/v1' },
    { aud: 'anon' }
  ]) {
    await rejectsWith(auth, `Bearer ${token(claims)}`, 401, 'UNAUTHENTICATED');
  }
});

test('rejeita usuário sem papel admin verificado no Auth', async () => {
  const auth = authorizer({ authUser: { ...user, app_metadata: {} } });
  await rejectsWith(auth, `Bearer ${token()}`, 403, 'FORBIDDEN');
});

test('rejeita administrador sem e-mail confirmado', async () => {
  await rejectsWith(authorizer({ authUser: { ...user, email_confirmed_at: null } }), `Bearer ${token()}`, 403, 'FORBIDDEN');
});

test('rejeita sessão sem AAL2 ou sem método TOTP', async () => {
  const auth = authorizer();
  await rejectsWith(auth, `Bearer ${token({ aal: 'aal1', amr: [{ method: 'password' }] })}`, 403, 'FORBIDDEN');
  await rejectsWith(auth, `Bearer ${token({ amr: [{ method: 'password' }] })}`, 403, 'FORBIDDEN');
});

test('autoriza sessão admin com AAL2 e TOTP sem devolver credenciais', async () => {
  const principal = await authorizer()(`Bearer ${token()}`);
  assert.deepEqual(principal, { userId: user.id, role: 'admin', aal: 'aal2' });
});

test('falha fechada e segura quando o Auth fica indisponível', async () => {
  const auth = authorizer({ fetchImpl: async () => { throw new Error('upstream leaked detail'); } });
  await rejectsWith(auth, `Bearer ${token()}`, 503, 'AUTH_UNAVAILABLE');
});

test('rejeita resposta Auth inválida ou de outra identidade', async () => {
  const invalidJson = authorizer({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => { throw new Error('invalid'); } }) });
  await rejectsWith(invalidJson, `Bearer ${token()}`, 503, 'AUTH_UNAVAILABLE');
  const otherUser = authorizer({ authUser: { ...user, id: '22222222-2222-4222-8222-222222222222' } });
  await rejectsWith(otherUser, `Bearer ${token()}`, 401, 'UNAUTHENTICATED');
});

test('rejeita payload JWT indecodificável e configuração incompleta', async () => {
  for (const config of [
    { authUrl: null, anonKey: 'key', expectedIssuer: issuer },
    { authUrl: issuer, anonKey: null, expectedIssuer: issuer },
    { authUrl: issuer, anonKey: '', expectedIssuer: issuer },
    { authUrl: issuer, anonKey: 'key', expectedIssuer: null },
    { authUrl: issuer, anonKey: 'key', expectedIssuer: issuer, fetchImpl: null },
    { authUrl: issuer, anonKey: 'key', expectedIssuer: issuer, now: null }
  ]) assert.throws(() => createSupabaseAdminAuthorizer(config));
  const authorize = authorizer();
  await assert.rejects(() => authorize('Bearer aaa.aaa.aaa'), (error) => error.status === 401);
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  await assert.rejects(() => authorize(`Bearer ${encode({})}.${encode([])}.signature`), (error) => error.status === 401);
});

test('exercita formas alternativas de audience, identidade e resposta Auth', async () => {
  assert.deepEqual(await authorizer()(`Bearer ${token({ aud: ['other', 'authenticated'] })}`), {
    userId: user.id, role: 'admin', aal: 'aal2'
  });
  for (const claims of [
    { aud: ['other'] }, { sub: null }, { sub: '' }
  ]) await rejectsWith(authorizer(), `Bearer ${token(claims)}`, 401, 'UNAUTHENTICATED');
  for (const fetchImpl of [async () => null, async () => ({ ok: 'yes' })]) {
    await rejectsWith(authorizer({ fetchImpl }), `Bearer ${token()}`, 503, 'AUTH_UNAVAILABLE');
  }
  await rejectsWith(authorizer({ fetchImpl: async () => response({}, 503) }), `Bearer ${token()}`, 503, 'AUTH_UNAVAILABLE');
  await rejectsWith(authorizer(), `Bearer ${token({ exp: 1_800_000_000 })}`, 401, 'UNAUTHENTICATED');
  assert.deepEqual(await authorizer()(`Bearer ${token({ amr: [null, { method: 'totp' }] })}`), {
    userId: user.id, role: 'admin', aal: 'aal2'
  });
});

test('usa defaults seguros de audience, fetch e relógio', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(user);
  try {
    const auth = createSupabaseAdminAuthorizer({ authUrl: issuer, anonKey: 'key', expectedIssuer: issuer });
    assert.deepEqual(await auth(`Bearer ${token()}`), { userId: user.id, role: 'admin', aal: 'aal2' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
