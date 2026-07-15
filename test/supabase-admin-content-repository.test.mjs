import test from 'node:test';
import assert from 'node:assert/strict';
import { createSupabaseAdminContentRepository } from '../src/supabase-admin-content-repository.mjs';

const args = {
  actorUserId: '11111111-1111-4111-8111-111111111111', key: '550e8400-e29b-41d4-a716-446655440000',
  requestHash: 'a'.repeat(64), requestId: '99999999-9999-4999-8999-999999999999',
  draft: { slug: 'hp365-2026-07-14', title: 'Teste', description: null, speaker: null, theme: null,
    occurredAt: '2026-07-14', youtubeVideoId: 'WuW3C2bFcHc', youtubeUrl: 'https://youtu.be/WuW3C2bFcHc' }
};

test('RPC usa fetch nativo e retorna envelope sanitizado', async () => {
  const calls = [];
  const repository = createSupabaseAdminContentRepository({
    supabaseUrl: 'http://127.0.0.1:54321', serverKey: 'local-test-key',
    fetchImpl: async (url, init) => { calls.push({ url, init }); return new Response(JSON.stringify({ kind: 'created', status: 201, body: { id: 'draft' } }), { status: 200 }); }
  });
  assert.deepEqual(await repository.createDraft(args), { kind: 'created', status: 201, body: { id: 'draft' } });
  assert.equal(calls[0].url, 'http://127.0.0.1:54321/rest/v1/rpc/create_devotional_draft');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers.apikey, 'local-test-key');
  assert.equal(calls[0].init.headers.authorization, 'Bearer local-test-key');
  assert.doesNotMatch(JSON.stringify(await repository.createDraft(args)), /local-test-key/);
});

test('aceita replay/conflito e falha fechado para endpoint/resposta/upstream inválidos', async () => {
  for (const envelope of [{ kind: 'replayed', status: 201, body: { id: 'same' } }, { kind: 'conflict' }, { kind: 'content_conflict' }]) {
    const repository = createSupabaseAdminContentRepository({ supabaseUrl: 'https://preview.supabase.co', serverKey: 'x'.repeat(32), fetchImpl: async () => new Response(JSON.stringify(envelope)) });
    assert.deepEqual(await repository.createDraft(args), envelope);
  }
  for (const config of [{}, { supabaseUrl: 'http://remote.example', serverKey: 'x' },
    { supabaseUrl: 'https://user@preview.supabase.co', serverKey: 'x' },
    { supabaseUrl: 'https://preview.supabase.co/path', serverKey: 'x' },
    { supabaseUrl: 'https://preview.supabase.co', serverKey: '' },
    { supabaseUrl: 'https://preview.supabase.co', serverKey: 'x'.repeat(8193) },
    { supabaseUrl: 'https://preview.supabase.co', serverKey: 'x', fetchImpl: null }]) {
    assert.throws(() => createSupabaseAdminContentRepository(config));
  }
  for (const fetchImpl of [async () => { throw new Error('secret'); }, async () => null,
    async () => new Response('bad', { status: 500 }), async () => new Response('not-json'), async () => new Response('{}'),
    async () => new Response(JSON.stringify({ kind: 'created', status: 200, body: {} })),
    async () => new Response(JSON.stringify({ kind: 'created', status: 201 })),
    async () => new Response(JSON.stringify({ kind: 'created', status: 201, body: 'bad' }))]) {
    const repository = createSupabaseAdminContentRepository({ supabaseUrl: 'https://preview.supabase.co', serverKey: 'x'.repeat(32), fetchImpl });
    await assert.rejects(() => repository.createDraft(args), (error) => error.code === 'DATA_UNAVAILABLE' && !/secret/i.test(error.message));
  }
});

test('usa fetch global padrão e aceita localhost local', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ kind: 'created', status: 201, body: { id: 'ok' } }));
  try {
    const repository = createSupabaseAdminContentRepository({ supabaseUrl: 'http://localhost:54321', serverKey: 'local' });
    assert.equal((await repository.createDraft(args)).body.id, 'ok');
  } finally { globalThis.fetch = original; }
});

test('chave secret moderna usa somente apikey e nunca é enviada como bearer JWT', async () => {
  let headers;
  const repository = createSupabaseAdminContentRepository({
    supabaseUrl: 'https://preview.supabase.co', serverKey: 'sb_secret_preview_only',
    fetchImpl: async (_url, init) => {
      headers = init.headers;
      return new Response(JSON.stringify({ kind: 'created', status: 201, body: { id: 'ok' } }));
    }
  });
  await repository.createDraft(args);
  assert.equal(headers.apikey, 'sb_secret_preview_only');
  assert.equal(headers.authorization, undefined);
});
