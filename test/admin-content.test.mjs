import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ContentError,
  createAdminContentService,
  normalizeCreateDraftInput
} from '../src/admin-content.mjs';

const principal = { userId: '11111111-1111-4111-8111-111111111111', role: 'admin', aal: 'aal2' };
const idempotencyKey = '550e8400-e29b-41d4-a716-446655440000';
const requestId = '99999999-9999-4999-8999-999999999999';
const input = {
  title: ' Devocional de teste ',
  description: ' Texto ',
  speaker: null,
  theme: ' Fé ',
  occurredAt: '2026-07-14',
  youtubeUrl: 'https://www.youtube.com/watch?v=WuW3C2bFcHc'
};

test('normaliza DTO, deriva slug e produz hash estável sem aceitar campos server-side', () => {
  const first = normalizeCreateDraftInput(input);
  const second = normalizeCreateDraftInput({ ...input, youtubeUrl: 'https://youtu.be/WuW3C2bFcHc' });
  assert.deepEqual(first.draft, {
    slug: 'hp365-2026-07-14', title: 'Devocional de teste', description: 'Texto', speaker: null,
    theme: 'Fé', occurredAt: '2026-07-14', youtubeVideoId: 'WuW3C2bFcHc', youtubeUrl: 'https://youtu.be/WuW3C2bFcHc'
  });
  assert.match(first.requestHash, /^[a-f0-9]{64}$/);
  assert.equal(first.requestHash, second.requestHash);
  assert.throws(() => normalizeCreateDraftInput({ ...input, status: 'published' }), /Solicitação inválida/);
});

test('rejeita tipos, datas, textos e URLs inválidos', () => {
  for (const value of [null, [], 'string', {}, { ...input, title: null }, { ...input, title: ' ' }, { ...input, title: 'x'.repeat(161) },
    { ...input, title: 'controle\u0001' }, { ...input, description: 1 },
    { ...input, description: 'x'.repeat(4001) }, { ...input, speaker: 'x'.repeat(161) },
    { ...input, theme: 'x'.repeat(161) }, { ...input, occurredAt: null }, { ...input, occurredAt: '9999-99-99' },
    { ...input, occurredAt: '2026-02-30' },
    { ...input, youtubeUrl: 'https://evil.example/video' }]) {
    assert.throws(() => normalizeCreateDraftInput(value));
  }
  assert.equal(normalizeCreateDraftInput({ ...input, description: ' ', speaker: undefined, theme: null }).draft.description, null);
});

test('service envia somente principal confirmado e valores canonicalizados ao repositório', async () => {
  const calls = [];
  const body = { id: '22222222-2222-4222-8222-222222222222', status: 'draft' };
  const service = createAdminContentService({ repository: { createDraft: async (value) => { calls.push(value); return { kind: 'created', status: 201, body }; } } });
  assert.deepEqual(await service.createDraft({ principal, input, idempotencyKey, requestId }), { kind: 'created', status: 201, body });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].actorUserId, principal.userId);
  assert.equal(calls[0].key, idempotencyKey);
  assert.equal(calls[0].requestId, requestId);
  assert.equal(calls[0].draft.status, undefined);
  assert.doesNotMatch(JSON.stringify(calls[0]), /Bearer|password|token/i);
});

test('service nega principal/IDs inválidos e traduz conflitos sem detalhe de persistência', async () => {
  const repository = { createDraft: async () => ({ kind: 'conflict' }) };
  const service = createAdminContentService({ repository });
  for (const value of [{ ...principal, role: 'user' }, { ...principal, aal: 'aal1' }, { ...principal, userId: 'bad' }, { role: 'admin', aal: 'aal2' }]) {
    await assert.rejects(() => service.createDraft({ principal: value, input, idempotencyKey, requestId }), (error) => error instanceof ContentError && error.code === 'FORBIDDEN');
  }
  await assert.rejects(() => service.createDraft({ principal, input, idempotencyKey: 'bad', requestId }), (error) => error.code === 'VALIDATION_ERROR');
  await assert.rejects(() => service.createDraft({ principal, input, idempotencyKey, requestId: 'bad' }), (error) => error.code === 'VALIDATION_ERROR');
  await assert.rejects(() => service.createDraft({ principal, input, idempotencyKey }), (error) => error.code === 'VALIDATION_ERROR');
  await assert.rejects(() => service.createDraft({ principal, input, idempotencyKey, requestId }), (error) => error.code === 'IDEMPOTENCY_CONFLICT' && !/sql|database/i.test(error.message));
});

test('service valida configuração e resposta interna do repositório', async () => {
  assert.throws(() => createAdminContentService({}));
  const contentConflict = createAdminContentService({ repository: { createDraft: async () => ({ kind: 'content_conflict' }) } });
  await assert.rejects(() => contentConflict.createDraft({ principal, input, idempotencyKey, requestId }), (error) => error.code === 'CONTENT_CONFLICT');
  for (const result of [null, { kind: 'unknown' }, { kind: 'created', status: 200, body: {} },
    { kind: 'created', status: 201 }, { kind: 'created', status: 201, body: 'bad' }]) {
    const service = createAdminContentService({ repository: { createDraft: async () => result } });
    await assert.rejects(() => service.createDraft({ principal, input, idempotencyKey, requestId }), (error) => error.code === 'DATA_UNAVAILABLE');
  }
  await assert.rejects(() => createAdminContentService({ repository: { createDraft: async () => ({}) } }).createDraft(), (error) => error.code === 'FORBIDDEN');
});
