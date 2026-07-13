import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeYouTubeUrl, normalizeTeamsUrl } from '../src/link-policy.mjs';

test('normaliza URLs YouTube aprovadas para o formato canônico', () => {
  assert.deepEqual(normalizeYouTubeUrl('https://youtu.be/WuW3C2bFcHc'), {
    videoId: 'WuW3C2bFcHc', url: 'https://youtu.be/WuW3C2bFcHc'
  });
  assert.deepEqual(normalizeYouTubeUrl('https://www.youtube.com/watch?v=WuW3C2bFcHc'), {
    videoId: 'WuW3C2bFcHc', url: 'https://youtu.be/WuW3C2bFcHc'
  });
});

test('rejeita URL não aprovada, credencial na URL e ID inválido', () => {
  for (const input of ['http://youtu.be/WuW3C2bFcHc', 'https://youtube.example/WuW3C2bFcHc', 'https://user:pass@youtu.be/WuW3C2bFcHc', 'https://youtu.be/curto']) {
    assert.throws(() => normalizeYouTubeUrl(input));
  }
});

test('Teams exige host explicitamente aprovado', () => {
  assert.equal(normalizeTeamsUrl('https://teams.microsoft.com/l/meetup-join/abc', new Set(['teams.microsoft.com'])), 'https://teams.microsoft.com/l/meetup-join/abc');
  assert.throws(() => normalizeTeamsUrl('https://teams.evil.example/l/meetup-join/abc', new Set(['teams.microsoft.com'])));
});
