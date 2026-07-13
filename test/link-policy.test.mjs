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

test('normaliza URL embed do YouTube sem query ou fragmento', () => {
  assert.deepEqual(normalizeYouTubeUrl('https://www.youtube.com/embed/AbCdEf123_-'), {
    videoId: 'AbCdEf123_-', url: 'https://youtu.be/AbCdEf123_-'
  });
});

test('exercita guardas de transporte, formato e configuração de links', () => {
  for (const value of [null, 'x'.repeat(2049), 'not a url', 'http://youtu.be/AbCdEf123_-',
    'https://user@youtu.be/AbCdEf123_-', 'https://user:pass@youtu.be/AbCdEf123_-',
    'https://youtu.be:444/AbCdEf123_-', 'https://evil.example/AbCdEf123_-',
    'https://youtu.be/AbCdEf123_-?x=1', 'https://youtube.com/watch?v=AbCdEf123_-&x=1',
    'https://youtube.com/embed/AbCdEf123_-#x']) {
    assert.throws(() => normalizeYouTubeUrl(value));
  }
  assert.throws(() => normalizeTeamsUrl('https://teams.example/path'));
  assert.throws(() => normalizeTeamsUrl('https://teams.example/path', new Set()));
  assert.throws(() => normalizeTeamsUrl('https://evil.example/path', new Set(['teams.example'])));
});
