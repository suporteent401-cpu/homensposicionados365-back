import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { createNodeRequestListener } from '../src/node-http-adapter.mjs';

test('adapta Request/Response por socket sem confiar no Host e preserva cookies', async () => {
  let seen;
  const listener = createNodeRequestListener({
    publicOrigin: 'http://127.0.0.1:54330',
    handler: async (request) => {
      seen = { url: request.url, method: request.method, body: await request.text() };
      const headers = new Headers({ 'content-type': 'application/json' });
      headers.append('set-cookie', 'first=1; HttpOnly');
      headers.append('set-cookie', 'second=2; HttpOnly');
      return new Response('{"ok":true}', { status: 201, headers });
    }
  });
  const server = createServer(listener);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/route`, {
      method: 'POST', headers: { host: 'evil.example', 'content-type': 'text/plain' }, body: 'safe'
    });
    assert.equal(response.status, 201);
    assert.deepEqual(await response.json(), { ok: true });
    assert.deepEqual(seen, { url: 'http://127.0.0.1:54330/route', method: 'POST', body: 'safe' });
    assert.equal(response.headers.getSetCookie().length, 2);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('falha fechada no adaptador sem propagar detalhe', async () => {
  assert.throws(() => createNodeRequestListener({ handler: () => undefined, publicOrigin: 'http://api.example' }));
  const server = createServer(createNodeRequestListener({
    publicOrigin: 'http://127.0.0.1:54330', handler: async () => { throw new Error('private'); }
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/failure`);
    assert.equal(response.status, 500);
    assert.doesNotMatch(await response.text(), /private/);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('rejeita request-target absoluta ou network-path', async () => {
  let calls = 0;
  const server = createServer(createNodeRequestListener({
    publicOrigin: 'http://127.0.0.1:54330', handler: async () => { calls += 1; return new Response(null, { status: 204 }); }
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    for (const path of ['http://evil.example/route', '//evil.example/route']) {
      const status = await new Promise((resolve, reject) => {
        const request = httpRequest({ hostname: '127.0.0.1', port: server.address().port, method: 'GET', path }, (response) => {
          response.resume();
          response.on('end', () => resolve(response.statusCode));
        });
        request.on('error', reject);
        request.end();
      });
      assert.equal(status, 500);
    }
    assert.equal(calls, 0);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('valida configuração/origem e cobre resposta vazia e falha após headers', async () => {
  for (const value of ['invalid', 'http://api.example', 'http://127.0.0.1:54330/', 'ftp://127.0.0.1']) {
    assert.throws(() => createNodeRequestListener({ handler: async () => new Response(), publicOrigin: value }));
  }
  assert.throws(() => createNodeRequestListener({ handler: null, publicOrigin: 'https://api.example' }));
  const listener = createNodeRequestListener({ handler: async () => new Response(null, { status: 204 }), publicOrigin: 'https://api.example' });
  let ended = false;
  const response = {
    headersSent: false, statusCode: 0,
    setHeader: () => undefined,
    end: () => { ended = true; }
  };
  await listener({ method: 'HEAD', url: '/', headers: {} }, response);
  assert.equal(response.statusCode, 204);
  assert.equal(ended, true);

  ended = false;
  await listener({ headers: {} }, response);
  assert.equal(ended, true);

  let closed = false;
  await listener({ method: 'GET', url: '//evil.example', headers: {} }, {
    headersSent: true, statusCode: 200, setHeader: () => { throw new Error('must not set'); },
    end: () => { closed = true; }
  });
  assert.equal(closed, true);
  await listener({ method: 'GET', url: '/\\evil.example/path', headers: {} }, {
    headersSent: false, statusCode: 0, setHeader: () => undefined, end: () => undefined
  });
});
