import { Readable } from 'node:stream';

function normalizePublicOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Origem publica invalida'); }
  const loopback = ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
  if (url.origin !== value || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new TypeError('Origem publica invalida');
  }
  return url.origin;
}

export function createNodeRequestListener({ handler, publicOrigin }) {
  if (typeof handler !== 'function') throw new TypeError('Handler HTTP invalido');
  const origin = normalizePublicOrigin(publicOrigin);

  return async function nodeRequestListener(request, response) {
    try {
      const method = request.method ?? 'GET';
      const requestTarget = request.url ?? '/';
      if (!requestTarget.startsWith('/') || requestTarget.startsWith('//')) throw new TypeError('Request target invalido');
      const requestUrl = new URL(requestTarget, origin);
      if (requestUrl.origin !== origin) throw new TypeError('Request target invalido');
      const body = method === 'GET' || method === 'HEAD' ? undefined : Readable.toWeb(request);
      const webResponse = await handler(new Request(requestUrl, {
        method,
        headers: request.headers,
        body,
        ...(body ? { duplex: 'half' } : {})
      }));
      response.statusCode = webResponse.status;
      for (const [name, value] of webResponse.headers) {
        if (name !== 'set-cookie') response.setHeader(name, value);
      }
      const cookies = webResponse.headers.getSetCookie();
      if (cookies.length > 0) response.setHeader('set-cookie', cookies);
      if (webResponse.body === null) return response.end();
      Readable.fromWeb(webResponse.body).pipe(response);
    } catch {
      if (!response.headersSent) {
        response.statusCode = 500;
        response.setHeader('content-type', 'application/json; charset=utf-8');
        response.setHeader('cache-control', 'no-store');
      }
      response.end(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'Erro interno' } }));
    }
  };
}
