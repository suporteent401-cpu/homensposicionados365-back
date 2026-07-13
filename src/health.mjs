const BODY = JSON.stringify({ status: 'ok' });

/**
 * Handler sem dependências para o health check público.
 * Não lê ambiente, banco ou versão para não vazar informação operacional.
 */
export function healthResponse() {
  return {
    status: 200,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff'
    },
    body: BODY
  };
}
