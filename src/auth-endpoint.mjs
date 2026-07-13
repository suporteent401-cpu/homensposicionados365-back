export function normalizeSupabaseAuthUrl(authUrl, expectedIssuer = authUrl) {
  if (typeof authUrl !== 'string' || typeof expectedIssuer !== 'string') throw new TypeError('Configuração de autenticação inválida');
  let url;
  try { url = new URL(authUrl); } catch { throw new TypeError('Configuração de autenticação inválida'); }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  const safeTransport = url.protocol === 'https:' || (url.protocol === 'http:' && loopback);
  if (!safeTransport || url.username || url.password || url.search || url.hash) {
    throw new TypeError('Configuração de autenticação inválida');
  }
  const normalized = url.href.replace(/\/$/, '');
  if (url.pathname.replace(/\/$/, '') !== '/auth/v1' || normalized !== expectedIssuer.replace(/\/$/, '')) {
    throw new TypeError('Configuração de autenticação inválida');
  }
  return normalized;
}
