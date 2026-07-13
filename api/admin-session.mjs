import { createVercelAdminSessionApp } from '../src/vercel-admin-session-app.mjs';

function unavailable() {
  return Response.json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Serviço indisponível' } }, {
    status: 503,
    headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
  });
}

export function createEntrypoint({ env, createApp = createVercelAdminSessionApp }) {
  let app;
  return {
    async fetch(request) {
      try {
        app ??= createApp({ env });
        return await app.fetch(request);
      } catch {
        return unavailable();
      }
    }
  };
}

export default createEntrypoint({ env: process.env });
