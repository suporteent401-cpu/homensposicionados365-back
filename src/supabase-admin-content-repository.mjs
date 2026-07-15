import { ContentError } from './admin-content.mjs';

function normalizeUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Configuração de dados inválida'); }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (url.origin !== value || url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new TypeError('Configuração de dados inválida');
  }
  return value;
}

const unavailable = () => new ContentError(503, 'DATA_UNAVAILABLE', 'Serviço de dados indisponível');

export function createSupabaseAdminContentRepository({ supabaseUrl, serverKey, fetchImpl = globalThis.fetch } = {}) {
  const endpoint = `${normalizeUrl(supabaseUrl)}/rest/v1/rpc/create_devotional_draft`;
  if (typeof serverKey !== 'string' || !serverKey || serverKey.length > 8_192 || typeof fetchImpl !== 'function') {
    throw new TypeError('Configuração de dados inválida');
  }
  return {
    async createDraft({ actorUserId, key, requestHash, requestId, draft }) {
      let response;
      try {
        response = await fetchImpl(endpoint, {
          method: 'POST',
          headers: {
            apikey: serverKey, 'content-type': 'application/json',
            ...(!serverKey.startsWith('sb_secret_') ? { authorization: `Bearer ${serverKey}` } : {})
          },
          body: JSON.stringify({
            p_actor_user_id: actorUserId, p_key: key, p_request_hash: requestHash, p_request_id: requestId,
            p_slug: draft.slug, p_title: draft.title, p_description: draft.description, p_speaker: draft.speaker,
            p_theme: draft.theme, p_occurred_at: draft.occurredAt, p_youtube_video_id: draft.youtubeVideoId,
            p_youtube_url: draft.youtubeUrl
          }),
          signal: AbortSignal.timeout(5_000)
        });
      } catch { throw unavailable(); }
      if (!response?.ok) throw unavailable();
      let result;
      try { result = await response.json(); } catch { throw unavailable(); }
      if (result?.kind === 'conflict') return { kind: 'conflict' };
      if (result?.kind === 'content_conflict') return { kind: 'content_conflict' };
      if (!['created', 'replayed'].includes(result?.kind) || result.status !== 201 || !result.body || typeof result.body !== 'object') throw unavailable();
      return { kind: result.kind, status: 201, body: result.body };
    }
  };
}
