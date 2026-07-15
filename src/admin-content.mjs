import { createHash } from 'node:crypto';
import { normalizeYouTubeUrl } from './link-policy.mjs';
import { validateIdempotencyKey } from './request-validation.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const FIELDS = new Set(['title', 'description', 'speaker', 'theme', 'occurredAt', 'youtubeUrl']);

export class ContentError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'ContentError';
    this.status = status;
    this.code = code;
  }
}

const invalid = () => new ContentError(400, 'VALIDATION_ERROR', 'Solicitação inválida');
const forbidden = () => new ContentError(403, 'FORBIDDEN', 'Acesso negado');
const unavailable = () => new ContentError(503, 'DATA_UNAVAILABLE', 'Serviço de dados indisponível');

function text(value, max, optional = false) {
  if (optional && (value === undefined || value === null)) return null;
  if (typeof value !== 'string') throw invalid();
  const normalized = value.trim();
  if ((!optional && !normalized) || normalized.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized)) throw invalid();
  return optional && !normalized ? null : normalized;
}

function date(value) {
  if (typeof value !== 'string' || !DATE.test(value)) throw invalid();
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) throw invalid();
  return value;
}

export function normalizeCreateDraftInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).some((field) => !FIELDS.has(field))) throw invalid();
  let youtube;
  try { youtube = normalizeYouTubeUrl(input.youtubeUrl); } catch { throw invalid(); }
  const occurredAt = date(input.occurredAt);
  const draft = {
    slug: `hp365-${occurredAt}`,
    title: text(input.title, 160),
    description: text(input.description, 4_000, true),
    speaker: text(input.speaker, 160, true),
    theme: text(input.theme, 160, true),
    occurredAt,
    youtubeVideoId: youtube.videoId,
    youtubeUrl: youtube.url
  };
  return { draft, requestHash: createHash('sha256').update(JSON.stringify(draft)).digest('hex') };
}

export function createAdminContentService({ repository } = {}) {
  if (typeof repository?.createDraft !== 'function') throw new TypeError('Configuração de conteúdo inválida');
  return {
    async createDraft({ principal, input, idempotencyKey, requestId } = {}) {
      if (!principal || !UUID.test(principal.userId ?? '') || principal.role !== 'admin' || principal.aal !== 'aal2') throw forbidden();
      let key;
      try {
        key = validateIdempotencyKey(idempotencyKey);
        if (!UUID.test(requestId ?? '')) throw new TypeError();
      } catch { throw invalid(); }
      const { draft, requestHash } = normalizeCreateDraftInput(input);
      const result = await repository.createDraft({ actorUserId: principal.userId, key, requestHash, requestId, draft });
      if (result?.kind === 'conflict') throw new ContentError(409, 'IDEMPOTENCY_CONFLICT', 'Conflito de idempotência');
      if (result?.kind === 'content_conflict') throw new ContentError(409, 'CONTENT_CONFLICT', 'Conteúdo já existente');
      if (!['created', 'replayed'].includes(result?.kind) || result.status !== 201 || !result.body || typeof result.body !== 'object') throw unavailable();
      return result;
    }
  };
}
