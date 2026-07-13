const CURSOR = /^[A-Za-z0-9_-]{1,256}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LIMIT = /^(?:[1-9]|[1-4][0-9]|50)$/;

export function parsePagination(searchParams) {
  if (!(searchParams instanceof URLSearchParams)) throw new TypeError('Query inválida');
  if (searchParams.getAll('limit').length > 1 || searchParams.getAll('cursor').length > 1) throw new TypeError('Query ambígua');
  const rawLimit = searchParams.get('limit');
  if (rawLimit !== null && !LIMIT.test(rawLimit)) throw new RangeError('Limit inválido');
  const cursor = searchParams.get('cursor');
  if (cursor !== null && !CURSOR.test(cursor)) throw new TypeError('Cursor inválido');
  return { limit: rawLimit === null ? 20 : Number(rawLimit), cursor };
}

export function validateIdempotencyKey(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Idempotency-Key inválida');
  return value.toLowerCase();
}
