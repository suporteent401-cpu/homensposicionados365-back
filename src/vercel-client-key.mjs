import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

export function decodeHmacKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43,}$/.test(value)) throw new TypeError('Configuração HMAC inválida');
  const key = Buffer.from(value, 'base64url');
  if (key.length < 32 || key.toString('base64url') !== value) throw new TypeError('Configuração HMAC inválida');
  return key;
}

export function createVercelClientKey({ hmacKey }) {
  const key = decodeHmacKey(hmacKey);
  return function getVercelClientKey(request) {
    const ip = request?.headers?.get('x-vercel-forwarded-for');
    const version = typeof ip === 'string' ? isIP(ip) : 0;
    if (typeof ip !== 'string' || ip.trim() !== ip || ip.includes(',') || ip.includes('%') || version === 0) {
      throw new TypeError('IP de borda inválido');
    }
    const canonicalIp = version === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip;
    return `ip:${createHmac('sha256', key).update('hp365\0ip\0').update(canonicalIp).digest('base64url')}`;
  };
}
