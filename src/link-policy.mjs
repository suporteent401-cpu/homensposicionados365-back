const YOUTUBE_ID = /^[A-Za-z0-9_-]{11}$/;
const YOUTUBE_HOSTS = new Set(['youtu.be', 'www.youtube.com', 'youtube.com']);

function parseHttpsUrl(input) {
  if (typeof input !== 'string' || input.length > 2_048) throw new TypeError('URL inválida');
  let url;
  try { url = new URL(input); } catch { throw new TypeError('URL inválida'); }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) throw new TypeError('URL não permitida');
  return url;
}

function rejected() {
  throw new TypeError('URL não pertence a um host permitido');
}

export function normalizeYouTubeUrl(input) {
  const url = parseHttpsUrl(input);
  const host = url.hostname.toLowerCase();
  if (!YOUTUBE_HOSTS.has(host)) return rejected();

  let videoId;
  if (host === 'youtu.be' && /^\/[A-Za-z0-9_-]{11}$/.test(url.pathname) && !url.search && !url.hash) {
    videoId = url.pathname.slice(1);
  } else if ((host === 'youtube.com' || host === 'www.youtube.com') && url.pathname === '/watch' && url.searchParams.size === 1 && !url.hash) {
    videoId = url.searchParams.get('v');
  } else if ((host === 'youtube.com' || host === 'www.youtube.com') && /^\/embed\/[A-Za-z0-9_-]{11}$/.test(url.pathname) && !url.search && !url.hash) {
    videoId = url.pathname.slice('/embed/'.length);
  }

  if (!videoId || !YOUTUBE_ID.test(videoId)) return rejected();
  return { videoId, url: `https://youtu.be/${videoId}` };
}

export function normalizeTeamsUrl(input, allowedHosts) {
  if (!(allowedHosts instanceof Set) || allowedHosts.size === 0) throw new TypeError('Hosts Teams não configurados');
  const url = parseHttpsUrl(input);
  if (!allowedHosts.has(url.hostname.toLowerCase())) return rejected();
  return url.href;
}
