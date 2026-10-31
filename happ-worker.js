// Optional Happ delivery endpoint. GitHub Actions remains the only generator.
// Deploy this as a Cloudflare Worker and subscribe to https://<worker>/happ.
const RAW = 'https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/';

function base64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export default {
  async fetch(request) {
    if (new URL(request.url).pathname !== '/happ') {
      return new Response('Not found', { status: 404 });
    }

    const [subscription, routing] = await Promise.all([
      fetch(RAW + 'ru-karing-happ.txt'),
      fetch(RAW + 'russia-routing.json'),
    ]);
    if (!subscription.ok || !routing.ok) {
      return new Response('GitHub subscription is temporarily unavailable', { status: 503 });
    }

    let profile;
    try {
      profile = await routing.json();
      if (!profile.Name || !Array.isArray(profile.DirectSites)) throw new Error('routing profile');
    } catch {
      return new Response('Invalid routing profile', { status: 503 });
    }

    const headers = new Headers(subscription.headers);
    // A fetched body may have been decoded; don't forward upstream length or encoding.
    headers.delete('content-length');
    headers.delete('content-encoding');
    headers.set('content-type', 'application/json; charset=utf-8');
    headers.set('routing', 'happ://routing/onadd/' + base64Utf8(JSON.stringify(profile)));
    headers.set('cache-control', 'public, max-age=300');
    return new Response(subscription.body, { status: 200, headers });
  },
};
