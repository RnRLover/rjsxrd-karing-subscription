import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const source = readFileSync('happ-worker.js', 'utf8');
const worker = (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).default;
const fixtureResult = spawnSync('python', ['-c', `
import json
from pathlib import Path
from subscription_delivery import bundle
print(json.dumps(bundle(json.loads(Path('subscription.json').read_bytes()), json.loads(Path('russia-routing.json').read_bytes()), {'geoip.dat':b'ip', 'geosite.dat':b'site'}, now=100)))
`], {encoding:'utf8'});
assert.equal(fixtureResult.status, 0, fixtureResult.stderr);
const bundle = JSON.parse(fixtureResult.stdout);
const originalFetch = globalThis.fetch;

async function call(fetcher, path='/happ') {
  globalThis.fetch = fetcher;
  try {return await worker.fetch(new Request('https://example.workers.dev'+path));}
  finally {globalThis.fetch = originalFetch;}
}

test('existing deployed worker supplies pure JSON and automatic geofile profile', async () => {
  const urls=[];
  const response = await call(async url => {
    urls.push(url);
    if (url.endsWith('russia-routing.json')) return Response.json(bundle.profile);
    return new Response(JSON.stringify(bundle.configs), {headers:{'content-length':'999999', 'content-encoding':'gzip'}});
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), bundle.configs);
  const header = response.headers.get('routing');
  assert.ok(header.startsWith('happ://routing/onadd/'));
  const profile = JSON.parse(Buffer.from(header.split('/').at(-1),'base64').toString('utf8'));
  assert.deepEqual(profile, bundle.profile);
  assert.ok(urls.some(u=>u.endsWith('ru-karing-happ.txt')));
  assert.ok(urls.some(u=>u.endsWith('russia-routing.json')));
  assert.equal(response.headers.get('content-length'),null);
  assert.equal(response.headers.get('content-encoding'),null);
});

test('missing source file fails rather than returning a subscription without metadata', async () => {
  const response = await call(async () => new Response('missing',{status:404}));
  assert.equal(response.status,503);
});

test('malformed profile cannot become a successful bootstrap response', async () => {
  const response = await call(async url => url.endsWith('russia-routing.json') ? Response.json({DirectSites:[]}) : Response.json(bundle.configs));
  assert.equal(response.status,503);
});

test('unrecognized endpoint does not read upstream', async () => {
  const response = await call(async()=>{throw Error('unexpected fetch');},'/unknown');
  assert.equal(response.status,404);
});
