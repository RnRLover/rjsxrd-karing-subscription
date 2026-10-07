import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('./happ-worker.js', import.meta.url), 'utf8');
const worker = (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).default;
const profile = { Name: 'Россия', DirectSites: ['geosite:category-ru'] };
const payload = '[{"remarks":"Основной","outbounds":[]}]\n';
globalThis.fetch = async url => new Response(url.endsWith('.txt') ? payload : JSON.stringify(profile));
const result = await worker.fetch(new Request('https://example.workers.dev/happ'));
assert.equal(result.status, 200);
assert.equal(await result.text(), payload);
const routing = result.headers.get('routing');
assert.ok(routing.startsWith('happ://routing/onadd/'));
assert.deepEqual(JSON.parse(Buffer.from(routing.split('/').at(-1), 'base64').toString('utf8')), profile);
assert.equal((await worker.fetch(new Request('https://example.workers.dev/else'))).status, 404);
console.log('Happ worker preserves JSON body and attaches routing header');
