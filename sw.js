// Offline cache. BUILD changes on every build, so a new deploy installs a fresh cache and
// the page offers a reload. Everything is served cache-first; nothing needs the network.
const BUILD = 'c83dcb3f0d';
const CACHE = `learning-lab-${BUILD}`;
const FILES = [
  './',
  'index.html',
  `app.js?v=${BUILD}`,
  `styles.css?v=${BUILD}`,
  'content.json',
  'manifest.webmanifest',
  'icons/icon-180.png',
  'icons/icon-192.png',
  'icons/icon-512.png',
];

self.addEventListener('install', event => {
  // cache: 'reload' bypasses the HTTP cache so a new build never mixes in stale files.
  event.waitUntil(caches.open(CACHE).then(cache =>
    cache.addAll(FILES.map(f => new Request(f, { cache: 'reload' })))));
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});

self.addEventListener('message', event => {
  if (event.data === 'skipWaiting') self.skipWaiting();
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    if (req.mode === 'navigate') return (await cache.match('index.html')) || fetch(req);
    return (await cache.match(req)) || fetch(req);
  })());
});
