const CACHE_NAME = 'galactic-static-v1';
const PRECACHE_URLS = [
  '/dist/sui-sdk-shell.iife.js',
  '/dist/sui-sdk-core.iife.js',
  '/dist/sui-sdk-transaction.iife.js',
  '/dist/sui-sdk-advanced.iife.js',
  '/assets/favicon-128.png',
  '/assets/vw-favicon.webp'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      const requests = PRECACHE_URLS.map(async (url) => {
        try {
          const response = await fetch(url, { credentials: 'same-origin' });
          if (response && response.ok) {
            await cache.put(url, response.clone());
          }
        } catch (error) {
          console.warn('SW preload skipped for', url, error);
        }
      });
      await Promise.allSettled(requests);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
          return undefined;
        })
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET' || event.request.url.startsWith('chrome-extension://')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(event.request);
    })
  );
});
