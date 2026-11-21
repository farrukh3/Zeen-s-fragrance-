// Zeen Admin service worker: koi data cache nahi hota. Sirf internet na ho to offline page dikhata hai.
const OFFLINE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fbf7ee;color:#2b2416;font:16px system-ui,sans-serif;text-align:center;padding:24px}.b{max-width:320px}.z{width:72px;height:72px;margin:0 auto 18px;border-radius:20px;background:linear-gradient(#d9b25a,#aa781e);color:#fffaf0;font:700 40px/72px Georgia,serif}button{margin-top:18px;background:#b88a2a;color:#fff;border:0;border-radius:12px;padding:12px 26px;font:600 15px system-ui}</style></head><body><div class="b"><div class="z">Z</div><h2>Internet nahi hai</h2><p style="color:#7c705a">Admin panel chalane ke liye internet chahiye. Connection check karke dobara try karo.</p><button onclick="location.reload()">Dobara try karo</button></div></body></html>';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(k => Promise.all(k.map(x => caches.delete(x)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  if (e.request.mode !== 'navigate') return; // API aur baaki sab seedha network se
  e.respondWith(fetch(e.request).catch(() => new Response(OFFLINE, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
});
