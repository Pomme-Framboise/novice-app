// Service worker : garde l'appli en mémoire pour qu'elle s'ouvre comme une
// vraie appli, même avec un réseau faible. Tout est demandé au réseau
// d'abord (jamais un vieux soir ni une vieille version), la mémoire ne sert
// que hors connexion.
const VERSION = "novice-v1";
const COQUILLE = ["./", "index.html", "app.css", "app.js", "manifest.json",
                  "icone-192.png", "icone-512.png", "apple-touch-icon.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(COQUILLE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys()
    .then(cles => Promise.all(cles.filter(k => k !== VERSION).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  e.respondWith(fetch(e.request, {cache: "no-store"}).then(r => {
    if (r.ok) {
      const copie = r.clone();
      caches.open(VERSION).then(c => c.put(e.request, copie));
    }
    return r;
  }).catch(() => caches.match(e.request)));
});
