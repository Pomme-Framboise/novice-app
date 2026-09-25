// Service worker : garde l'appli en mémoire pour qu'elle s'ouvre comme une
// vraie appli, même avec un réseau faible. Tout est demandé au réseau
// d'abord (jamais un vieux soir ni une vieille version), la mémoire ne sert
// que hors connexion.
const VERSION = "novice-v2";
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

// Notifications envoyées par le robot (moteur/alertes.py). Le contenu arrive
// chiffré pour ce téléphone ; on l'affiche tel quel.
self.addEventListener("push", e => {
  let n = {};
  try { n = e.data ? e.data.json() : {}; } catch (x) { n = {titre: "Novice", texte: e.data ? e.data.text() : ""}; }
  e.waitUntil(self.registration.showNotification(n.titre || "Novice", {
    body: n.texte || "", tag: n.tag || undefined, icon: "icone-192.png", badge: "icone-192.png",
    data: {url: n.url || "./"}}));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type: "window", includeUncontrolled: true}).then(fenetres => {
    const f = fenetres.find(c => "focus" in c);
    return f ? f.focus() : self.clients.openWindow((e.notification.data || {}).url || "./");
  }));
});
