/* Novice : l'appli.
 *
 * 1. Connexion : la phrase de passe dérive une clé (PBKDF2-SHA256, 600 000
 *    tours), qui déchiffre donnees.json (AES-256-GCM) dans le navigateur.
 *    La phrase ne quitte jamais le téléphone. « Rester connecté » garde la
 *    clé 30 jours dans ce navigateur (IndexedDB), sous une forme qu'aucun
 *    script ne peut relire.
 * 2. Affichage : cinq onglets (Accueil, Novice, Marchés, Mes actions, Labo)
 *    construits à partir du paquet de données du soir.
 *
 * Tout texte venant des données (actus, lectures de Claude) passe par esc() :
 * il n'est jamais interprété comme du code.
 */
"use strict";

const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const JOUR_MS = 86400000;
const CAPITAL = 300;
let D = null;          // le paquet de données déchiffré
let CLE = null;        // la clé tirée du mot de passe, en mémoire le temps de la session

// ------------------------------------------------------------------ outils
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const lien = u => /^https?:\/\//i.test(u || "") ? esc(u) : "#";
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const nb = (v, d = 1) => v == null || isNaN(v) ? "—" : Number(v).toFixed(d).replace(".", ",");
const pct = (v, d = 1) => v == null || isNaN(v) ? "—" : (v > 0 ? "+" : "") + nb(v, d) + " %";
const eur = (v, d = 0) => v == null || isNaN(v) ? "—" : (v > 0 ? "+" : "") + nb(v, d) + " €";
const classe = v => v > 0 ? "up" : v < 0 ? "down" : "";
const dateFr = s => { if (!s) return "—"; const [a, m, j] = s.slice(0, 10).split("-"); return `${j}/${m}`; };
const MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
const JOURS = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"];
const dateLongue = d => `${JOURS[d.getDay()]} ${d.getDate()} ${MOIS[d.getMonth()]}`;
const NOMS = {novice: "Novice", calc: "Calculateur de hausse", calc10: "Calculateur, vente à +10 %", n1: "N°1 du scan", tech: "Top 10 technique seul",
              v15: "Vente à +15 %", hasard: "Hasard", indice: "Indice", ana: "Filtre analystes 30 j", presse: "Filtre presse euphorique"};
const COULEURS = {calc: "#5B8DEF", calc10: "#9DB7F2", ana: "#C98BB9", presse: "#7FA36B", n1: "#2BA39B", tech: "#8E6BD8", v15: "#E07A5F", hasard: "--grey", indice: "--dash"};
const TEMOINS = ["hasard", "indice"];
const col = c => c.startsWith("--") ? css(c) : c;
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ------------------------------------------------------------------ clé et déchiffrement
async function deriverCle(phrase, sel, tours) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(phrase.trim()), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name: "PBKDF2", hash: "SHA-256", salt: sel, iterations: tours},
                                 base, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
}

async function dechiffrer(cle, paquet) {
  const clair = await crypto.subtle.decrypt({name: "AES-GCM", iv: b64(paquet.iv)}, cle, b64(paquet.donnees));
  const flux = new Blob([clair]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(flux).text());
}

async function chargerPaquet() {
  const r = await fetch("donnees.json", {cache: "no-store"});
  if (!r.ok) throw new Error("données introuvables");
  return r.json();
}

// Mémoire de la clé (IndexedDB) : la clé est « non extractible », aucun
// script ne peut en lire le contenu, le navigateur sait seulement s'en servir.
function base() {
  return new Promise((ok, ko) => {
    const r = indexedDB.open("novice", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("cles");
    r.onsuccess = () => ok(r.result);
    r.onerror = () => ko(r.error);
  });
}
async function memoriser(cle) {
  try { const db = await base(); db.transaction("cles", "readwrite").objectStore("cles").put({cle, expire: Date.now() + 30 * JOUR_MS}, "cle"); } catch (e) {}
}
async function relire() {
  try {
    const db = await base();
    return await new Promise(ok => {
      const r = db.transaction("cles").objectStore("cles").get("cle");
      r.onsuccess = () => ok(r.result && r.result.expire > Date.now() ? r.result.cle : null);
      r.onerror = () => ok(null);
    });
  } catch (e) { return null; }
}
async function oublier() {
  try { const db = await base(); const st = db.transaction("cles", "readwrite").objectStore("cles"); st.delete("cle"); st.delete("faceid"); } catch (e) {}
}
async function ranger(nom, valeur) {
  try { const db = await base(); db.transaction("cles", "readwrite").objectStore("cles").put(valeur, nom); } catch (e) {}
}
async function sortir(nom) {
  try {
    const db = await base();
    return await new Promise(ok => { const r = db.transaction("cles").objectStore("cles").get(nom); r.onsuccess = () => ok(r.result || null); r.onerror = () => ok(null); });
  } catch (e) { return null; }
}

// ------------------------------------------------------------------ Face ID
// Face ID (ou l'empreinte digitale) verrouille l'appli à l'ouverture et après
// 15 minutes d'inactivité. C'est le téléphone qui vérifie le visage : l'appli
// ne reçoit qu'un « oui » signé, jamais de photo ni d'empreinte. La phrase de
// passe reste le secours.
const INACTIVITE_MS = 15 * 60 * 1000;
const aleatoire = n => crypto.getRandomValues(new Uint8Array(n));
async function faceIdPossible() {
  return !!(window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
            && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false));
}
async function activerFaceId() {
  const cred = await navigator.credentials.create({publicKey: {
    challenge: aleatoire(32), rp: {name: "Novice"},
    user: {id: aleatoire(16), name: "antoine", displayName: "Antoine"},
    pubKeyCredParams: [{type: "public-key", alg: -7}, {type: "public-key", alg: -257}],
    authenticatorSelection: {authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred"},
    timeout: 60000}});
  await ranger("faceid", {id: new Uint8Array(cred.rawId)});
}
async function verifierFaceId() {
  const f = await sortir("faceid");
  await navigator.credentials.get({publicKey: {challenge: aleatoire(32),
    allowCredentials: [{type: "public-key", id: f.id}], userVerification: "required", timeout: 60000}});
}
function ecranVerrou(suite) {
  const cache = document.createElement("div");
  cache.className = "verrou";
  cache.innerHTML = `<div class="connexion"><div class="avatar lg">N</div><h1>Novice</h1><div class="over">Verrouillée</div>
    <button class="btn" id="btnFace">Déverrouiller avec Face ID</button>
    <div class="erreur" id="erreurFace"></div>
    <div class="foot" style="margin:18px 0 0;text-align:center"><a href="#" id="parPhrase">Utiliser le mot de passe</a></div></div>`;
  document.body.appendChild(cache);
  const essayer = async () => {
    try { await verifierFaceId(); cache.remove(); suite && suite(); }
    catch (e) { $("#erreurFace").textContent = "Face ID n'a pas abouti. Réessaie ou utilise le mot de passe."; }
  };
  cache.querySelector("#btnFace").onclick = essayer;
  cache.querySelector("#parPhrase").onclick = ev => { ev.preventDefault(); cache.remove(); oublier().then(() => ecranConnexion()); };
  // Pas d'appel automatique : Safari exige un geste de l'utilisateur (le bouton).
}
let derniereActivite = Date.now();
["pointerdown", "keydown", "scroll"].forEach(t => document.addEventListener(t, () => derniereActivite = Date.now(), {passive: true, capture: true}));
document.addEventListener("visibilitychange", async () => {
  if (document.visibilityState !== "visible" || !D || document.querySelector(".verrou")) return;
  if (Date.now() - derniereActivite > INACTIVITE_MS && await sortir("faceid")) ecranVerrou();
  derniereActivite = Date.now();
});
setInterval(async () => {
  if (D && !document.querySelector(".verrou") && Date.now() - derniereActivite > INACTIVITE_MS && await sortir("faceid")) ecranVerrou();
}, 60000);
function proposerFaceId() {
  const cache = document.createElement("div");
  cache.className = "verrou";
  cache.innerHTML = `<div class="connexion"><div class="avatar lg">N</div><h1>Face ID</h1>
    <div class="bubble" style="margin-top:10px">Verrouiller Novice avec Face ID à chaque ouverture et après 15 minutes sans t'en servir ? Tu n'auras plus à taper ton mot de passe pendant 30 jours.</div>
    <button class="btn" id="oui">Activer Face ID</button><div class="erreur" id="erreurFace"></div>
    <div class="foot" style="margin:18px 0 0;text-align:center"><a href="#" id="non">Plus tard</a></div></div>`;
  document.body.appendChild(cache);
  cache.querySelector("#oui").onclick = async () => {
    try { await activerFaceId(); cache.remove(); } catch (e) { $("#erreurFace").textContent = "Activation annulée ou impossible sur cet appareil."; }
  };
  cache.querySelector("#non").onclick = ev => { ev.preventDefault(); cache.remove(); };
}

// ------------------------------------------------------------------ démarrage
async function demarrer() {
  if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});
  // Test en local uniquement : données en clair, jamais publiées.
  if (new URLSearchParams(location.search).has("clair") && !location.hostname.endsWith("github.io")) {
    D = await (await fetch("donnees-en-clair.json", {cache: "no-store"})).json();
    return afficher();
  }
  const cle = await relire();
  if (cle) {
    try {
      D = await dechiffrer(cle, await chargerPaquet());
      CLE = cle;
      afficher();
      if (await sortir("faceid")) ecranVerrou();
      return;
    } catch (e) { await oublier(); }
  }
  ecranConnexion();
}

function ecranConnexion(message = "") {
  $("#app").innerHTML = `<form class="connexion" id="formCo">
    <div class="avatar lg">N</div>
    <h1>Novice</h1>
    <div class="over">Ta méthode, appliquée chaque soir.</div>
    <input type="text" name="username" value="antoine" autocomplete="username" hidden aria-hidden="true">
    <input type="password" id="phrase" name="password" placeholder="Mot de passe" autocomplete="current-password" autofocus>
    <label class="memo"><input type="checkbox" id="memo" checked> Rester connecté 30 jours sur cet appareil</label>
    <div class="erreur" id="erreur">${esc(message)}</div>
    <button class="btn" id="btnCo">Ouvrir</button>
  </form>`;
  $("#formCo").onsubmit = async ev => {
    ev.preventDefault();
    const bouton = $("#btnCo"); bouton.disabled = true; bouton.textContent = "Déchiffrement…";
    try {
      const paquet = await chargerPaquet();
      const cle = await deriverCle($("#phrase").value, b64(paquet.sel), paquet.tours);
      D = await dechiffrer(cle, paquet);
      CLE = cle;
      const garder = $("#memo").checked;
      if (garder) await memoriser(cle);
      afficher();
      if (garder && await faceIdPossible() && !(await sortir("faceid"))) proposerFaceId();
    } catch (e) {
      bouton.disabled = false; bouton.textContent = "Ouvrir";
      $("#erreur").textContent = e.message === "données introuvables"
        ? "Données introuvables : le calcul du soir n'a pas encore été publié."
        : "Mot de passe incorrect.";
    }
  };
}

// ------------------------------------------------------------------ données dérivées
const R = () => D.resume || {};
const grilleDe = t => (D.grille || {})[t];
const nomDe = t => {
  const f = (R().short_list || []).find(x => x.ticker === t)
        || (D.novice.positions || []).find(x => x.ticker === t)
        || (D.mes_positions.ouvertes || []).find(x => x.ticker === t);
  return f ? f.nom : t;
};
function courbes() {
  const c = {novice: (D.novice.courbe || [])};
  for (const [k, v] of Object.entries(D.labo || {})) c[k] = v.courbe || [];
  return c;
}
function bilanDe(k) { return k === "novice" ? D.novice.bilan || {} : ((D.labo || {})[k] || {}).bilan || {}; }
function gainTotal(b) { return (b.gain_realise_eur || 0) + (b.gain_latent_eur || 0); }

// Aligne plusieurs courbes (listes {date, gain_eur}) sur les mêmes dates.
function aligner(series) {
  const dates = [...new Set(Object.values(series).flat().map(p => p.date))].sort();
  const out = {};
  for (const [k, s] of Object.entries(series)) {
    const m = Object.fromEntries(s.map(p => [p.date, p.gain_eur]));
    let dernier = 0;
    out[k] = dates.map(d => (d in m ? (dernier = m[d]) : dernier));
  }
  return {dates, out};
}

// ------------------------------------------------------------------ graphiques
function traceLignes(svg, sets, W, H, aireIdx) {
  const tout = sets.flatMap(s => s.d).filter(v => v != null);
  if (!tout.length || sets[0].d.length < 2) { svg.innerHTML = ""; return; }
  const mn = Math.min(...tout, 0), mx = Math.max(...tout, 0);
  const pad = (mx - mn) * 0.08 || 1;
  const X = i => i / (sets[0].d.length - 1) * W, Y = v => H - 6 - (v - mn + pad) / (mx - mn + 2 * pad) * (H - 12);
  const p = d => d.map((v, i) => v == null ? "" : (i && d[i - 1] != null ? "L" : "M") + X(i).toFixed(1) + "," + Y(v).toFixed(1)).join("");
  const or = css("--gold-2");
  let h = `<defs><linearGradient id="g${svg.id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${or}" stop-opacity=".3"/><stop offset="1" stop-color="${or}" stop-opacity="0"/></linearGradient></defs>`;
  h += `<line x1="0" x2="${W}" y1="${Y(0)}" y2="${Y(0)}" stroke="${css("--line")}"/>`;
  if (aireIdx != null) h += `<path d="${p(sets[aireIdx].d)}L${W},${H}L0,${H}Z" fill="url(#g${svg.id})"/>`;
  sets.slice().reverse().forEach(s => h += `<path d="${p(s.d)}" fill="none" stroke="${s.c}" stroke-width="${s.w || 1.6}" ${s.dash ? 'stroke-dasharray="4 3"' : ""} opacity="${s.o ?? 1}" stroke-linecap="round" stroke-linejoin="round"/>`);
  svg.innerHTML = h;
}

// ------------------------------------------------------------------ structure
const ICONES = {
  accueil: '<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  novice: '<path d="M12 3l2.2 5.8L20 11l-5.8 2.2L12 19l-2.2-5.8L4 11l5.8-2.2z"/>',
  marches: '<path d="M3 17l5-5 4 4 8-9"/><path d="M15 7h5v5"/>',
  actions: '<rect x="3" y="6" width="18" height="14" rx="3"/><path d="M3 10h18M16 15h2"/>',
  labo: '<path d="M9 3h6M10 3v6l-5.5 9.5A1.7 1.7 0 0 0 6 21h12a1.7 1.7 0 0 0 1.5-2.5L14 9V3"/><path d="M7.5 15h9"/>'
};
const LIBELLES = {accueil: "Accueil", novice: "Novice", marches: "Marchés", actions: "Mes actions", labo: "Labo"};

function afficher() {
  const alerte = (D.mes_positions.ouvertes || []).some(p => ["Alerte", "Sortir"].includes((p.verdict || {}).verdict));
  $("#app").innerHTML = `
    <div class="views">
      <section class="view" id="v-accueil"></section>
      <section class="view" id="v-novice" hidden></section>
      <section class="view" id="v-marches" hidden></section>
      <section class="view" id="v-actions" hidden></section>
      <section class="view" id="v-labo" hidden></section>
    </div>
    <section class="sub" id="s-fiche"></section>
    <section class="sub" id="s-resultats"></section>
    <section class="sub" id="s-reglages"></section>
    <section class="sub" id="s-strat"></section>
    <nav class="tabs">${Object.keys(ICONES).map(k => `<button class="tab${k === "accueil" ? " on" : ""}" data-v="${k}">${k === "actions" && alerte ? '<span class="dot"></span>' : ""}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${ICONES[k]}</svg>${LIBELLES[k]}</button>`).join("")}</nav>`;
  vueAccueil(); vueNovice(); vueMarches(); vueActions(); vueLabo();
  $$(".tab").forEach(t => t.onclick = () => aller(t.dataset.v));
  // Lien direct vers la case du jeton GitHub : …/novice-app/#github
  if (location.hash === "#github") {
    history.replaceState(null, "", location.pathname);
    aller("novice"); ouvrir("reglages");
    setTimeout(() => { const c = $("#blocGithub"); if (c) c.scrollIntoView({block: "center"}); const champ = $("#champJeton"); if (champ) champ.focus(); }, 500);
  }
}

function aller(v) {
  $$(".tab").forEach(t => t.classList.toggle("on", t.dataset.v === v));
  $$(".view").forEach(s => s.hidden = s.id !== "v-" + v);
  $$(".sub").forEach(s => s.classList.remove("open"));
  $("#v-" + v).scrollTop = 0;
}
function ouvrir(id) { const s = $("#s-" + id); s.scrollTop = 0; s.classList.add("open"); }

document.addEventListener("click", e => {
  const f = e.target.closest("[data-fiche]"); if (f) { e.preventDefault(); return fiche(f.dataset.fiche); }
  const g = e.target.closest("[data-go]"); if (g) return aller(g.dataset.go);
  const o = e.target.closest("[data-open]"); if (o) return ouvrir(o.dataset.open);
  const c = e.target.closest("[data-close]"); if (c) return c.closest(".sub").classList.remove("open");
  const s = e.target.closest("[data-strat]"); if (s) return strategie(s.dataset.strat);
  const q = e.target.closest(".q6[data-why]"); if (q) { const x = q.querySelector("small.why"); if (x) x.hidden = !x.hidden; }
  const d = e.target.closest("[data-deco]"); if (d) { oublier().then(() => location.reload()); }
});

function segments(conteneur, onglets, choix) {
  conteneur.querySelectorAll(".seg button").forEach(b => b.onclick = () => {
    conteneur.querySelectorAll(".seg button").forEach(x => x.classList.toggle("on", x === b));
    onglets.forEach(id => conteneur.querySelector("#" + id).hidden = id !== b.dataset.s);
    if (choix) choix(b.dataset.s);
  });
}

// ------------------------------------------------------------------ GitHub : l'appli agit
// Un « jeton » GitHub à accès limité (dépôt privé novice seulement : contenu
// et lancement du calcul) permet à l'appli d'enregistrer tes achats et ventes
// et de lancer un scan. Il est gardé sur ce téléphone, chiffré avec la clé de
// ton mot de passe, et n'est jamais publié.
const DEPOT = "Pomme-Framboise/novice";
async function jeton() {
  const j = await sortir("jeton");
  if (!j || !CLE) return null;
  try {
    const clair = await crypto.subtle.decrypt({name: "AES-GCM", iv: j.iv}, CLE, j.donnees);
    return new TextDecoder().decode(clair);
  } catch (e) { return null; }
}
async function rangerJeton(valeur) {
  const iv = aleatoire(12);
  const donnees = await crypto.subtle.encrypt({name: "AES-GCM", iv}, CLE, new TextEncoder().encode(valeur.trim()));
  await ranger("jeton", {iv, donnees});
}
async function gh(chemin, options = {}) {
  const j = await jeton();
  if (!j) throw new Error("sans jeton");
  const r = await fetch(`https://api.github.com/repos/${DEPOT}${chemin}`, {...options, headers: {
    Authorization: `Bearer ${j}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
    ...(options.body ? {"Content-Type": "application/json"} : {})}});
  if (r.status === 401) throw new Error("jeton refusé");
  if (!r.ok && r.status !== 204) throw new Error(`GitHub a répondu ${r.status}`);
  return r.status === 204 ? null : r.json();
}
const versB64 = t => { const o = new TextEncoder().encode(t); let b = ""; o.forEach(x => b += String.fromCharCode(x)); return btoa(b); };
const depuisB64 = t => new TextDecoder().decode(Uint8Array.from(atob(t.replace(/\n/g, "")), c => c.charCodeAt(0)));
async function lireMesPositions() {
  const f = await gh("/contents/donnees/mes_positions.json?ref=main");
  return {sha: f.sha, mes: JSON.parse(depuisB64(f.content))};
}
async function ecrireMesPositions(mes, sha, message) {
  await gh("/contents/donnees/mes_positions.json", {method: "PUT", body: JSON.stringify({
    message, sha, branch: "main", content: versB64(JSON.stringify(mes, null, 1) + "\n")})});
}

// Suivi d'un calcul lancé sur GitHub, puis rechargement des données publiées.
async function suivre(workflow, depuis, message) {
  const bandeau = $("#suivi") || document.body.appendChild(Object.assign(document.createElement("div"), {id: "suivi", className: "toast show"}));
  bandeau.classList.add("show");
  for (let i = 0; i < 90; i++) {
    await new Promise(ok => setTimeout(ok, 15000));
    let run;
    try { run = ((await gh(`/actions/workflows/${workflow}/runs?per_page=5`)).workflow_runs || []).find(r => new Date(r.created_at) >= depuis); } catch (e) { continue; }
    if (!run) { bandeau.textContent = `${message} : en file d'attente chez GitHub…`; continue; }
    if (run.status !== "completed") {
      let etape = "";
      try { const jobs = await gh(`/actions/runs/${run.id}/jobs`); const e = (jobs.jobs[0].steps || []).find(x => x.status === "in_progress"); etape = e ? " · " + e.name : ""; } catch (e) {}
      bandeau.textContent = `${message} : en cours${etape}`;
      continue;
    }
    if (run.conclusion !== "success") { bandeau.textContent = `${message} : échec chez GitHub. Réessaie plus tard.`; setTimeout(() => bandeau.remove(), 8000); return; }
    bandeau.textContent = "Terminé, mise à jour de l'appli…";
    await new Promise(ok => setTimeout(ok, 45000));   // le temps que GitHub Pages serve la nouvelle version
    try { D = await dechiffrer(CLE, await chargerPaquet()); afficher(); } catch (e) {}
    bandeau.remove();
    toast("Données à jour.");
    return;
  }
  bandeau.textContent = `${message} : toujours en cours, reviens plus tard.`;
}

function toast(texte) {
  const t = document.body.appendChild(Object.assign(document.createElement("div"), {className: "toast show", textContent: texte}));
  setTimeout(() => t.remove(), 4000);
}

function feuille(html) {
  const fond = document.body.appendChild(Object.assign(document.createElement("div"), {className: "feuille-fond"}));
  const f = document.body.appendChild(Object.assign(document.createElement("div"), {className: "feuille", innerHTML: `<div class="poignee"></div>${html}`}));
  const fermer = () => { fond.remove(); f.remove(); };
  fond.onclick = fermer;
  f.querySelectorAll("[data-annuler]").forEach(b => b.onclick = ev => { ev.preventDefault(); fermer(); });
  return {f, fermer};
}

async function exigerJeton() {
  if (await jeton()) return true;
  toast("Connecte d'abord l'appli à GitHub : Novice › roue crantée › GitHub.");
  return false;
}

async function scanner() {
  if (!await exigerJeton()) return;
  const {f, fermer} = feuille(`<h3>Lancer un scan maintenant ?</h3>
    <p>Novice refait tout : cours des ~870 titres, classement, six questions lues par Claude. Compte 5 à 10 minutes.</p>
    <p>Pendant la séance, c'est un <b>aperçu provisoire</b> : Novice n'achète et ne vend que sur le calcul du soir.</p>
    <button class="btn" id="go">Lancer le scan</button><button class="btn sec" data-annuler>Annuler</button>`);
  f.querySelector("#go").onclick = async () => {
    fermer();
    const depuis = new Date(Date.now() - 5000);
    try {
      await gh("/actions/workflows/soir.yml/dispatches", {method: "POST", body: JSON.stringify({ref: "main", inputs: {manuel: "true"}})});
      suivre("soir.yml", depuis, "Scan");
    } catch (e) { toast("Impossible de lancer le scan : " + e.message); }
  };
}

const PLACES = {PA: ["Paris", "EUR"], AS: ["Amsterdam", "EUR"], BR: ["Bruxelles", "EUR"], LS: ["Lisbonne", "EUR"],
                DE: ["Francfort", "EUR"], MI: ["Milan", "EUR"], MC: ["Madrid", "EUR"], L: ["Londres", "GBp"]};
function placeDe(ticker) {
  const suffixe = ticker.includes(".") ? ticker.split(".").pop() : "";
  return PLACES[suffixe] || (suffixe ? ["?", "EUR"] : ["US", "USD"]);
}
const aujourdhui = () => new Date().toISOString().slice(0, 10);
const nombre = v => parseFloat(String(v).replace(",", ".").replace(/\s/g, ""));

async function achat() {
  if (!await exigerJeton()) return;
  const suggestions = [...new Set([...(R().short_list || []).map(t => t.ticker), ...(D.novice.positions || []).map(p => p.ticker)])];
  const {f, fermer} = feuille(`<h3>J'ai acheté</h3>
    <p>Novice calculera ton stop, ton niveau de vente et te donnera un verdict chaque soir.</p>
    <label class="champ"><span>Action (code Yahoo : ANET, AIR.PA, RHM.DE…)</span><input id="tk" list="tks" autocapitalize="characters" autocomplete="off"><datalist id="tks">${suggestions.map(t => `<option value="${esc(t)}">${esc(nomDe(t))}</option>`).join("")}</datalist></label>
    <label class="champ"><span>Nom (facultatif)</span><input id="nm"></label>
    <div class="champs2"><label class="champ"><span>Date d'achat</span><input id="dt" type="date" value="${aujourdhui()}"></label>
      <label class="champ"><span>Montant (€)</span><input id="mt" inputmode="decimal" value="300"></label></div>
    <label class="champ"><span>Prix payé par action, dans la devise de cotation</span><input id="px" inputmode="decimal"></label>
    <div class="erreur" id="err"></div>
    <button class="btn" id="ok">Enregistrer</button><button class="btn sec" data-annuler>Annuler</button>`);
  f.querySelector("#tk").oninput = e => { const t = e.target.value.trim().toUpperCase(); if (!f.querySelector("#nm").value && nomDe(t) !== t) f.querySelector("#nm").value = nomDe(t); };
  f.querySelector("#ok").onclick = async () => {
    const ticker = f.querySelector("#tk").value.trim().toUpperCase(), prix = nombre(f.querySelector("#px").value),
          montant = nombre(f.querySelector("#mt").value), date = f.querySelector("#dt").value;
    const err = f.querySelector("#err");
    if (!/^[A-Z0-9^.\-]{1,15}$/.test(ticker)) return err.textContent = "Code de l'action invalide.";
    if (!(prix > 0) || !(montant > 0) || !date) return err.textContent = "Prix, montant et date sont obligatoires.";
    const [place, devise] = placeDe(ticker);
    f.querySelector("#ok").disabled = true; f.querySelector("#ok").textContent = "Enregistrement…";
    try {
      const {sha, mes} = await lireMesPositions();
      if ((mes.ouvertes || []).some(p => p.ticker === ticker)) throw new Error(`${ticker} est déjà dans tes positions`);
      mes.ouvertes = [...(mes.ouvertes || []), {ticker, nom: f.querySelector("#nm").value.trim() || ticker, place, devise,
                                                date_achat: date, prix, montant}];
      const depuis = new Date(Date.now() - 5000);
      await ecrireMesPositions(mes, sha, `Achat de ${ticker} enregistré depuis l'appli`);
      fermer();
      D.mes_positions.ouvertes = mes.ouvertes; vueActions();
      toast(`${ticker} enregistré. Verdict dans 2 à 3 minutes.`);
      suivre("publier.yml", depuis, "Calcul de tes niveaux");
    } catch (e) { err.textContent = e.message; f.querySelector("#ok").disabled = false; f.querySelector("#ok").textContent = "Enregistrer"; }
  };
}

async function vente(ticker) {
  if (!await exigerJeton()) return;
  const p = (D.mes_positions.ouvertes || []).find(x => x.ticker === ticker); if (!p) return;
  const v = p.verdict || {};
  const {f, fermer} = feuille(`<h3>J'ai vendu ${esc(p.nom || ticker)}</h3>
    <p>Verdict de Novice ce soir : <b>${esc(v.verdict || "?")}</b>${v.raison ? " (" + esc(v.raison) + ")" : ""}. Il comparera ta vente à ce que dit la règle.</p>
    <div class="champs2"><label class="champ"><span>Date de vente</span><input id="dt" type="date" value="${aujourdhui()}"></label>
      <label class="champ"><span>Prix de vente</span><input id="px" inputmode="decimal" value="${v.dernier_cours ? nb(v.dernier_cours, 2) : ""}"></label></div>
    <label class="champ"><span>Gain réel en € affiché par Trade Republic (facultatif, sinon estimé)</span><input id="ge" inputmode="decimal"></label>
    <label class="champ"><span>Pourquoi ? (facultatif)</span><input id="mo" placeholder="signal de sortie, besoin du capital…"></label>
    <div class="erreur" id="err"></div>
    <button class="btn" id="ok">Enregistrer la vente</button><button class="btn sec" data-annuler>Annuler</button>`);
  f.querySelector("#ok").onclick = async () => {
    const prixVente = nombre(f.querySelector("#px").value), date = f.querySelector("#dt").value, err = f.querySelector("#err");
    if (!(prixVente > 0) || !date) return err.textContent = "Prix et date de vente sont obligatoires.";
    const gainSaisi = nombre(f.querySelector("#ge").value);
    f.querySelector("#ok").disabled = true;
    try {
      const {sha, mes} = await lireMesPositions();
      const pos = (mes.ouvertes || []).find(x => x.ticker === ticker);
      if (!pos) throw new Error("position introuvable, recharge l'appli");
      const brut = (prixVente / pos.prix - 1) * 100;
      const gainEur = isNaN(gainSaisi) ? pos.montant * brut / 100 - 2 : gainSaisi;
      mes.ouvertes = mes.ouvertes.filter(x => x.ticker !== ticker);
      mes.ventes = [...(mes.ventes || []), {...pos, date_vente: date, prix_vente: prixVente,
        motif: f.querySelector("#mo").value.trim() || "vente depuis l'appli",
        gain_pct: Math.round(gainEur / pos.montant * 10000) / 100, gain_eur: Math.round(gainEur * 100) / 100,
        gain_estime: isNaN(gainSaisi), verdict_du_soir: v.verdict || null}];
      const depuis = new Date(Date.now() - 5000);
      await ecrireMesPositions(mes, sha, `Vente de ${ticker} enregistrée depuis l'appli`);
      fermer();
      D.mes_positions = {...D.mes_positions, ouvertes: mes.ouvertes, ventes: mes.ventes}; vueActions(); vueAccueil();
      toast(`Vente de ${ticker} enregistrée.`);
      suivre("publier.yml", depuis, "Comparaison à la règle");
    } catch (e) { err.textContent = e.message; f.querySelector("#ok").disabled = false; }
  };
}

async function blocGithub() {
  const el = $("#blocGithub"); if (!el) return;
  const connecte = !!(await jeton());
  el.innerHTML = connecte
    ? `<div class="set">Connexion à GitHub<span class="v up">active</span></div>
       <div class="set" style="justify-content:center"><a href="#" id="retirerJeton">Retirer le jeton de ce téléphone</a></div>`
    : `<div style="padding:14px 16px" class="empty">Pour que l'appli puisse lancer un scan et enregistrer tes achats et ventes, crée un jeton GitHub limité :
        <ol style="padding-left:18px;margin:8px 0">
          <li>Ouvre <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener">github.com › jeton à accès limité</a>.</li>
          <li>Nom : <b>Novice appli</b>. Expiration : 1 an.</li>
          <li>Repository access : <b>Only select repositories</b> › <b>novice</b>.</li>
          <li>Permissions › Repository : <b>Contents</b> en Read and write, <b>Actions</b> en Read and write.</li>
          <li>Generate token, copie-le, colle-le ci-dessous.</li>
        </ol></div>
       <div style="padding:0 16px 16px"><input id="champJeton" class="saisie" placeholder="github_pat_…" autocomplete="off" autocapitalize="off" spellcheck="false">
        <button class="btn" id="rangerJeton" style="margin-top:10px">Enregistrer sur ce téléphone</button><div class="erreur" id="errJeton"></div></div>`;
  const r = $("#retirerJeton"); if (r) r.onclick = async ev => { ev.preventDefault(); await ranger("jeton", null); blocGithub(); };
  const b = $("#rangerJeton"); if (b) b.onclick = async () => {
    const v = $("#champJeton").value.trim(), err = $("#errJeton");
    if (!/^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$/.test(v)) return err.textContent = "Ce n'est pas un jeton GitHub (il commence par github_pat_).";
    b.disabled = true; b.textContent = "Vérification…"; err.textContent = "";
    try {
      // Une clé gardée avant cette version sait lire, pas chiffrer : on la
      // renouvelle avec le mot de passe, une seule fois.
      if (!CLE || !CLE.usages.includes("encrypt")) {
        const mdp = await demanderMotDePasse();
        if (!mdp) throw new Error("annulé");
        const paquet = await chargerPaquet();
        const cle = await deriverCle(mdp, b64(paquet.sel), paquet.tours);
        await dechiffrer(cle, paquet);            // vérifie que c'est le bon
        CLE = cle; await memoriser(cle);
      }
      await rangerJeton(v);
      await gh("");                                // le jeton ouvre-t-il le dépôt ?
      toast("Jeton enregistré, l'appli est connectée."); blocGithub();
    } catch (e) {
      if (e.message !== "annulé") await ranger("jeton", null);
      b.disabled = false; b.textContent = "Enregistrer sur ce téléphone";
      err.textContent = e.message === "annulé" ? ""
        : e.message === "jeton refusé" ? "GitHub refuse ce jeton : il est invalide ou expiré."
        : e.message.includes("404") ? "Ce jeton n'ouvre pas le dépôt novice : vérifie « Only select repositories › novice »."
        : e.message.includes("403") ? "Ce jeton n'a pas les bons droits : Contents et Actions en Read and write."
        : e.name === "OperationError" ? "Mot de passe incorrect."
        : "Enregistrement impossible : " + e.message;
    }
  };
}

function demanderMotDePasse() {
  return new Promise(ok => {
    const {f, fermer} = feuille(`<h3>Ton mot de passe, une fois</h3>
      <p>Pour ranger le jeton en sécurité sur ce téléphone, Novice a besoin de ton mot de passe une dernière fois.</p>
      <input type="text" name="username" value="antoine" autocomplete="username" hidden aria-hidden="true">
      <label class="champ"><span>Mot de passe</span><input type="password" id="mdp" autocomplete="current-password"></label>
      <button class="btn" id="okMdp">Continuer</button><button class="btn sec" id="annulerMdp">Annuler</button>`);
    f.querySelector("#okMdp").onclick = () => { const v = f.querySelector("#mdp").value; fermer(); ok(v); };
    f.querySelector("#annulerMdp").onclick = () => { fermer(); ok(null); };
    $$(".feuille-fond").forEach(x => x.onclick = () => { fermer(); ok(null); });
    setTimeout(() => f.querySelector("#mdp").focus(), 100);
  });
}

// ------------------------------------------------------------------ Parler à Novice
// La question part sur GitHub (workflow « Question à Novice ») ; Claude
// répond avec les données du soir et écrit la réponse dans le dépôt privé,
// où l'appli vient la lire. L'historique reste sur ce téléphone.
async function conversation() { return (await sortir("conversation")) || []; }
async function afficherConversation() {
  const m = $("#msgs"); if (!m) return;
  const c = await conversation();
  m.innerHTML = c.slice(-12).map(x => `<div class="msg moi">${esc(x.q)}</div>` + (x.r
    ? `<div class="msg novice">${esc(x.r).replace(/\n/g, "<br>")}${(x.sources || []).length ? `<div class="sources" style="margin-top:6px">${x.sources.slice(0, 3).map(s => `<a href="${lien(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.titre || s.url)}</a>`).join("")}</div>` : ""}</div>`
    : `<div class="msg novice attente">Je réfléchis… (1 à 2 minutes)</div>`)).join("");
}
async function poser(question) {
  question = question.trim().slice(0, 500);
  if (!question || !await exigerJeton()) return;
  const id = Date.now().toString(36) + "-" + [...aleatoire(4)].map(x => x.toString(16).padStart(2, "0")).join("");
  const c = await conversation();
  c.push({id, q: question, r: null});
  await ranger("conversation", c.slice(-30));
  afficherConversation();
  try {
    await gh("/actions/workflows/question.yml/dispatches", {method: "POST", body: JSON.stringify({ref: "main", inputs: {question, id}})});
    attendreReponse(id);
  } catch (e) { await noter(id, {r: "Question non envoyée : " + e.message}); }
}
async function noter(id, champs) {
  const c = await conversation();
  const x = c.find(y => y.id === id); if (x) Object.assign(x, champs);
  await ranger("conversation", c); afficherConversation();
}
async function attendreReponse(id) {
  for (let i = 0; i < 36; i++) {          // jusqu'à 6 minutes
    await new Promise(ok => setTimeout(ok, 10000));
    try {
      const f = await gh(`/contents/donnees/reponses/${id}.json?ref=main`);
      const r = JSON.parse(depuisB64(f.content));
      return noter(id, {r: r.reponse || "Réponse vide.", sources: r.sources || []});
    } catch (e) { if (!String(e.message).includes("404")) break; }
  }
  noter(id, {r: "Pas de réponse pour l'instant. Rouvre l'appli plus tard : elle ira la chercher."});
}
function brancherConversation() {
  const envoyer = () => { const v = $("#chatIn").value; $("#chatIn").value = ""; poser(v); };
  $("#chatGo").onclick = envoyer;
  $("#chatIn").onkeydown = e => { if (e.key === "Enter") envoyer(); };
  $$("#sugg button").forEach(b => b.onclick = () => poser(b.textContent));
  afficherConversation();
  // Reprend l'attente des questions restées sans réponse (appli fermée entre-temps).
  conversation().then(c => c.filter(x => !x.r || x.r.startsWith("Pas de réponse pour l'instant")).forEach(x => attendreReponse(x.id)));
}

// ------------------------------------------------------------------ Accueil
function vueAccueil() {
  const r = R(), maintenant = new Date(), heure = maintenant.getHours();
  const genere = r.genere_le ? new Date(r.genere_le) : null;
  const vieux = genere && (maintenant - genere) > 3 * JOUR_MS;
  const b = bilanDe("novice"), mes = D.mes_positions.ouvertes || [];
  const nov = r.novice || {};
  const c = courbes(), a = aligner({novice: c.novice, hasard: c.hasard || [], indice: c.indice || []});
  const dernierHasard = a.out.hasard.at(-1) ?? 0, dernierIndice = a.out.indice.at(-1) ?? 0;
  const top = (r.short_list || []).slice().sort((x, y) => (y.score_global || 0) - (x.score_global || 0)).slice(0, 3);
  const meilleur = top[0];

  let mouvements = [
    ...(nov.achats_demain || []).map(t => `<div class="li tappable" data-fiche="${esc(t)}"><div class="logo">${esc(t)}</div><div class="t"><b>${esc(nomDe(t))}</b><span>achat demain à l'ouverture · 300 €</span></div><span class="chip in">Entrée</span></div>`),
    ...(nov.ventes_demain || []).map(t => `<div class="li tappable" data-fiche="${esc(t)}"><div class="logo">${esc(t)}</div><div class="t"><b>${esc(nomDe(t))}</b><span>deuxième clôture sous le niveau de vente</span></div><span class="chip out">Sortie</span></div>`)];
  if (!mouvements.length) mouvements = [`<div class="li"><div class="t"><b>Aucun mouvement ce soir</b><span>Aucun titre n'a réuni tes conditions, et aucune position ne doit être vendue.</span></div></div>`];

  const messageNovice = (b.positions_ouvertes || b.achats_en_attente || b.operations_closes)
    ? `J'ai <b>${b.positions_ouvertes || 0} position${(b.positions_ouvertes || 0) > 1 ? "s" : ""}</b> en cours${b.achats_en_attente ? ` et <b>${b.achats_en_attente}</b> achat${b.achats_en_attente > 1 ? "s" : ""} prévu${b.achats_en_attente > 1 ? "s" : ""} demain` : ""}. ${b.operations_closes ? `${b.operations_closes} opération${b.operations_closes > 1 ? "s" : ""} close${b.operations_closes > 1 ? "s" : ""}, gain net moyen ${pct(b.gain_net_moyen_pct)}.` : "Aucune opération close pour l'instant."}`
    : meilleur ? `Aucun titre n'a réuni tes conditions ce soir. Le mieux noté, <b>${esc(meilleur.nom)}</b>, fait <b>${nb(meilleur.score_global, 0)}</b> sur 100 (${esc(meilleur.statut || "")}). Je n'achète pas pour acheter.`
    : "Pas encore de calcul du soir.";

  $("#v-accueil").innerHTML = `
    <div class="hd"><div><div class="over">${dateLongue(maintenant)}</div><h1>${heure >= 18 || heure < 5 ? "Bonsoir" : "Bonjour"} Antoine</h1></div></div>
    <div style="padding:8px 20px 14px"><span class="pill${vieux ? " old" : ""}"><i></i>Données du ${genere ? dateFr(r.genere_le) + " à " + String(genere.getHours()).padStart(2, "0") + "h" + String(genere.getMinutes()).padStart(2, "0") : "—"}${r.provisoire ? " · provisoire" : ""}</span></div>
    ${vieux ? `<div class="bandeau">Le calcul du soir n'a pas tourné depuis le ${dateFr(r.genere_le)}. Les chiffres ci-dessous datent de ce jour-là.</div>` : ""}
    <div class="card tappable" data-go="actions">
      <div class="row"><span class="over">Tes actions ce soir</span><span class="cta" style="margin:0">Voir ›</span></div>
      ${mes.length ? mes.map(p => { const v = p.verdict || {}; const cl = v.verdict === "Garder" ? "in" : v.verdict === "Alerte" ? "al" : "out";
        return `<div class="li" style="padding:12px 0 0;border:0"><div class="logo">${esc(p.ticker)}</div><div class="t"><b>${esc(p.nom || p.ticker)}</b><span>${esc(v.raison || "")}</span></div><span class="chip ${cl}">${esc(v.verdict || "?")}</span></div>`; }).join("")
        : `<div class="empty" style="margin-top:8px">Aucune position en cours chez Trade Republic.</div>`}
    </div>
    <div class="card">
      <div class="row"><span class="over">Portefeuille de Novice</span><span class="pill">depuis le ${dateFr(D.novice.lance_le)}</span></div>
      <div style="margin-top:10px" class="big ${classe(gainTotal(b))}">${eur(gainTotal(b))}</div>
      <div style="margin-top:6px;font-size:13.5px" class="muted">hasard ${eur(dernierHasard)} · indice ${eur(dernierIndice)}</div>
      ${a.dates.length > 1 ? `<svg id="courbeAccueil" viewBox="0 0 320 130" width="100%" height="130" style="display:block;margin-top:12px"></svg>
        <div class="legend"><span><i style="background:var(--gold-2)"></i>Novice</span><span><i style="background:var(--grey)"></i>Hasard</span><span><i style="background:var(--dash)"></i>Indice</span></div>`
        : `<div class="empty" style="margin-top:12px">La courbe apparaîtra après le premier achat de Novice.</div>`}
    </div>
    <div class="stats">
      <div class="stat"><b>${b.positions_ouvertes || 0}<span style="font-size:13px;color:var(--muted)"> / 20</span></b><span>positions</span></div>
      <div class="stat"><b>${b.operations_closes || 0}</b><span>opérations closes</span></div>
      <div class="stat"><b class="${classe(b.gain_net_moyen_pct)}">${pct(b.gain_net_moyen_pct)}</b><span>gain net moyen</span></div>
    </div>
    <h2>Ce soir <small data-go="marches">Tout voir</small></h2>
    <div class="list">${mouvements.join("")}</div>
    <div class="list">${top.map(t => `<div class="li tappable" data-fiche="${esc(t.ticker)}"><div class="logo">${esc(t.ticker)}</div><div class="t"><b>${esc(t.nom)}</b><span>${esc(t.statut || "")}</span></div><div class="r">${nb(t.score_global, 0)}<span>sur 100</span></div></div>`).join("")}</div>
    <h2>Novice</h2>
    <div class="card tappable" data-go="novice"><div class="nov"><div class="avatar">N</div><div class="bubble">${messageNovice}</div></div></div>
    <div class="foot" style="text-align:center;margin-top:18px"><a href="#" data-deco>Se déconnecter de cet appareil</a></div>`;
  const svg = $("#courbeAccueil");
  if (svg) traceLignes(svg, [{d: a.out.novice, c: css("--gold-2"), w: 2.4}, {d: a.out.hasard, c: css("--grey")}, {d: a.out.indice, c: css("--dash"), dash: 1}], 316, 128, 0);
}

// ------------------------------------------------------------------ Novice
function vueNovice() {
  const b = bilanDe("novice");
  $("#v-novice").innerHTML = `
    <div class="hd"><div class="row" style="gap:14px;justify-content:flex-start"><div class="avatar lg">N</div><div><h1>Novice</h1><div class="over">Ta méthode, appliquée chaque soir</div></div></div>
      <button class="gear" data-open="reglages" aria-label="Réglages"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3 1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8 1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg></button>
    </div>
    <div style="padding:0 16px"><div class="seg"><button class="on" data-s="nov-apercu">Aperçu</button><button data-s="nov-adapt">Adaptation</button></div></div>
    <div id="nov-apercu">
      <div class="card" style="margin-top:14px"><div class="bubble">Chaque soir, j'applique <b>ta méthode du scan global</b> : régime des indices, filtre technique sur ${nb(R().univers_analyse, 0)} titres, puis tes <b>six questions</b> sur les 10 premiers, lues sur le web par Claude. J'achète ceux qui font <b>68 ou plus</b> (73 en régime orange), jusqu'à 20 positions de 300 €. Je vends sur tes règles : stop à 4 ATR, deux clôtures sous le niveau de vente, butoir à 6 mois.</div>
        <div class="msgs" id="msgs"></div>
        <div class="sugg" id="sugg"><button>Pourquoi aucun achat ce soir ?</button><button>Explique la note du mieux classé</button><button>Où en est le Labo ?</button></div>
        <div class="chat"><input id="chatIn" placeholder="Pose-moi une question…" enterkeyhint="send"><button id="chatGo" aria-label="Envoyer">↑</button></div>
        <div class="foot" style="margin:8px 0 0">Je réponds en 1 à 2 minutes : je relis mes données du soir et je cherche sur le web si besoin.</div></div>
      <h2>Mon travail</h2>
      <div class="card tappable" data-open="resultats">
        <div class="row"><span class="over">Depuis le ${dateFr(D.novice.lance_le)}</span><span class="cta" style="margin:0">Tout voir ›</span></div>
        <div class="kpi2">
          <div><b>${(D.novice.entrees || []).length}</b><span>achats décidés</span></div>
          <div><b>${b.operations_closes || 0}</b><span>ventes</span></div>
          <div><b class="${classe(b.gain_net_moyen_pct)}">${pct(b.gain_net_moyen_pct)}</b><span>gain net moyen par opération</span></div>
          <div><b class="${classe(gainTotal(b))}">${eur(gainTotal(b))}</b><span>gain net, frais compris</span></div>
        </div>
        <div class="prog"><i style="width:${Math.min(100, (b.operations_closes || 0))}%"></i></div>
        <div class="over" style="margin-top:6px;font-size:12px">${b.operations_closes || 0} opérations closes sur ~100 pour repérer un gros écart. Tant que la barre est courte, c'est surtout du hasard.</div>
      </div>
    </div>
    <div id="nov-adapt" hidden>
      <div class="card" style="margin-top:14px"><div class="empty">L'apprentissage de Novice commencera quand il aura assez d'opérations closes pour qu'un constat ne soit pas dû au hasard. Chaque constat devra passer la vérification statistique avant d'apparaître ici, et chaque idée sera testée à part (Novice bis) sans rien changer à Novice.</div></div>
    </div>`;
  segments($("#v-novice"), ["nov-apercu", "nov-adapt"]);
  brancherConversation();

  const pos = D.novice.positions || [];
  const bloc = (titre, liste, rendu) => liste.length ? `<div class="group-t">${titre} · ${liste.length}</div><div class="list">${liste.map(rendu).join("")}</div>` : "";
  $("#s-resultats").innerHTML = `<button class="back" data-close>‹ Novice</button><div class="hd"><h1>Résultats</h1></div>
    ${pos.length ? "" : `<div class="card" style="margin-top:14px"><div class="empty">Novice n'a encore rien acheté.</div></div>`}
    ${bloc("Achats prévus demain", pos.filter(p => p.etat === "en attente"), p => `<div class="li tappable" data-fiche="${esc(p.ticker)}"><div class="logo">${esc(p.ticker)}</div><div class="t"><b>${esc(p.nom)}</b><span>signal du ${dateFr(p.date_signal)} · score ${nb(p.score_global, 0)}</span></div><span class="chip in">Demain</span></div>`)}
    ${bloc("En cours", pos.filter(p => ["ouverte", "vente demain"].includes(p.etat)), p => `<div class="li tappable" data-fiche="${esc(p.ticker)}"><div class="logo">${esc(p.ticker)}</div><div class="t"><b>${esc(p.nom)}</b><span>${p.etat === "vente demain" ? "vente demain à l'ouverture" : `séance ${p.seances} · marge avant sortie ${pct(p.marge_avant_sortie_pct)}`}</span></div><div class="r ${classe(p.gain_eur)}">${pct(p.gain_pct)}<span>${eur(p.gain_eur, 2)}</span></div></div>`)}
    ${bloc("Vendues", pos.filter(p => p.etat === "vendue"), p => `<div class="li tappable" data-fiche="${esc(p.ticker)}"><div class="logo">${esc(p.ticker)}</div><div class="t"><b>${esc(p.nom)}</b><span>${dateFr(p.date_entree)} → ${dateFr(p.date_sortie)} · ${esc(p.motif)}</span></div><div class="r ${classe(p.gain_eur)}">${pct(p.gain_pct)}<span>${eur(p.gain_eur, 2)}</span></div></div>`)}`;

  const regle = (l, v) => `<div class="set">${l}<span class="v">${v}</span></div>`;
  $("#s-reglages").innerHTML = `<button class="back" data-close>‹ Novice</button><div class="hd"><h1>Réglages</h1></div>
    <div class="foot" style="margin-top:4px">Ta méthode du scan global, telle que Novice l'applique. Les modifier depuis l'appli arrivera avec les essais (Novice bis).</div>
    <div class="group-t">Six questions · fondamental sur 100</div>
    <div class="list">${regle("Q1 Résultats et guidance", "30 pts") + regle("Q2 Potentiel analystes (plein à 12 %)", "20 pts") + regle("Q3 Momentum sectoriel", "12 pts") + regle("Q4 Catalyseur à 90 jours", "15 pts") + regle("Q5 Force relative", "13 pts") + regle("Q6 Risques", "10 pts")}</div>
    <div class="group-t">Décision</div>
    <div class="list">${regle("Poids fondamental / technique", "60 / 40") + regle("Seuil d'achat", "68") + regle("Seuil en régime orange", "73") + regle("Écarter si résultats sous", "7 séances") + regle("Positions maximum", "20 × 300 €")}</div>
    <div class="group-t">Sortie</div>
    <div class="list">${regle("Stop posé à l'achat", "4 × ATR14") + regle("Niveau de vente", "MM50 − 1 ATR") + regle("Clôtures sous le niveau", "2") + regle("Butoir", "6 mois")}</div>
    <div class="group-t">GitHub (pour agir depuis l'appli)</div>
    <div class="list" id="blocGithub"></div>
    <div class="group-t">Hypothèses de coût</div>
    <div class="list">${regle("Frais Trade Republic", "1 € + 1 €") + regle("Écart achat / vente", "0,1 % par côté") + regle("Change", "cours du jour")}</div>`;
  blocGithub();
}

// ------------------------------------------------------------------ Marchés
function vueMarches() {
  const r = R(), liste = r.short_list || [];
  const regimes = Object.entries(r.regimes || {});
  const compte = c => regimes.filter(([, v]) => v === c).length;
  const dominant = ["ROUGE", "ORANGE", "VERT"].find(c => r.regimes && r.regimes["^GSPC"] === c) || "VERT";
  const statutChip = s => s === "conditions réunies" ? "in" : s === "sous surveillance" ? "al" : "neutre";
  const actus = Object.entries(D.actus || {}).flatMap(([t, l]) => (l || []).map(a => ({...a, ticker: t})))
    .sort((a, b) => (b.date || "").localeCompare(a.date || "")).slice(0, 40);
  $("#v-marches").innerHTML = `
    <div class="hd"><div><div class="over">Scan du ${dateFr(r.date_scan)}${r.provisoire ? " · provisoire" : ""}</div><h1>Marchés</h1></div><button class="scanbtn" id="btnScan"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M20 12a8 8 0 1 1-2.3-5.6"/><path d="M20 4v5h-5"/></svg>Scanner</button></div>
    <div style="padding:0 16px"><div class="seg"><button class="on" data-s="mk-sig">Signaux</button><button data-s="mk-act">Actus</button></div></div>
    <div id="mk-sig">
      <div class="card" style="margin-top:14px"><div class="climat"><span class="feu ${esc(dominant)}"></span><div><b style="font-size:15px">S&amp;P 500 en régime ${esc(dominant.toLowerCase())}</b>
        <div class="over" style="font-size:12.5px">Tous indices : ${compte("VERT")} verts, ${compte("ORANGE")} orange, ${compte("ROUGE")} rouges. Seuil d'achat à 73 en orange, aucun achat en rouge.</div></div></div></div>
      <h2>Short list</h2>
      <div class="list">${liste.map((t, i) => `<div class="li tappable" data-fiche="${esc(t.ticker)}"><div class="rank">${i + 1}</div><div class="logo">${esc(t.ticker)}</div><div class="t"><b>${esc(t.nom)}</b><span class="chip ${statutChip(t.statut)}" style="display:inline-block;margin-top:4px">${esc(t.statut || "")}</span></div><div class="r">${nb(t.score_global, 0)}<span>score</span></div></div>`).join("")}</div>
      <div class="foot" style="margin-top:0">Classement par force relative parmi ${nb(r.univers_analyse, 0)} titres, puis six questions sur les 10 premiers. Score global = 0,6 × fondamental + 0,4 × technique.</div>
    </div>
    <div id="mk-act" hidden>
      <div class="list news" style="margin-top:14px">${actus.length ? actus.map(a => `<a class="li" href="${lien(a.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;color:inherit"><div class="logo">${esc(a.ticker)}</div><div class="t"><span class="kind">${esc(a.source || "")}</span><b>${esc(a.titre)}</b><span>${dateFr(a.date)}</span></div></a>`).join("") : `<div class="li"><div class="empty">Pas d'actus ce soir.</div></div>`}</div>
      <div class="foot" style="margin-top:0">Articles Yahoo Finance sur les titres de la short list. Les sources lues par Claude sont dans chaque fiche titre.</div>
    </div>`;
  segments($("#v-marches"), ["mk-sig", "mk-act"]);
  $("#btnScan").onclick = scanner;
}

// ------------------------------------------------------------------ Fiche titre
function fiche(t) {
  const g = grilleDe(t), lec = (D.lectures || {})[t] || {}, cours = (D.cours || {})[t] || [];
  const s = (R().short_list || []).find(x => x.ticker === t) || {};
  const der = cours.at(-1), avant = cours.at(-2);
  const varJ = der && avant ? (der[1] / avant[1] - 1) * 100 : null;
  const pos = (D.novice.positions || []).find(p => p.ticker === t && p.etat !== "vendue");
  const statut = g ? g.statut : null;
  const Q = [["Q1", "Résultats et guidance"], ["Q2", "Potentiel analystes"], ["Q3", "Momentum sectoriel"], ["Q4", "Catalyseur à 90 jours"], ["Q5", "Force relative"], ["Q6", "Risques"]];
  $("#s-fiche").innerHTML = `<button class="back" data-close>‹ Retour</button>
    <div class="hd"><div class="row" style="gap:12px;justify-content:flex-start"><div class="logo" style="width:48px;height:48px">${esc(t)}</div><div><h1 style="font-size:26px">${esc(nomDe(t))}</h1><div class="over">${esc(t)}${s.secteur ? " · " + esc(s.secteur) : ""}</div></div></div></div>
    <div class="card" style="margin-top:12px">
      <div class="row"><div><div class="big" style="font-size:32px">${der ? nb(der[1], 2) : "—"} <span style="font-size:15px" class="muted">${esc(s.devise || "")}</span></div><div style="font-size:14px;margin-top:4px"><b class="${classe(varJ)}">${pct(varJ)}</b> <span class="muted">dernière séance</span></div></div>${pos ? `<span class="pill">Novice · ${esc(pos.etat)}</span>` : ""}</div>
      ${cours.length > 1 ? `<svg id="courbeFiche" viewBox="0 0 320 150" width="100%" height="150" style="display:block;margin-top:12px"></svg><div class="legend"><span><i style="background:var(--gold-2)"></i>Cours</span><span><i style="background:var(--warn)"></i>Niveau de vente (MM50 − ATR)</span></div>` : ""}
    </div>
    ${g ? `<h2>Score global</h2><div class="card">
      <div class="row"><div class="score"><b>${nb(g.score_global, 0)}</b><span class="muted">/ 100</span></div><span class="chip ${statut === "conditions réunies" ? "in" : statut === "sous surveillance" ? "al" : "neutre"}">${esc(statut)}</span></div>
      <div class="rowmini"><span>Fondamental <b style="color:var(--ink)">${nb(g.fondamental, 0)}</b> × 0,6</span><span>Technique <b style="color:var(--ink)">${nb(g.technique, 0)}</b> × 0,4</span></div>
      <div class="over" style="font-size:12.5px;margin-top:8px">${esc(g.motif)}</div></div>
      <div class="card">${Q.map(([k, l]) => { const q = g.questions[k] || {}; return `<div class="q6 tappable" data-why><span class="n">${k}</span><span class="l">${l}<small class="why" hidden>${esc(q.detail)}</small></span><span class="p">${nb(q.points, 0)}<span class="muted" style="font-weight:500"> / ${q.max}</span></span></div>`; }).join("")}</div>
      <div class="foot" style="margin-top:-4px">Touche une question pour lire sa justification.${lec.modele ? ` Lecture de l'actualité : ${esc(lec.modele === "claude" ? "Claude, avec recherche web" : lec.modele)}.` : ""}</div>` : ""}
    ${(() => { const p = ((D.filtres || {}).presse || {})[t], an = ((D.filtres || {}).analystes || {})[t];
      if (!p && !an) return "";
      return `<h2>Filtres du Labo</h2><div class="card">
        ${p ? `<div class="row"><span>Presse sur 5 jours</span><b class="${p.euphorique ? "warn" : ""}">${p.articles_5j} articles${p.ton_moyen != null ? ", ton " + nb(p.ton_moyen, 1) : ""}${p.euphorique ? " · euphorique" : ""}</b></div>` : ""}
        ${an ? `<div class="row" style="margin-top:8px"><span>Objectifs d'analystes, 30 jours</span><b class="${an.baisse ? "down" : "up"}">${an.baisse ? "baisse" : "aucune baisse"}</b></div>${an.detail.length ? `<div class="over" style="font-size:12px;margin-top:4px">${an.detail.map(esc).join(" · ")}</div>` : ""}` : ""}
      </div>`; })()}
    ${(lec.sources || []).length ? `<h2>Sources lues</h2><div class="card sources">${lec.sources.slice(0, 12).map(x => `<a href="${lien(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.titre || x.url)}</a>`).join("")}</div>` : ""}
    ${((D.actus || {})[t] || []).length ? `<h2>Actus</h2><div class="list news">${D.actus[t].map(a => `<a class="li" href="${lien(a.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;color:inherit"><div class="t"><span class="kind">${esc(a.source || "")}</span><b>${esc(a.titre)}</b><span>${dateFr(a.date)}</span></div></a>`).join("")}</div>` : ""}`;
  ouvrir("fiche");
  const svg = $("#courbeFiche");
  if (svg) traceLignes(svg, [{d: cours.map(c => c[1]), c: css("--gold-2"), w: 2.2}, {d: cours.map(c => c[2]), c: css("--warn"), dash: 1}], 316, 148);
}

// ------------------------------------------------------------------ Mes actions
function vueActions() {
  const mes = D.mes_positions || {}, ouvertes = mes.ouvertes || [], ventes = mes.ventes || [];
  setTimeout(() => {
    const b = $("#btnAchat"); if (b) b.onclick = achat;
    $$("[data-vente]").forEach(x => x.onclick = () => vente(x.dataset.vente));
  });
  $("#v-actions").innerHTML = `
    <div class="hd"><div><div class="over">Trade Republic · réel</div><h1>Mes actions</h1></div><button class="scanbtn" id="btnAchat">+ Achat</button></div>
    ${ouvertes.length ? ouvertes.map(p => { const v = p.verdict || {};
      return `<div class="card" style="margin-top:14px">
        <div class="row"><div class="row" style="gap:12px;justify-content:flex-start"><div class="logo">${esc(p.ticker)}</div><div><b style="font-size:16px">${esc(p.nom || p.ticker)}</b><div class="over" style="font-size:12px">acheté ${nb(p.prix, 2)} le ${dateFr(p.date_achat)}${v.seances ? " · séance " + v.seances : ""}</div></div></div>
          <b class="${classe(v.dernier_cours / p.prix - 1)}" style="font-size:17px">${v.dernier_cours ? pct((v.dernier_cours / p.prix - 1) * 100) : "—"}</b></div>
        <div class="verdict v-${esc(v.verdict)}"><span class="ic">${v.verdict === "Garder" ? "✓" : v.verdict === "Alerte" ? "!" : "×"}</span><div><b>${esc(v.verdict || "?")}</b><span>${esc(v.raison || "")}</span></div></div>
        <div class="levels"><div><b>${nb(v.niveau_vente, 2)}</b><span>niveau de vente</span></div><div><b>${nb(v.stop, 2)}</b><span>stop 4 ATR</span></div><div><b>${pct(v.marge_avant_sortie_pct)}</b><span>marge avant sortie</span></div></div>
        <div class="row" style="margin-top:12px"><a href="#" data-fiche="${esc(p.ticker)}" style="font-size:13px">Graphique et actus</a><button class="scanbtn" data-vente="${esc(p.ticker)}">J'ai vendu</button></div>
      </div>`; }).join("")
      : `<div class="card" style="margin-top:14px"><div class="empty">Aucune position en cours. Quand tu achètes chez Trade Republic, touche <b>+ Achat</b> : Novice calculera ton stop, ton niveau de vente et te donnera un verdict chaque soir.</div></div>`}
    <h2>Mes ventes</h2>
    <div class="list">${ventes.slice().reverse().map(v => `<div class="li"><div class="logo">${esc(v.ticker)}</div><div class="t"><b>${esc(v.nom)}</b><span>${dateFr(v.date_achat)} → ${dateFr(v.date_vente)} · ${esc(v.motif)}</span></div><div class="r ${classe(v.gain_eur)}">${pct(v.gain_pct)}<span>${eur(v.gain_eur, 2)}</span></div></div>`).join("") || `<div class="li"><div class="empty">Aucune vente.</div></div>`}</div>
    ${ventes.length ? `<h2>Toi contre la règle</h2><div class="card"><div class="vsr"><span class="h">Titre</span><span class="h">Toi</span><span class="h">Règle aujourd'hui</span>
      ${ventes.map(v => { const r = v.regle || {}; return `<span>${esc(v.ticker)}</span><b class="${classe(v.gain_pct)}">${pct(v.gain_pct)}</b><span>${pct(r.gain_brut_pct)} <span class="muted">(${r.etat === "vendue" ? "vendue " + dateFr(r.date_sortie) : "encore ouverte"})</span></span>`; }).join("")}</div>
      <div class="empty" style="margin-top:12px">« Toi » : gain net, frais compris (estimé quand tu ne l'as pas saisi). « Règle » : ce que donnerait aujourd'hui la règle du système sur le même achat, avant frais et change. ${ventes.length} opérations ne permettent aucune conclusion.</div></div>` : ""}`;
}

// ------------------------------------------------------------------ Labo
function vueLabo() {
  const c = courbes(), cles = ["novice", ...Object.keys(D.labo || {})];
  const a = aligner(Object.fromEntries(cles.map(k => [k, c[k] || []])));
  const tri = cles.slice().sort((x, y) => (bilanDe(y).gain_net_moyen_pct ?? -1e9) - (bilanDe(x).gain_net_moyen_pct ?? -1e9));
  const bn = bilanDe("novice"), bt = bilanDe("tech");
  const marge = n => n ? 1.645 * 60 / Math.sqrt(n) : null;
  $("#v-labo").innerHTML = `
    <div class="hd"><div><div class="over">Qui fait mieux que Novice ?</div><h1>Labo</h1></div></div>
    <div style="padding:0 16px"><div class="seg"><button class="on" data-s="lab-pf">Portefeuilles</button><button data-s="lab-bilan">Bilan</button></div></div>
    <div id="lab-pf">
      <div class="card" style="margin-top:14px"><div class="row"><span class="over">Gain en euros depuis le lancement</span></div>
        ${a.dates.length > 1 ? `<svg id="courbeLabo" viewBox="0 0 320 150" width="100%" height="150" style="display:block;margin-top:10px"></svg><div class="legend"><span><i style="background:var(--gold-2)"></i>Novice</span><span><i style="background:var(--grey)"></i>les autres</span></div>` : `<div class="empty" style="margin-top:10px">Les courbes apparaîtront après les premiers achats.</div>`}</div>
      <h2>Classement</h2>
      <div class="list lb">${tri.map(k => { const b = bilanDe(k); const n = b.operations_closes || 0;
        return `<div class="li tappable" data-strat="${k}"><span class="dotc" style="background:${k === "novice" ? css("--gold-2") : col(COULEURS[k] || "--grey")}"></span><div class="t"><b>${NOMS[k] || k}${TEMOINS.includes(k) ? '<span class="temoin">TÉMOIN</span>' : ""}</b><span>${n} opérations closes · ${(b.positions_ouvertes || 0) + (b.achats_en_attente || 0)} en cours · ${n >= 100 ? "comparaison possible" : "trop tôt"}</span></div><div class="r ${classe(b.gain_net_moyen_pct)}">${pct(b.gain_net_moyen_pct)}<span>${eur(gainTotal(b))}</span></div></div>`; }).join("")}</div>
      <div class="foot" style="margin-top:0">Classé par gain net moyen par opération, frais compris, 300 € par position partout. Une stratégie qui ne bat pas le hasard et l'indice n'apporte rien.</div>
    </div>
    <div id="lab-bilan" hidden>
      <h2>Ta grille vaut-elle quelque chose ?</h2>
      <div class="card"><div class="bubble" style="font-size:14px">Novice (avec les six questions) contre le <b>top 10 technique seul</b> (sans elles).</div>
        <div class="kpi2"><div><b class="${classe(bn.gain_net_moyen_pct)}">${pct(bn.gain_net_moyen_pct)}</b><span>Novice, ${bn.operations_closes || 0} opérations</span></div><div><b class="${classe(bt.gain_net_moyen_pct)}">${pct(bt.gain_net_moyen_pct)}</b><span>Technique seul, ${bt.operations_closes || 0} opérations</span></div></div>
        <div class="empty" style="margin-top:12px">${(bn.operations_closes || 0) < 2 ? "Pas encore assez d'opérations closes pour comparer." : `Marge d'incertitude sur la moyenne de Novice : ±${nb(marge(bn.operations_closes), 0)} points. Tant que l'écart est plus petit, rien n'est prouvé.`}</div></div>
      <h2>Encore combien d'opérations ?</h2>
      <div class="card"><div class="row"><b style="font-size:15px">Gros écart (±10 pts)</b><span class="over">${bn.operations_closes || 0} / ~100</span></div><div class="prog"><i style="width:${Math.min(100, bn.operations_closes || 0)}%"></i></div>
        <div class="row" style="margin-top:14px"><b style="font-size:15px">Écart fin (±3 pts)</b><span class="over">${bn.operations_closes || 0} / ~1 100</span></div><div class="prog"><i style="width:${Math.min(100, (bn.operations_closes || 0) / 11)}%"></i></div>
        <div class="empty" style="margin-top:10px">Une opération de ce système varie énormément (écart-type d'environ 60 %). Le Labo tranchera les grands écarts en un an environ ; un écart de 1 ou 2 points restera invisible des années.</div></div>
    </div>`;
  segments($("#v-labo"), ["lab-pf", "lab-bilan"], s => s === "lab-pf" && tracerLabo());
  tracerLabo();
  function tracerLabo(focus) {
    const svg = $("#courbeLabo"); if (!svg) return;
    const ordre = cles.slice().sort((x, y) => (x === "novice") - (y === "novice") || (x === focus) - (y === focus));
    traceLignes(svg, ordre.map(k => ({d: a.out[k], c: k === "novice" ? css("--gold-2") : k === focus ? col(COULEURS[k]) : css("--grey"),
      w: k === "novice" ? 2.6 : k === focus ? 2 : 1.2, o: k === "novice" || k === focus ? 1 : .35, dash: TEMOINS.includes(k)})).reverse(), 316, 148);
  }
  vueLabo.tracer = tracerLabo;
}

function strategie(k) {
  const s = k === "novice" ? D.novice : (D.labo || {})[k] || {}, b = s.bilan || {}, pos = s.positions || [];
  $("#s-strat").innerHTML = `<button class="back" data-close>‹ Labo</button><div class="hd"><h1 style="font-size:26px">${NOMS[k] || k}</h1></div>
    <div class="stats" style="margin-top:12px"><div class="stat"><b>${b.operations_closes || 0}</b><span>opérations closes</span></div><div class="stat"><b class="${classe(b.gain_net_moyen_pct)}">${pct(b.gain_net_moyen_pct)}</b><span>gain net moyen</span></div><div class="stat"><b class="${classe(gainTotal(b))}">${eur(gainTotal(b))}</b><span>total</span></div></div>
    <div class="group-t">Positions</div>
    <div class="list">${pos.slice().reverse().map(p => `<div class="li tappable" data-fiche="${esc(p.ticker)}"><div class="logo">${esc(p.ticker)}</div><div class="t"><b>${esc(p.nom || p.ticker)}</b><span>${p.etat === "en attente" ? "achat demain" : p.etat === "vendue" ? dateFr(p.date_entree) + " → " + dateFr(p.date_sortie) + " · " + esc(p.motif) : "en cours depuis le " + dateFr(p.date_entree)}</span></div><div class="r ${classe(p.gain_eur)}">${p.gain_pct != null ? pct(p.gain_pct) : ""}<span>${p.gain_eur != null ? eur(p.gain_eur, 2) : ""}</span></div></div>`).join("") || `<div class="li"><div class="empty">Aucune position.</div></div>`}</div>`;
  ouvrir("strat");
  if (vueLabo.tracer) vueLabo.tracer(k);
}

demarrer().catch(e => { $("#app").innerHTML = `<div class="chargement">Erreur : ${esc(e.message)}</div>`; });
