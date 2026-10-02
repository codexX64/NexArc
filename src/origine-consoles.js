// Origine des consoles web : l'interface d'une carte de gestion (iDRAC, iLO,
// JetKVM, hyperviseur…) s'affiche dans NEXARC sans jamais s'exécuter sous
// l'origine de NEXARC. Le code d'une carte n'est pas le nôtre : servi depuis
// cette origine, il y lirait l'API avec la session de l'opérateur. Il est donc
// servi par un second écouteur (NEXARC_CONSOLE_URL) où rien de NEXARC ne
// vit : ni page, ni API, ni session.
//
// Chaque ouverture tire une passe de 256 bits, liée à la session qui l'a
// demandée, à une machine et à un accès. Elle voyage dans le chemin
// (/c/{passe}/…) : cette origine n'a aucun cookie à lire. Elle meurt avec la
// session, au plus tard après huit heures, et ne rouvre que cet accès.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Debit, adresseClient, lireCorps, sha256hex } from '../socle/src/index.js';
import { mandaterHttp } from './proxy.js';
import { accepter, connecter, refuser, verifierUpgrade } from './websocket.js';

const DUREE_MAX_MS = 8 * 3600e3;
// Assez pour les onglets d'un opérateur, pas assez pour gonfler la mémoire.
const PASSES_PAR_SESSION = 20;
const CHEMIN = /^\/c\/([A-Za-z0-9_-]{43})\/(.*)$/;
const ROLES_CONSOLE = new Set(['membre', 'admin']);

export class OrigineConsoles {
  constructor({ url, parc, comptes, proxys, journal, racine }) {
    this.origine = new URL(url).origin;
    this.parc = parc; this.comptes = comptes; this.proxys = proxys; this.journal = journal;
    this.script = fs.readFileSync(path.join(racine, 'web', 'reancrage.js'));
    this.passes = new Map();
    // Une page de carte charge des dizaines de ressources à l'ouverture.
    this.debit = new Debit({ max: 1200 });
    this.serveur = http.createServer((req, res) => this.traiter(req, res).catch(e => {
      // Corps refusé (413, 415) : dit tel quel ; tout le reste est une carte injoignable.
      const refus = e?.status >= 400 && e.status < 500;
      this.repondre(res, refus ? e.status : 502, refus ? e.message : 'Console injoignable.');
    }));
    this.serveur.on('upgrade', (req, socket) => this.mettreANiveau(req, socket).catch(() => socket.destroy()));
    this.serveur.headersTimeout = 20000;
    this.serveur.requestTimeout = 0;
  }

  ecouter(port, hote) { return new Promise(r => this.serveur.listen(port, hote, r)); }
  arreter() { return new Promise(r => { this.serveur.close(r); this.serveur.closeAllConnections(); }); }

  // Tire une passe pour l'accès `idx` de la machine, au nom de la session du
  // contexte ; `parent` est l'origine de la page qui encadrera la console.
  ouvrir(ctx, m, idx, type) {
    const t = Date.now();
    for (const [k, p] of this.passes) if (p.expire < t || !this.comptes.sessionVivante(p.jeton)) this.passes.delete(k);
    const siennes = [...this.passes].filter(([, p]) => p.jeton === ctx.jeton).sort((a, b) => a[1].expire - b[1].expire);
    while (siennes.length >= PASSES_PAR_SESSION) this.passes.delete(siennes.shift()[0]);
    const passe = crypto.randomBytes(32).toString('base64url');
    this.passes.set(sha256hex(passe), {
      jeton: ctx.jeton, compte: ctx.session.compte, machineId: m.id, idx, parent: ctx.origine,
      expire: Math.min(ctx.session.expire, t + DUREE_MAX_MS),
    });
    this.journal.ecrire({ acteur: ctx.session.compte, action: 'console.ouverte', objet: m.host, ip: ctx.ip, details: { type, idx } });
    return `${this.origine}/c/${passe}/`;
  }

  // La passe, si elle vaut encore : session vivante, rôle encore suffisant,
  // accès toujours déclaré (sa cible est relue, jamais gardée).
  resoudre(passe) {
    const p = this.passes.get(sha256hex(passe));
    if (!p) return null;
    const compte = this.comptes.compte(p.compte);
    if (p.expire < Date.now() || !this.comptes.sessionVivante(p.jeton) || !ROLES_CONSOLE.has(compte?.role)) {
      this.passes.delete(sha256hex(passe));
      return null;
    }
    const entree = this.parc.entreeConsole(p.machineId, p.idx);
    if (!entree || !/^https?:\/\//i.test(entree.target)) return null;
    return { ...p, base: entree.target.replace(/\/+$/, ''), pin: entree.pin || null };
  }

  // Une console n'a besoin que du plein écran et du presse-papiers ; le reste
  // des capacités du navigateur lui est fermé, quoi que la carte demande.
  entetes(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), midi=(), magnetometer=(), gyroscope=(), accelerometer=(), display-capture=(), fullscreen=(self), clipboard-read=(self), clipboard-write=(self)');
  }

  repondre(res, status, message) {
    if (res.headersSent) return res.destroy();
    this.entetes(res);
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: message }));
  }

  async traiter(req, res) {
    if (!this.debit.prendre(adresseClient(req, this.proxys))) return this.repondre(res, 429, 'Trop de requêtes.');
    const url = new URL(req.url, 'http://consoles');
    if (url.pathname === '/reancrage.js' && ['GET', 'HEAD'].includes(req.method)) {
      this.entetes(res);
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Content-Length': this.script.length });
      return res.end(req.method === 'HEAD' ? undefined : this.script);
    }
    const m = CHEMIN.exec(url.pathname);
    const cible = m && this.resoudre(m[1]);
    if (!cible) return this.repondre(res, 404, 'Introuvable.');
    // Une écriture ne vient que d'une page de cette origine : une passe qui
    // aurait fui ne sert pas à poster depuis un autre site.
    if (!['GET', 'HEAD'].includes(req.method) && req.headers.origin && req.headers.origin !== this.origine) return this.refuser(req, res, cible);
    const corps = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await lireCorps(req, { json: false, limite: 8 * 1024 * 1024 }) : null;
    this.entetes(res);
    mandaterHttp(req, res, { base: cible.base, reste: m[2], prefix: `/c/${m[1]}/`, pin: cible.pin, corps, parent: cible.parent });
  }

  // Une page d'un autre site qui écrit à la carte par une passe : refusée et
  // journalisée comme un refus d'accès du service (sans la passe, qui est un droit).
  refuser(req, res, cible) {
    const ip = adresseClient(req, this.proxys);
    this.journal.rare(`consoles:${ip}`, { acteur: cible.compte, action: 'acces.refuse', objet: '/c/', ip, resultat: 'refus', details: { cause: 'origine', origine: String(req.headers.origin).slice(0, 200) } });
    if (res) return this.repondre(res, 403, 'Origine refusée.');
  }

  async mettreANiveau(req, socket) {
    if (!this.debit.prendre(adresseClient(req, this.proxys))) return refuser(socket, 429, 'Too Many Requests');
    const v = verifierUpgrade(req, { origines: [this.origine] });
    const url = new URL(req.url, 'http://consoles');
    const m = CHEMIN.exec(url.pathname);
    const cible = m && this.resoudre(m[1]);
    if (!v.ok) { if (v.code === 403 && cible) this.refuser(req, null, cible); return refuser(socket, v.code, 'Forbidden'); }
    if (!cible) return refuser(socket, 404, 'Not Found');
    const amont = `${cible.base.startsWith('https') ? 'wss' : 'ws'}://${cible.base.replace(/^https?:\/\//, '')}/${m[2]}${url.search}`;
    // La carte d'abord : un message que le navigateur enverrait dès la
    // poignée de main ne se perd pas pendant qu'on la joint.
    let carte = null;
    try { carte = await connecter(amont, { pin: cible.pin }); } catch { /* carte injoignable : dit au navigateur ci-dessous */ }
    if (socket.destroyed) return carte?.close();
    const ws = accepter(req, socket, {});
    if (!carte) return ws.fermerCode(1011, 'console injoignable');
    ws.on('binaire', d => carte.envoyerBinaire(d));
    ws.on('texte', t => carte.envoyerTexte(t));
    carte.on('binaire', d => ws.envoyerBinaire(d));
    carte.on('texte', t => ws.envoyerTexte(t));
    ws.on('fermeture', () => carte.close());
    carte.on('fermeture', () => ws.close());
  }
}
