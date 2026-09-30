// Démarrage de Sentinel : configuration validée, base, socle commun (comptes,
// sessions, coffre), reprise de la 1.x, boucles de collecte et d'automatisation,
// serveur HTTP, mandataire des consoles et mise à niveau WebSocket (pont VNC,
// mandataire WebSocket) écrite à la main.
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { lireConfigSentinel, VERSION } from './config.js';
import { ouvrirBase, Parc } from './base.js';
import { Agents } from './agents.js';
import { Alertes } from './alertes.js';
import { Taches } from './taches.js';
import { Synapse } from './synapse.js';
import { migrerComptes, migrerParc } from './migration.js';
import { creerApi } from './api.js';
import { pont } from './vncbridge.js';
import { mandaterHttp } from './proxy.js';
import { verifierUpgrade, accepter, connecter, refuser } from './websocket.js';
import {
  Debit, ErreurHttp, demarrerSocle, entetesSecurite, envelopper, nonceCsp, politiqueContenu,
  repondreErreur, repondreJson, servirFichier, lireCorps, origineDe,
} from '../socle/src/index.js';

const RACINE = path.resolve(import.meta.dirname, '..');
const CONSOLE = { info: (...a) => console.log(...a), warn: (...a) => console.warn(...a), error: (...a) => console.error(...a) };
// Signalement privé d'une faille, sur le dépôt : lu par le mainteneur.
const CONTACT_SECURITE = 'https://github.com/CodexX64/sentinel-rmm/security/advisories/new';

// Diffuseur d'activité en direct (SSE). Chaque flux ouvert reçoit les lignes ;
// un flux fermé se retire de lui-même.
class Flux {
  constructor() { this.abonnes = new Set(); }
  brancher(res) {
    this.abonnes.add(res);
    res.write(': ok\n\n');
    const battement = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* fermé */ } }, 25000);
    battement.unref?.();
    res.on('close', () => { clearInterval(battement); this.abonnes.delete(res); });
  }
  pousser(obj) {
    const ligne = `data: ${JSON.stringify(obj)}\n\n`;
    for (const res of this.abonnes) { try { res.write(ligne); } catch { this.abonnes.delete(res); } }
  }
}

export async function demarrer(env = process.env, { log = CONSOLE } = {}) {
  const cfg = lireConfigSentinel(env);
  const db = ouvrirBase(cfg.donnees);
  const socle = await demarrerSocle({
    service: { id: 'sentinel', nom: 'Sentinel', contactSecurite: CONTACT_SECURITE }, db, dossier: cfg.donnees, env, log,
    migrer: ({ comptes, coffre }) => migrerComptes({ db, comptes, coffre, log }),
  });
  migrerParc({ db, log });

  const parc = new Parc(db, { coffre: socle.coffre, horsLigneApres: cfg.horsLigneApres });
  let rescelles;
  try { rescelles = parc.resceller(); } catch (e) { socle.arreter(); db.close(); throw e; }
  if (rescelles.vnc || rescelles.redfish) log.info?.(`[coffre] Secrets d'appareils rescellés sous SOCLE_CLE : ${rescelles.vnc} mot(s) de passe VNC, ${rescelles.redfish} identifiant(s) Redfish.`);
  if (rescelles.retires) {
    log.warn?.(`[coffre] ${rescelles.retires} secret(s) d'appareil illisible(s) sous les deux clés, retiré(s) : à ressaisir.`);
    socle.journal.ecrire({ acteur: 'système', action: 'coffre.secrets_retires', resultat: 'erreur', details: { n: rescelles.retires } });
  }
  const synapse = new Synapse({ url: cfg.synapseUrl, jeton: cfg.synapseJeton, log });
  const flux = new Flux();
  const alertes = new Alertes(db, {
    parc, flux, synapse,
    seuils: { horsLigneMin: cfg.alerteHorsLigneMin, correctifsJours: cfg.alerteCorrectifsJours, disquePct: cfg.alerteDisquePct, risque: cfg.alerteRisque },
  });
  const agents = new Agents(db, { parc, maxMachines: cfg.maxMachines, synapse, alertes, flux: l => flux.pousser({ t: 'flux', ...l }) });
  const taches = new Taches(db, { parc, synapse, journal: socle.journal, flux });
  const api = creerApi({ socle, cfg, db, parc, agents, alertes, taches, synapse, flux, racine: RACINE });
  // Données d'un compte : exportées à sa demande, neutralisées à sa suppression.
  socle.portail.exporteur = compteId => parc.donneesDe(compteId);
  socle.comptes.apresSuppression.push(compteId => parc.oublier(compteId));

  // Boucles de fond : collecte (marquage hors ligne), automatisations, purge.
  const bCollecte = setInterval(() => { try { for (const l of agents.collecter()) flux.pousser({ t: 'flux', ...l }); } catch (e) { log.error?.('collecte:', e.message); } }, cfg.intervalle * 1000);
  const bAutos = setInterval(() => { try { taches.tour(); } catch (e) { log.error?.('automatisation:', e.message); } }, 60000);
  const bPurge = setInterval(() => {
    try { agents.purger(); alertes.purger(); } catch (e) { log.error?.('purge:', e.message); }
  }, 600000);
  for (const b of [bCollecte, bAutos, bPurge]) b.unref?.();

  const origines = req => {
    const o = origineDe(req, socle.portail.proxys);
    return [o, ...socle.portail.originesEnPlus].filter(Boolean);
  };

  // Toute requête compte : une page en demande une vingtaine, une rafale des milliers.
  const debit = new Debit({ max: 900 });
  const serveur = http.createServer(envelopper(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://sentinel');
      const ctx = socle.portail.contexte(req, res);
      if (!debit.prendre(ctx.ip)) { socle.journal.rare(`debit:${ctx.ip}`, { action: 'limite.atteinte', objet: 'requetes', ip: ctx.ip, resultat: 'refus' }); throw new ErreurHttp(429, 'Trop de requêtes.'); }
      ctx.url = url;
      // Mandataire des consoles : la cible pose sa propre politique de cadrage,
      // on ne lui applique pas la CSP stricte du service.
      if (url.pathname.startsWith('/console/')) return await mandaterConsole(req, res, url, ctx);
      const nonce = nonceCsp();
      entetesSecurite(res, { secure: ctx.securise, csp: politiqueContenu({ nonce, secure: ctx.securise, img: ['data:'], connect: ["'self'"], frame: ["'self'"] }) });
      if (await socle.portail.traiter(req, res, url, ctx)) return;
      if (await api.traiter(ctx)) return;
      if (!['GET', 'HEAD'].includes(req.method)) return repondreJson(res, 405, { error: 'Méthode non admise.' });
      if (url.pathname.startsWith('/socle/') && servirFichier(req, res, path.join(RACINE, 'socle', 'web'), url.pathname.slice(6), { nonce, cache: 'public, max-age=3600' })) return;
      const fichier = url.pathname === '/' ? '/index.html' : url.pathname;
      if (servirFichier(req, res, path.join(RACINE, 'web'), fichier, { nonce })) return;
      repondreJson(res, 404, { error: 'Introuvable.' });
    } catch (e) { repondreErreur(res, e, { journal: log }); }
  }));

  // ---- mise à niveau WebSocket : pont VNC et mandataire des consoles ----
  serveur.on('upgrade', async (req, socket) => {
    try {
      const url = new URL(req.url, 'http://sentinel');
      const v = verifierUpgrade(req, { origines: origines(req) });
      if (!v.ok) return refuser(socket, v.code, v.erreur);
      // Session du socle exigée et rôle vérifié AVANT la mise à niveau.
      const acces = autoriserWs(req);
      if (!acces) return refuser(socket, 401, 'Unauthorized');

      let m = /^\/vnc\/([A-Za-z0-9_-]{16})\/(\d+)$/.exec(url.pathname);
      if (m) return await upgradeVnc(req, socket, m[1], Number(m[2]));
      m = /^\/console\/([A-Za-z0-9_-]{16})\/(\d+)\/(.*)$/.exec(url.pathname);
      if (m) return await upgradeConsole(req, socket, url, m[1], Number(m[2]), m[3]);
      refuser(socket, 404, 'Not Found');
    } catch { try { socket.destroy(); } catch { /* déjà fermé */ } }
  });

  // Le contexte du socle, pas une copie : même nom de cookie (préfixe __Host-
  // derrière un relais HTTPS déclaré, sans préfixe en HTTP local), même session,
  // même contrôle de rôle et même journal des refus que pour une route HTTP.
  function autoriserWs(req) {
    const ctx = socle.portail.contexte(req, null);
    try { socle.portail.exiger(ctx, { role: 'membre' }); return ctx; } catch { return null; }
  }

  async function upgradeVnc(req, socket, ref, idx) {
    const id = parc.idDe(ref); if (!id) return refuser(socket, 404);
    const item = parc.entreeConsole(id, idx);
    if (!item || item.type !== 'vnc') return refuser(socket, 404);
    const cible = String(item.target); const i = cible.lastIndexOf(':');
    const host = cible.slice(0, i).trim(), port = Number(cible.slice(i + 1));
    if (!host || !Number.isInteger(port)) return refuser(socket, 404);
    const motDePasse = parc.ouvrirVncPw(item, parc.machine(id).ref);
    const offert = String(req.headers['sec-websocket-protocol'] || '').split(',').map(x => x.trim());
    const ws = accepter(req, socket, { sousProtocole: offert.includes('binary') ? 'binary' : null });
    await pont(ws, host, port, { motDePasse }).catch(() => { try { ws.close(); } catch { /* fermé */ } });
  }

  async function upgradeConsole(req, socket, url, ref, idx, reste) {
    const cible = resoudreConsoleAmont(ref, idx);
    if (!cible || !cible.base) return refuser(socket, 404);
    const scheme = cible.base.startsWith('https') ? 'wss' : 'ws';
    const host = cible.base.replace(/^https?:\/\//, '');
    const amont = `${scheme}://${host}/${reste}` + (url.search || '');
    const ws = accepter(req, socket, {});
    let up;
    try { up = await connecter(amont, { pin: cible.pin || null }); }
    catch { return ws.fermerCode(1011, 'console injoignable'); }
    // Relais bidirectionnel binaire/texte.
    ws.on('binaire', d => up.envoyerBinaire(d));
    ws.on('texte', t => up.envoyerTexte(t));
    up.on('binaire', d => ws.envoyerBinaire(d));
    up.on('texte', t => ws.envoyerTexte(t));
    ws.on('fermeture', () => up.close());
    up.on('fermeture', () => ws.close());
  }

  async function mandaterConsole(req, res, url, ctx) {
    const m = /^\/console\/([A-Za-z0-9_-]{16})\/(\d+)\/(.*)$/.exec(url.pathname);
    if (!m) return repondreJson(res, 404, { error: 'Introuvable.' });
    // Session complète, rôle membre : le mandataire donne le contrôle de la carte.
    let s;
    try { s = socle.portail.exiger(ctx, { role: 'membre' }); void s; } catch (e) { return repondreErreur(res, e, { journal: log }); }
    const cible = resoudreConsoleAmont(m[1], Number(m[2]));
    if (!cible || !cible.base) return repondreJson(res, 404, { error: 'Console introuvable.' });
    const corps = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await lireCorps(req, { json: false, limite: 8 * 1024 * 1024 }) : null;
    req.params = { reste: m[3] };
    mandaterHttp(req, res, { base: cible.base, prefix: `/console/${m[1]}/${m[2]}/`, pin: cible.pin, corps });
  }

  // Résout un (ref, idx) en cible amont, CÔTÉ SERVEUR, limitée aux consoles
  // enregistrées : le client ne fournit jamais l'adresse.
  function resoudreConsoleAmont(ref, idx) {
    const id = parc.idDe(ref); if (!id) return null;
    const item = parc.entreeConsole(id, idx); if (!item) return null;
    if (item.type === 'mesh') return { base: (cfg.meshUrl || '').replace(/\/+$/, ''), item, pin: null };
    if (!/^https?:\/\//i.test(item.target)) return null;
    return { base: item.target.replace(/\/+$/, ''), item, pin: item.pin || null };
  }

  serveur.headersTimeout = 20000;
  serveur.requestTimeout = 0;      // les flux SSE et WebSocket durent
  serveur.keepAliveTimeout = 5000;
  await new Promise(r => serveur.listen(cfg.port, cfg.hote, r));
  log.info(`Sentinel ${VERSION} à l'écoute sur ${cfg.hote}:${serveur.address().port}`);
  const arreter = () => new Promise(r => { socle.arreter(); clearInterval(bCollecte); clearInterval(bAutos); clearInterval(bPurge); serveur.close(() => { db.close(); r(); }); serveur.closeAllConnections?.(); });
  return { serveur, socle, cfg, db, parc, agents, alertes, taches, api, arreter };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  demarrer().then(({ arreter }) => {
    for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => arreter().then(() => process.exit(0)));
  }).catch(e => { console.error(e.message); process.exit(1); });
}
