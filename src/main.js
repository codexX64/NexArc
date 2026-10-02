// Démarrage de NEXARC : configuration validée, base, socle commun (comptes,
// sessions, coffre), reprise de la 1.x, boucles de collecte et d'automatisation,
// serveur HTTP et mise à niveau WebSocket (pont VNC) écrite à la main, et, si
// son adresse est posée, l'origine à part des consoles web.
import http from 'node:http';
import path from 'node:path';
import { lireConfigNexarc, VERSION } from './config.js';
import { ouvrirBase, Parc } from './base.js';
import { Agents } from './agents.js';
import { Alertes } from './alertes.js';
import { Taches } from './taches.js';
import { Synapse } from './synapse.js';
import { lienDeSecours, migrerComptes, migrerParc } from './migration.js';
import { creerApi } from './api.js';
import { pont } from './vncbridge.js';
import { OrigineConsoles } from './origine-consoles.js';
import { verifierUpgrade, accepter, refuser } from './websocket.js';
import {
  Debit, ErreurHttp, demarrerSocle, entetesSecurite, envelopper, nonceCsp, politiqueContenu,
  repondreErreur, repondreJson, servirFichier, origineDe, adresseClient,
} from '../socle/src/index.js';

const RACINE = path.resolve(import.meta.dirname, '..');
const CONSOLE = { info: (...a) => console.log(...a), warn: (...a) => console.warn(...a), error: (...a) => console.error(...a) };
// Signalement privé d'une faille, sur le dépôt : lu par le mainteneur.
const CONTACT_SECURITE = 'https://github.com/CodexX64/nexarc/security/advisories/new';

// Diffuseur d'activité en direct (SSE). Chaque flux ouvert reçoit les lignes ;
// un flux fermé se retire de lui-même. Un flux tient une connexion ouverte :
// quelques onglets par session, deux cents en tout.
const FLUX_PAR_SESSION = 4, FLUX_MAX = 200;
class Flux {
  constructor() { this.abonnes = new Map(); }
  place(session) {
    return this.abonnes.size < FLUX_MAX && [...this.abonnes.values()].filter(s => s === session).length < FLUX_PAR_SESSION;
  }
  brancher(res, session) {
    this.abonnes.set(res, session);
    res.write(': ok\n\n');
    const battement = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* fermé */ } }, 25000);
    battement.unref?.();
    res.on('close', () => { clearInterval(battement); this.abonnes.delete(res); });
  }
  pousser(obj) {
    const ligne = `data: ${JSON.stringify(obj)}\n\n`;
    for (const res of this.abonnes.keys()) { try { res.write(ligne); } catch { this.abonnes.delete(res); } }
  }
}

export async function demarrer(env = process.env, { log = CONSOLE } = {}) {
  const cfg = lireConfigNexarc(env);
  const db = ouvrirBase(cfg.donnees);
  const socle = await demarrerSocle({
    service: { id: 'nexarc', nom: 'NEXARC', contactSecurite: CONTACT_SECURITE }, db, dossier: cfg.donnees, env, log,
    migrer: ({ comptes, coffre }) => migrerComptes({ db, comptes, coffre, log }),
  });
  migrerParc({ db, log });
  lienDeSecours({ db, comptes: socle.comptes, journal: socle.journal, urlPublique: socle.cfg.urlPublique, log });

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
  const taches = new Taches(db, { parc, synapse, journal: socle.journal, flux, commandeLibre: cfg.commandeLibre });
  const consoles = cfg.consoleUrl ? new OrigineConsoles({ url: cfg.consoleUrl, parc, comptes: socle.comptes, proxys: socle.portail.proxys, journal: socle.journal, racine: RACINE }) : null;
  const api = creerApi({ socle, cfg, db, parc, agents, alertes, taches, synapse, flux, racine: RACINE, consoles, log });
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
  // Seules les consoles et, s'il s'ouvre intégré, le bureau Mesh s'affichent en cadre.
  const cadres = [cfg.consoleUrl && new URL(cfg.consoleUrl).origin, cfg.meshEmbed && cfg.meshUrl && new URL(cfg.meshUrl).origin].filter(Boolean);
  const serveur = http.createServer(envelopper(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://nexarc');
      const ctx = socle.portail.contexte(req, res);
      if (!debit.prendre(ctx.ip)) { socle.journal.rare(`debit:${ctx.ip}`, { action: 'limite.atteinte', objet: 'requetes', ip: ctx.ip, resultat: 'refus' }); throw new ErreurHttp(429, 'Trop de requêtes.'); }
      ctx.url = url;
      const nonce = nonceCsp();
      entetesSecurite(res, { secure: ctx.securise, csp: politiqueContenu({ nonce, secure: ctx.securise, img: ['data:'], connect: ["'self'"], frame: cadres }) });
      if (await socle.portail.traiter(req, res, url, ctx)) return;
      if (await api.traiter(ctx)) return;
      if (!['GET', 'HEAD'].includes(req.method)) return repondreJson(res, 405, { error: 'Méthode non admise.' });
      if (url.pathname.startsWith('/socle/') && servirFichier(req, res, path.join(RACINE, 'socle', 'web'), url.pathname.slice(6), { nonce, cache: 'public, max-age=3600' })) return;
      const fichier = url.pathname === '/' ? '/index.html' : url.pathname;
      if (servirFichier(req, res, path.join(RACINE, 'web'), fichier, { nonce, gamme: socle.cfg.gamme })) return;
      repondreJson(res, 404, { error: 'Introuvable.' });
    } catch (e) { repondreErreur(res, e, { journal: log }); }
  }));

  serveur.on('upgrade', async (req, socket) => {
    try {
      const url = new URL(req.url, 'http://nexarc');
      // Une mise à niveau compte dans le débit de l'adresse, comme une requête.
      if (!debit.prendre(adresseClient(req, socle.portail.proxys))) return refuser(socket, 429, 'Too Many Requests');
      const v = verifierUpgrade(req, { origines: origines(req) });
      if (!v.ok) return refuser(socket, v.code, v.erreur);
      // Session du socle exigée et rôle vérifié AVANT la mise à niveau.
      const acces = autoriserWs(req);
      if (!acces) return refuser(socket, 401, 'Unauthorized');

      const m = /^\/vnc\/([A-Za-z0-9_-]{16})\/(\d+)$/.exec(url.pathname);
      if (m) return await upgradeVnc(req, socket, acces, m[1], Number(m[2]));
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

  async function upgradeVnc(req, socket, ctx, ref, idx) {
    const id = parc.idDe(ref); if (!id) return refuser(socket, 404);
    const entree = parc.entreeConsole(id, idx);
    if (!entree || entree.type !== 'vnc') return refuser(socket, 404);
    const cible = String(entree.target); const i = cible.lastIndexOf(':');
    const host = cible.slice(0, i).trim(), port = Number(cible.slice(i + 1));
    if (!host || !Number.isInteger(port)) return refuser(socket, 404);
    const m = parc.machine(id);
    const motDePasse = parc.ouvrirVncPw(entree, m.ref);
    const offert = String(req.headers['sec-websocket-protocol'] || '').split(',').map(x => x.trim());
    const ws = accepter(req, socket, { sousProtocole: offert.includes('binary') ? 'binary' : null });
    // noVNC se reconnecte seul : une ligne par session et par console suffit.
    socle.journal.rare(`console:${ctx.session.id}:${id}:${idx}`, { acteur: ctx.session.compte, action: 'console.ouverte', objet: m.host, ip: ctx.ip, details: { type: 'vnc', idx } }, 10 * 60e3);
    await pont(ws, host, port, { motDePasse }).catch(() => { try { ws.close(); } catch { /* fermé */ } });
  }

  serveur.headersTimeout = 20000;
  serveur.requestTimeout = 0;      // les flux SSE et WebSocket durent
  serveur.keepAliveTimeout = 5000;
  await new Promise(r => serveur.listen(cfg.port, cfg.hote, r));
  log.info(`NEXARC ${VERSION} à l'écoute sur ${cfg.hote}:${serveur.address().port}`);
  if (consoles) {
    await consoles.ecouter(cfg.consolePort, cfg.hote);
    log.info(`Consoles web sur ${cfg.hote}:${consoles.serveur.address().port}, servies à ${consoles.origine}`);
    const hoteConsoles = new URL(consoles.origine).hostname;
    if ([cfg.urlEnrolement, socle.cfg.urlPublique].some(u => u && new URL(u).hostname === hoteConsoles)) {
      log.warn?.(`NEXARC_CONSOLE_URL partage le nom d'hôte de NEXARC : les scripts des cartes restent à part, pas les cookies. Donne-lui son propre nom (README, « Consoles et cartes de gestion »).`);
    }
  }
  const arreter = () => new Promise(r => { socle.arreter(); clearInterval(bCollecte); clearInterval(bAutos); clearInterval(bPurge); consoles?.arreter(); serveur.close(() => { db.close(); r(); }); serveur.closeAllConnections?.(); });
  return { serveur, socle, cfg, db, parc, agents, alertes, taches, api, consoles, arreter };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  demarrer().then(({ arreter }) => {
    for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => arreter().then(() => process.exit(0)));
  }).catch(e => { console.error(e.message); process.exit(1); });
}
