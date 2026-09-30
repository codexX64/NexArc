// Routes de Sentinel. Chaque route dit qui peut l'appeler : session du socle
// (avec son rôle), jeton de service du Hub, ou jeton d'agent — et rien d'autre.
// Toute machine désignée par une requête est résolue par sa référence publique
// et son autorisation vérifiée. Les actions sensibles (secrets d'appareil,
// commande libre, suppression) exigent le rôle admin et un renfort récent.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ErreurHttp, Routeur, Debit, lireCorps, valider, repondreJson, egal } from '../socle/src/index.js';
import { DEMANDES, CIBLES, chargeRefusee } from './taches.js';
import { TYPES, typesPublics, normaliser, cibleInterdite } from './consoles.js';
import { nodeValide, urlBureau } from './mesh.js';
import { sousReseau, diffusionDirigee, emettre } from './wol.js';
import { observer, empreinte } from './tls.js';
import * as redfish from './redfish.js';
import * as enroll from './enroll.js';
import { MAX_AUTOMATISATIONS } from './base.js';

const NOM_HOTE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/;

const S = {
  // Remontée d'un agent : bornée par schéma (champ inconnu refusé, tailles bornées).
  ingest: {
    hostname: { type: 'chaine', requis: true, max: 80, motif: NOM_HOTE },
    ip: { type: 'chaine', max: 45 }, os: { type: 'chaine', max: 60 }, oskind: { type: 'chaine', parmi: ['win', 'lin', 'mac', 'srv'], defaut: 'win' },
    role: { type: 'chaine', max: 40 }, site: { type: 'chaine', max: 40, defaut: 'Agents' },
    cpu: { type: 'entier', min: 0, max: 100, defaut: 0 }, ram: { type: 'entier', min: 0, max: 100, defaut: 0 }, disk: { type: 'entier', min: 0, max: 100, defaut: 0 },
    av: { type: 'chaine', max: 60, defaut: '' }, fw: { type: 'chaine', max: 60, defaut: '' }, enc: { type: 'chaine', max: 60, defaut: '' },
    patch: { type: 'entier', min: 0, max: 999, defaut: 0 }, mesh_node: { type: 'chaine', max: 200, defaut: '' },
    inventory: { type: 'json', profondeur: 6 }, software: { type: 'liste', max: 3000, de: { type: 'json', profondeur: 4 } }, updates: { type: 'liste', max: 800, de: { type: 'json', profondeur: 4 } },
  },
  tache: { kind: { type: 'chaine', requis: true, parmi: DEMANDES }, payload: { type: 'chaine', max: 4000, defaut: '' } },
  resultat: { output: { type: 'chaine', max: 200000, defaut: '' }, rc: { type: 'entier', min: -2147483648, max: 2147483647, defaut: 0 } },
  consoles: { consoles: { type: 'liste', max: 8, requis: true, de: { type: 'json', profondeur: 4 } } },
  meshNode: { mesh_node: { type: 'chaine', max: 200, defaut: '' } },
  redfish: { url: { type: 'chaine', max: 500, defaut: '' }, user: { type: 'chaine', max: 64, defaut: '' }, password: { type: 'chaine', max: 200, defaut: '' } },
  power: { action: { type: 'chaine', requis: true, parmi: Object.keys(redfish.ACTIONS) } },
  hote: {
    host: { type: 'chaine', requis: true, max: 60, motif: NOM_HOTE }, ip: { type: 'chaine', max: 45, defaut: '' },
    site: { type: 'chaine', max: 40, defaut: 'Matériel' }, ctype: { type: 'chaine', requis: true, parmi: Object.keys(TYPES) },
    target: { type: 'chaine', requis: true, max: 500 }, label: { type: 'chaine', max: 40, defaut: '' }, embed: { type: 'booleen', defaut: true },
  },
  auto: {
    nom: { type: 'chaine', requis: true, max: 60 }, kind: { type: 'chaine', requis: true, parmi: DEMANDES }, payload: { type: 'chaine', max: 2000, defaut: '' },
    cible: { type: 'chaine', parmi: [...CIBLES], defaut: 'tous' }, cible_val: { type: 'chaine', max: 60, defaut: '' },
    toutes_h: { type: 'entier', min: 1, max: 720, defaut: 24 }, heure: { type: 'entier', min: 0, max: 23, defaut: 2 },
  },
  pin: { idx: { type: 'entier', min: 0, max: 7 }, redfish: { type: 'booleen', defaut: false }, fp: { type: 'chaine', requis: true, max: 100 } },
  acces: { idx: { type: 'entier', min: 0, max: 7, defaut: 0 } },
  // Site et nom sont contrôlés à part (enroll.controler) : ils entrent dans un script root.
  inscription: { site: { type: 'chaine', max: 60, defaut: 'Agents' }, name: { type: 'chaine', max: 60, defaut: '' }, relay: { type: 'booleen', defaut: false } },
  echange: { code: { type: 'chaine', requis: true, max: 40 } },
};

// Chaque route non publique déclare dans ses options le rôle minimal qu'elle
// exige (lecture, membre, admin). La déclaration ne remplace pas le contrôle,
// fait dans le gestionnaire : l'essai « autorisation » balaie toutes les routes
// et vérifie que l'un et l'autre concordent.
export function creerApi({ socle, cfg, db, parc, agents, alertes, taches, synapse, flux, racine, consoles }) {
  const r = new Routeur();
  const { portail, journal, limiteur } = socle;
  const debitReveil = new Debit({ max: 30 }), debitPower = new Debit({ max: 20 }), debitIngest = new Debit({ max: cfg.ingestMinute });

  // Codes d'inscription, jetons d'agents et jeton du Hub : chaque échec compte
  // pour l'adresse, qui se bloque par paliers (limiteur persistant du socle).
  // Le compteur est à part de celui des connexions humaines : un poste révoqué
  // qui insiste ne bloque pas les opérateurs derrière la même adresse.
  const cleMachine = ctx => [`ip:machine:${ctx.ip}`];
  const controlerEchecs = ctx => limiteur.controler(cleMachine(ctx));
  const refuserPreuve = (ctx, message) => {
    limiteur.echec(cleMachine(ctx));
    journal.rare(`machine:${ctx.ip}`, { action: 'connexion.jeton', objet: ctx.url.pathname, ip: ctx.ip, resultat: 'refus' });
    throw new ErreurHttp(401, message);
  };

  // Un jeton présenté est vérifié, et un faux compte comme un échec : il ne
  // retombe jamais sur la session.
  const estHub = ctx => {
    const h = String(ctx.req.headers.authorization || '');
    if (!h.startsWith('Bearer ')) return false;
    controlerEchecs(ctx);
    if (cfg.jetonHub && egal(h.slice(7), cfg.jetonHub)) return true;
    return refuserPreuve(ctx, 'Jeton de service invalide.');
  };
  const session = (ctx, opts = {}) => portail.exiger(ctx, { role: 'lecture', ...opts });
  const machine = ref => parc.idDe(ref) ?? (() => { throw new ErreurHttp(404, 'Machine introuvable.'); })();
  const meshActif = () => !!cfg.meshUrl;

  // Corps validé (limite adaptée à l'inventaire d'un agent).
  const corps = async (ctx, schema, gros = false) => valider(await lireCorps(ctx.req, { limite: gros ? 512 * 1024 : 64 * 1024 }), schema);

  // ───────── sonde publique ─────────
  r.get('/api/health', ctx => repondreJson(ctx.res, 200, { ok: true }), { public: true });

  // ───────── état, résumé, collecte ─────────
  r.get('/api/state', ctx => { if (!estHub(ctx)) session(ctx); return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() }; }, { hub: true, role: 'lecture' });
  r.get('/api/summary', ctx => { if (!estHub(ctx)) session(ctx); return parc.resume(); }, { hub: true, role: 'lecture' });
  r.post('/api/collect', ctx => { session(ctx, { role: 'membre' }); for (const l of agents.collecter()) flux.pousser({ t: 'flux', ...l }); return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() }; }, { role: 'membre' });

  // Flux d'activité en direct (SSE), à la place du sondage de la 1.x.
  r.get('/api/activite', ctx => {
    const s = session(ctx);
    if (!flux.place(s.id)) throw new ErreurHttp(429, 'Trop de flux d\'activité ouverts : ferme un onglet.');
    ctx.res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store, no-transform', 'X-Accel-Buffering': 'no' });
    flux.brancher(ctx.res, s.id);
    return undefined; // la réponse reste ouverte
  }, { role: 'lecture' });

  // ───────── alertes ─────────
  // Acquitter : « vu, pris en charge ». L'alerte reste ouverte tant que sa
  // cause dure ; elle se résout d'elle-même quand la mesure redevient bonne.
  r.post('/api/alerts/:ref/ack', ctx => {
    const s = session(ctx, { role: 'membre' });
    if (!alertes.acquitter(ctx.params.ref, { identifiant: s.compteLigne.identifiant, compte: s.compte })) throw new ErreurHttp(404, 'Alerte introuvable.');
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'membre' });

  // ───────── détail d'une machine : logiciels, tâches ─────────
  r.get('/api/machines/:ref/software', ctx => {
    session(ctx); const m = parc.machine(machine(ctx.params.ref));
    let sw = []; try { sw = m.software ? JSON.parse(m.software) : []; } catch { sw = []; }
    return { software: sw };
  }, { role: 'lecture' });
  r.get('/api/machines/:ref/jobs', ctx => {
    session(ctx); const id = machine(ctx.params.ref);
    return { jobs: taches.liste(id, 25).map(t => parc.tachePublique(t)) };
  }, { role: 'lecture' });
  r.post('/api/machines/:ref/jobs', async ctx => {
    const hub = estHub(ctx);
    const s = hub ? null : session(ctx, { role: 'membre' });
    const id = machine(ctx.params.ref);
    const m = parc.machine(id);
    if (m.source !== 'agent') throw new ErreurHttp(409, 'Cette machine n\'a pas d\'agent (accès matériel seul).');
    const b = await corps(ctx, S.tache);
    // Commande libre : rôle admin + renfort récent, et seulement si activée.
    if (b.kind === 'cmd') {
      if (hub) throw new ErreurHttp(403, 'Une commande libre passe par un opérateur, jamais par le Hub.');
      if (!cfg.commandeLibre) throw new ErreurHttp(403, 'Commande libre désactivée (SENTINEL_ALLOW_EXEC=0).');
      portail.exiger(ctx, { role: 'admin', renfort: true });
    }
    const refus = chargeRefusee(b.kind, b.payload.trim());
    if (refus) throw new ErreurHttp(422, refus);
    if (taches.enAttente(id) >= 20) throw new ErreurHttp(429, 'Trop de tâches en attente sur cette machine.');
    const t = taches.creer(id, { kind: b.kind, payload: b.payload.trim(), auteur: hub ? 'hub' : s.compteLigne.identifiant, auteurCompte: hub ? null : s.compte, sensible: b.kind === 'cmd' });
    return { ok: true, id: t.ref };
  }, { hub: true, role: 'membre' });

  // ───────── consoles ─────────
  r.get('/api/console-types', ctx => { session(ctx); return { types: typesPublics(meshActif()) }; }, { role: 'lecture' });

  // Ouvrir un accès : une passe pour l'origine des consoles, ou un jeton de
  // connexion Mesh. Chacun est un droit tiré pour l'occasion : POST.
  r.post('/api/machines/:ref/remote', async ctx => {
    session(ctx, { role: 'membre' });
    const { idx } = await corps(ctx, S.acces);
    const m = parc.machine(machine(ctx.params.ref));
    const items = consolesEffectives(m);
    if (!items.length) throw new ErreurHttp(409, 'Aucun accès distant configuré pour cette machine.');
    if (idx >= items.length) throw new ErreurHttp(404, 'Accès introuvable.');
    const item = items[idx];
    if (item.type === 'vnc') return { type: 'vnc', embed: true, idx, label: item.label }; // le client ouvre /vnc/...
    if (item.type === 'mesh') {
      if (!meshActif()) throw new ErreurHttp(503, 'MeshCentral non configuré.');
      const url = urlBureau(item.target, { meshUrl: cfg.meshUrl, user: cfg.meshUser, cle: cfg.meshCle, viewmode: cfg.meshViewmode, hide: cfg.meshHide });
      return { url, embed: cfg.meshEmbed, label: item.label, type: 'mesh' };
    }
    if (item.embed && consoles) {
      // Pas de passe pour une carte que le mandataire refuserait de joindre.
      if (/^https/i.test(item.target) && !item.pin) throw new ErreurHttp(409, 'Certificat de la carte non épinglé : confirme son empreinte.');
      return { url: consoles.ouvrir(ctx, m, idx, item.type), embed: true, label: item.label, type: item.type };
    }
    return { url: item.target, embed: false, label: item.label, type: item.type };
  }, { role: 'membre' });

  // Un accès distant dit où le serveur se connecte sur le réseau interne, et
  // porte parfois un secret d'appareil (mot de passe VNC) : seul un
  // administrateur sous renfort récent le déclare, et le journal le garde.
  r.put('/api/machines/:ref/consoles', async ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const b = await corps(ctx, S.consoles);
    const id = machine(ctx.params.ref);
    let items; try { items = normaliser(b.consoles, nodeValide); } catch (e) { throw new ErreurHttp(422, e.message); }
    parc.enregistrerConsoles(id, items);
    journal.ecrire({ acteur: ctx.session.compte, action: 'consoles.modifiees', objet: parc.machine(id).host, ip: ctx.ip, details: { n: items.length, types: items.map(c => c.type).join(',') } });
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'admin' });

  r.put('/api/machines/:ref/mesh-node', async ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const id = machine(ctx.params.ref);
    const b = await corps(ctx, S.meshNode);
    const node = (b.mesh_node || '').trim();
    if (node && !nodeValide(node)) throw new ErreurHttp(422, 'Nœud MeshCentral invalide.');
    db.prepare('UPDATE machines SET mesh_node = ? WHERE id = ?').run(node || null, id);
    journal.ecrire({ acteur: ctx.session.compte, action: 'mesh.noeud', objet: parc.machine(id).host, ip: ctx.ip });
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'admin' });

  // ───────── épinglage TLS (confiance au premier usage, confirmée par l'admin) ─────────
  // GET montre l'empreinte et le sujet ; POST la confirme et l'épingle. Les deux
  // passent par la sonde observer() de tls.js, sans vérification d'autorité, et
  // donc sous ses trois garanties : (1) atteinte seulement ici, par un admin
  // sous renfort récent ; (2) aucune donnée applicative envoyée, socket fermée
  // dès la poignée finie ; (3) rien d'autre ne sort que l'empreinte et le sujet,
  // le certificat n'étant gardé qu'après confirmation de l'empreinte montrée.
  r.get('/api/machines/:ref/pin', async ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const m = parc.machine(machine(ctx.params.ref));
    const { host, port } = ciblePinTLS(m, ctx.url.searchParams);
    const vu = await observer(host, port).catch(e => { throw new ErreurHttp(502, `Carte injoignable : ${e.message}`); });
    return { fp: vu.fp, sujet: vu.sujet };
  }, { role: 'admin' });
  r.post('/api/machines/:ref/pin', async ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const id = machine(ctx.params.ref);
    const m = parc.machine(id);
    const b = await corps(ctx, S.pin);
    const { host, port, idx, redfish: rf } = ciblePinTLS(m, new URLSearchParams(b.redfish ? { redfish: '1' } : { idx: String(b.idx ?? 0) }));
    const vu = await observer(host, port).catch(e => { throw new ErreurHttp(502, `Carte injoignable : ${e.message}`); });
    if (empreinte(vu.fp) !== empreinte(String(b.fp))) throw new ErreurHttp(409, 'L\'empreinte a changé depuis l\'affichage : recommence.');
    if (rf) parc.poserPinRedfish(id, { fp: vu.fp, pem: vu.pem });
    else parc.poserPinConsole(id, idx, { fp: vu.fp, pem: vu.pem });
    journal.ecrire({ acteur: ctx.session.compte, action: 'console.epinglee', objet: m.host, ip: ctx.ip, details: { fp: vu.fp } });
    return { ok: true, fp: vu.fp };
  }, { role: 'admin' });

  // ───────── Redfish : alimentation ─────────
  r.put('/api/machines/:ref/redfish', async ctx => {
    session(ctx, { role: 'admin', renfort: true }); // identifiants d'appareil
    const id = machine(ctx.params.ref);
    const b = await corps(ctx, S.redfish);
    const url = (b.url || '').trim();
    if (url && !/^https?:\/\//i.test(url)) throw new ErreurHttp(422, 'URL Redfish invalide.');
    if (url && cibleInterdite(url)) throw new ErreurHttp(422, 'Adresse interdite (métadonnées, lien local ou plage réservée).');
    if ((b.user || b.password) && !b.password) throw new ErreurHttp(422, 'Mot de passe requis.');
    parc.poserRedfish(id, { url, user: b.user, password: b.password });
    journal.ecrire({ acteur: ctx.session.compte, action: 'redfish.identifiants', objet: parc.machine(id).host, ip: ctx.ip });
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'admin' });
  r.get('/api/machines/:ref/power', async ctx => {
    session(ctx, { role: 'membre' });
    const m = parc.machine(machine(ctx.params.ref));
    const conf = parc.redfishConf(m);
    if (!conf) throw new ErreurHttp(409, 'Contrôle d\'alimentation non configuré.');
    if (/^https/i.test(conf.base) && !conf.pin) throw new ErreurHttp(409, 'Certificat de la carte non épinglé : confirme son empreinte.');
    try { return await redfish.etat(conf.base, { user: conf.user, password: conf.password, pin: conf.pin }); }
    catch (e) { throw new ErreurHttp(502, `Carte injoignable : ${e.message}`); }
  }, { role: 'membre' });
  // Allumer reste à la portée d'un membre (comme le réveil par le réseau) :
  // rien ne s'interrompt. Couper, arrêter, redémarrer ou forcer un cycle
  // interrompt un système en marche : rôle admin et renfort récent.
  r.post('/api/machines/:ref/power', async ctx => {
    session(ctx, { role: 'membre' });
    const b = await corps(ctx, S.power);
    if (b.action !== 'on') portail.exiger(ctx, { role: 'admin', renfort: true });
    if (!debitPower.prendre(ctx.ip)) throw new ErreurHttp(429, 'Trop d\'actions, patiente un instant.');
    const m = parc.machine(machine(ctx.params.ref));
    const conf = parc.redfishConf(m);
    if (!conf) throw new ErreurHttp(409, 'Contrôle d\'alimentation non configuré.');
    if (/^https/i.test(conf.base) && !conf.pin) throw new ErreurHttp(409, 'Certificat de la carte non épinglé.');
    let used; try { used = await redfish.agir(conf.base, { user: conf.user, password: conf.password, pin: conf.pin }, b.action); }
    catch (e) { throw new ErreurHttp(502, `Action refusée : ${e.message}`); }
    synapse?.alimentation(m.host, b.action);
    journal.ecrire({ acteur: ctx.session.compte, action: 'alimentation', objet: m.host, ip: ctx.ip, details: { action: b.action } });
    return { ok: true, action: b.action, reset_type: used };
  }, { role: 'membre' });

  // ───────── hôtes sans agent (carte de gestion) ─────────
  r.post('/api/hosts', async ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const b = await corps(ctx, S.hote);
    let items; try { items = normaliser([{ type: b.ctype, target: b.target, label: b.label, embed: b.embed }], nodeValide); } catch (e) { throw new ErreurHttp(422, e.message); }
    if (db.prepare('SELECT 1 FROM machines WHERE host = ?').get(b.host)) throw new ErreurHttp(409, 'Une machine porte déjà ce nom.');
    const ref = crypto.randomBytes(12).toString('base64url');
    db.prepare(`INSERT INTO machines(ref, host, ip, site, os, oskind, role, source, consoles, last_report, cree)
      VALUES(?,?,?,?,?,?,?,'kvm',?,?,?)`).run(ref, b.host, b.ip || '—', b.site || 'Matériel', 'Carte d\'administration', 'hw', 'matériel', JSON.stringify(items), Date.now() / 1000, Date.now() / 1000);
    journal.ecrire({ acteur: ctx.session.compte, action: 'machine.ajoutee', objet: b.host, ip: ctx.ip, details: { type: b.ctype } });
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'admin' });

  r.del('/api/machines/:ref', ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const id = machine(ctx.params.ref);
    const m = parc.machine(id);
    parc.supprimer(id);
    journal.ecrire({ acteur: ctx.session.compte, action: 'machine.supprimee', objet: m.host, ip: ctx.ip });
    return { ...parc.etat(), intervalle: cfg.intervalle, mesh_enabled: meshActif() };
  }, { role: 'admin' });

  // ───────── réveil réseau ─────────
  r.get('/api/relays', ctx => { session(ctx); return { coverage: couverture() }; }, { role: 'lecture' });
  r.post('/api/machines/:ref/wake', async ctx => {
    const hub = estHub(ctx);
    const s = hub ? null : session(ctx, { role: 'membre' });
    if (!debitReveil.prendre(ctx.ip)) throw new ErreurHttp(429, 'Trop de réveils, patiente un instant.');
    const m = parc.machine(machine(ctx.params.ref));
    const mac = m.mac;
    if (!mac) throw new ErreurHttp(409, 'Adresse MAC inconnue pour cette machine (aucun inventaire).');
    const cible = sousReseau(m.ip); const bcast = diffusionDirigee(m.ip);
    const payload = bcast ? `${mac}|${bcast}` : mac;
    const methodes = [];
    if (cfg.reseauHote) {
      try { await emettre(mac); if (bcast) await emettre(mac, { diffusion: bcast }); methodes.push('diffusion serveur'); } catch { /* le bridge Docker avale le paquet : les relais prennent le relais */ }
    }
    const now = Date.now() / 1000;
    const candidats = db.prepare("SELECT id, ip, host, role, last_report FROM machines WHERE source = 'agent' AND id <> ?").all(m.id)
      .filter(a => parc.enLigne(a.last_report) && sousReseau(a.ip) === cible)
      .sort((a, b) => (a.role !== 'relais') - (b.role !== 'relais'));
    for (const a of candidats.slice(0, 3)) {
      taches.creer(a.id, { kind: 'wol', payload, auteur: hub ? 'hub' : s.compteLigne.identifiant, auteurCompte: hub ? null : s.compte });
      methodes.push(`${a.role === 'relais' ? 'relais' : 'poste'} ${a.host}`);
    }
    if (!methodes.length) throw new ErreurHttp(409, 'Aucun relais en ligne sur ce segment. Ajoute un nœud relais (ex. Raspberry Pi) dans ce VLAN.');
    synapse?.reveil(m.host, methodes);
    return { ok: true, mac, methods: methodes };
  }, { hub: true, role: 'membre' });

  // ───────── automatisations ─────────
  r.get('/api/automations', ctx => { session(ctx); return { automations: parc.automatisations() }; }, { role: 'lecture' });
  // Une automatisation « commande libre » est une commande libre répétée : même
  // réglage (SENTINEL_ALLOW_EXEC), même rôle, même renfort, à chaque geste qui
  // la fait exister ou exécuter.
  const commandeLibre = (ctx, kind) => {
    if (kind !== 'cmd') return;
    if (!cfg.commandeLibre) throw new ErreurHttp(403, 'Commande libre désactivée (SENTINEL_ALLOW_EXEC=0).');
    portail.exiger(ctx, { role: 'admin', renfort: true });
  };
  r.post('/api/automations', async ctx => {
    session(ctx, { role: 'membre' });   // auth d'abord : anon → 401, lecture → 403
    const b = await corps(ctx, S.auto);
    commandeLibre(ctx, b.kind);
    const refus = chargeRefusee(b.kind, b.payload.trim());
    if (refus) throw new ErreurHttp(422, refus);
    if (b.cible !== 'tous' && !b.cible_val.trim()) throw new ErreurHttp(422, 'Précise la cible.');
    if (db.prepare('SELECT COUNT(*) n FROM automatisations').get().n >= MAX_AUTOMATISATIONS) throw new ErreurHttp(409, `${MAX_AUTOMATISATIONS} automatisations au plus : supprime celles qui ne servent plus.`);
    const ref = crypto.randomBytes(12).toString('base64url');
    db.prepare(`INSERT INTO automatisations(ref, nom, kind, payload, cible, cible_val, toutes_h, heure, actif) VALUES(?,?,?,?,?,?,?,?,1)`)
      .run(ref, b.nom, b.kind, b.payload.trim(), b.cible, b.cible_val.trim(), b.toutes_h, b.heure);
    journal.ecrire({ acteur: ctx.session.compte, action: 'automatisation.creee', objet: b.nom, ip: ctx.ip, details: { kind: b.kind } });
    return { automations: parc.automatisations() };
  }, { role: 'membre' });
  r.put('/api/automations/:ref', ctx => {
    session(ctx, { role: 'membre' });
    const a = db.prepare('SELECT id, nom, kind FROM automatisations WHERE ref = ?').get(ctx.params.ref);
    if (!a) throw new ErreurHttp(404, 'Automatisation introuvable.');
    const actif = ctx.url.searchParams.get('enabled') !== 'false';
    if (actif) commandeLibre(ctx, a.kind);
    else if (a.kind === 'cmd') portail.exiger(ctx, { role: 'admin', renfort: true });
    db.prepare('UPDATE automatisations SET actif = ? WHERE id = ?').run(actif ? 1 : 0, a.id);
    journal.ecrire({ acteur: ctx.session.compte, action: actif ? 'automatisation.activee' : 'automatisation.suspendue', objet: a.nom, ip: ctx.ip, details: { kind: a.kind } });
    return { automations: parc.automatisations() };
  }, { role: 'membre' });
  r.del('/api/automations/:ref', ctx => {
    session(ctx, { role: 'admin', renfort: true });
    const a = db.prepare('SELECT id, nom, kind FROM automatisations WHERE ref = ?').get(ctx.params.ref);
    if (a) {
      db.prepare('DELETE FROM automatisations WHERE id = ?').run(a.id);
      journal.ecrire({ acteur: ctx.session.compte, action: 'automatisation.supprimee', objet: a.nom, ip: ctx.ip, details: { kind: a.kind } });
    }
    return { automations: parc.automatisations() };
  }, { role: 'admin' });
  r.post('/api/automations/:ref/run', ctx => {
    session(ctx, { role: 'membre' });
    const a = db.prepare('SELECT * FROM automatisations WHERE ref = ?').get(ctx.params.ref);
    if (!a) throw new ErreurHttp(404, 'Automatisation introuvable.');
    commandeLibre(ctx, a.kind);
    const n = taches.lancer(a, { acteur: ctx.session.compte });
    return { ok: true, queued: n };
  }, { role: 'membre' });

  // ───────── réglages (lecture) ─────────
  r.get('/api/settings', ctx => {
    session(ctx);
    const n = db.prepare("SELECT COUNT(*) n FROM machines WHERE source = 'agent'").get().n;
    return {
      collect_interval: cfg.intervalle, offline_after: cfg.horsLigneApres, real_agents: n, exec: cfg.commandeLibre,
      mesh: { enabled: meshActif(), url: cfg.meshUrl || '', embed: cfg.meshEmbed, autologin: !!(cfg.meshCle && cfg.meshUser) },
      alertes: { hors_ligne_min: cfg.alerteHorsLigneMin, correctifs_jours: cfg.alerteCorrectifsJours, disque_pct: cfg.alerteDisquePct, risque: cfg.alerteRisque },
    };
  }, { role: 'lecture' });

  // ───────── enrôlement ─────────
  // Tirer un code, l'échanger, relever ses tâches : chacun change l'état, donc
  // un POST, jamais un GET qu'un lien ou un préchargement déclencherait.
  r.post('/api/enroll/info', async ctx => {
    session(ctx, { role: 'membre' });
    const b = await corps(ctx, S.inscription);
    const base = baseUrl(ctx);
    const site = b.site.trim() || 'Agents';
    const nom = b.name.trim();
    const relais = b.relay;
    // Contrôlé avant de créer le code : ces valeurs finiront dans un script root.
    const refus = enroll.controler(base, { site, nom });
    if (refus) throw new ErreurHttp(422, refus);
    const { code, expire_dans } = agents.nouveauCode({ site, nom, relais });
    const sites = db.prepare("SELECT DISTINCT site FROM machines WHERE site <> '' ORDER BY site").all().map(s => s.site);
    const commands = {}, downloads = {};
    for (const os of ['windows', 'macos', 'linux']) {
      commands[os] = enroll.uneLigne(os, base, code, { site, nom, relais });
      downloads[os] = `${base}/api/enroll/script?os=${os}&code=${code}&site=${encodeURIComponent(site)}&name=${encodeURIComponent(nom)}${relais ? '&relais=1' : ''}`;
    }
    return { base_url: base, code, expire_dans, site, name: nom, sites, commands, downloads, agent_url: `${base}/api/enroll/agent.py?code=${code}` };
  }, { role: 'membre' });

  // Échange du code contre le jeton d'agent (par l'agent lui-même).
  r.post('/api/enroll/config', async ctx => {
    controlerEchecs(ctx);
    const { code } = await corps(ctx, S.echange);
    const r2 = agents.echanger(code);
    if (!r2) refuserPreuve(ctx, 'Code d\'inscription invalide, expiré ou déjà utilisé.');
    return { token: r2.jeton, site: r2.site, name: r2.nom, relay: r2.relais, url: baseUrl(ctx) };
  }, { public: true });

  r.get('/api/enroll/agent.py', ctx => {
    // Une session d'opérateur, ou un code d'inscription encore valide.
    codeOuSession(ctx);
    const src = fs.readFileSync(path.join(racine, 'agent', 'sentinel-agent.py'), 'utf8');
    ctx.res.writeHead(200, { 'Content-Type': 'text/x-python; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Disposition': 'attachment; filename="sentinel-agent.py"' });
    ctx.res.end(src);
    return undefined;
  }, { public: true });

  r.get('/api/enroll/script', ctx => {
    const code = codeOuSession(ctx);
    const os = ctx.url.searchParams.get('os') || 'linux';
    if (!Object.hasOwn(enroll.BUILDERS, os)) throw new ErreurHttp(404, 'Système non supporté.');
    const [builder, fichier, media] = enroll.BUILDERS[os];
    const site = (ctx.url.searchParams.get('site') || 'Agents').trim() || 'Agents';
    const nom = (ctx.url.searchParams.get('name') || '').trim();
    const relais = ctx.url.searchParams.get('relais') === '1';
    // Une session d'opérateur ouvre cette route sans code valide : le code, le
    // site et le nom sont donc contrôlés ici, avant d'entrer dans le script.
    const refus = enroll.controler(baseUrl(ctx), { code, site, nom });
    if (refus) throw new ErreurHttp(422, refus);
    const body = builder(baseUrl(ctx), code, { site, nom, relais });
    ctx.res.writeHead(200, { 'Content-Type': media, 'Cache-Control': 'no-store', 'Content-Disposition': `attachment; filename="${fichier}"` });
    ctx.res.end(body);
    return undefined;
  }, { public: true });

  // ───────── agent : remontée, relève, résultat (jeton d'agent) ─────────
  r.post('/api/ingest', async ctx => {
    if (!debitIngest.prendre(ctx.ip)) throw new ErreurHttp(429, 'Trop de remontées.');
    controlerEchecs(ctx);
    const jeton = String(ctx.req.headers['x-agent-token'] || '');
    // Le jeton d'abord : un inconnu ne fait lire ni valider 512 Kio.
    if (!agents.jetonConnu(jeton)) refuserPreuve(ctx, 'Jeton d\'agent invalide.');
    const b = await corps(ctx, S.ingest, true);
    const res = agents.ingest(jeton, b);
    if (res.erreur === 401) refuserPreuve(ctx, 'Jeton d\'agent invalide.');
    if (res.erreur === 429) throw new ErreurHttp(429, 'Limite de machines atteinte.');
    return { ok: true };
  }, { public: true });

  r.post('/api/agent/jobs', ctx => {
    const m = agentDe(ctx);
    return taches.relever(m.id, cfg.delaiTache);
  }, { public: true });

  r.post('/api/agent/jobs/:ref/result', async ctx => {
    const m = agentDe(ctx);
    const b = await corps(ctx, S.resultat, true);
    if (!taches.resultat(ctx.params.ref, m.id, b.output, b.rc)) throw new ErreurHttp(404, 'Tâche introuvable.');
    return { ok: true };
  }, { public: true });

  // ───────── helpers ─────────
  function agentDe(ctx) {
    controlerEchecs(ctx);
    const res = agents.resoudre(String(ctx.req.headers['x-agent-token'] || ''));
    return res?.id ? res : refuserPreuve(ctx, 'Jeton d\'agent invalide.');
  }
  // Les fichiers d'inscription s'ouvrent à un opérateur (session membre) ou à
  // qui tient un code encore valide ; rend le code demandé.
  function codeOuSession(ctx) {
    const code = ctx.url.searchParams.get('code') || '';
    if (sessionSilencieuse(ctx)) return code;
    controlerEchecs(ctx);
    return agents.codeValide(code) ? code : refuserPreuve(ctx, 'Code d\'inscription invalide ou expiré.');
  }
  function sessionSilencieuse(ctx) { try { portail.exiger(ctx, { role: 'membre' }); return true; } catch { return false; } }
  function consolesEffectives(m) { try { return m.consoles ? JSON.parse(m.consoles) : []; } catch { return []; } }
  function baseUrl(ctx) {
    if (cfg.urlEnrolement) return cfg.urlEnrolement.replace(/\/+$/, '');
    return ctx.origine || `http://localhost:${cfg.port}`;
  }
  function ciblePinTLS(m, params) {
    if (params.get('redfish') === '1') {
      const conf = m.rf_url || (consolesEffectives(m).find(c => ['idrac', 'ilo', 'ipmi'].includes(c.type))?.target);
      if (!conf) throw new ErreurHttp(409, 'Aucune carte Redfish configurée.');
      const u = new URL(conf); return { host: u.hostname, port: Number(u.port) || 443, redfish: true };
    }
    const idx = Math.max(0, Math.min(7, Number(params.get('idx')) || 0));
    const item = consolesEffectives(m)[idx];
    if (!item) throw new ErreurHttp(404, 'Console introuvable.');
    if (item.type === 'vnc') { const h = item.target.slice(0, item.target.lastIndexOf(':')); throw new ErreurHttp(422, `La console VNC ${h} n'utilise pas TLS : rien à épingler.`); }
    if (!/^https/i.test(item.target)) throw new ErreurHttp(422, 'Console non-TLS : rien à épingler.');
    const u = new URL(item.target); return { host: u.hostname, port: Number(u.port) || 443, idx };
  }
  function couverture() {
    const rows = db.prepare("SELECT host, ip, role, last_report, site FROM machines WHERE source = 'agent'").all();
    const cover = new Map();
    for (const a of rows) {
      const sub = sousReseau(a.ip);
      if (!sub) continue;
      const e = cover.get(sub) || { subnet: sub, relays: [], agents: [], online_emitters: 0, site: a.site };
      const online = parc.enLigne(a.last_report);
      const qui = { host: a.host, online, relay: a.role === 'relais' };
      (qui.relay ? e.relays : e.agents).push(qui);
      if (online) e.online_emitters++;
      cover.set(sub, e);
    }
    return [...cover.values()].map(e => ({ ...e, covered: e.relays.some(r2 => r2.online) || e.online_emitters >= 2 })).sort((a, b) => a.subnet.localeCompare(b.subnet));
  }

  // Aiguillage : renvoie vrai si la requête était pour l'API. Journalise les
  // refus d'accès (403) qui ne viennent pas déjà du socle.
  return {
    async traiter(ctx) {
      const p = ctx.url.pathname;
      if (!p.startsWith('/api/')) return false;
      const t = r.trouver(ctx.req.method, p);
      if (!t) throw new ErreurHttp(404, 'Route inconnue.');
      if (t.methodes) { ctx.res.setHeader('Allow', t.methodes.join(', ')); throw new ErreurHttp(405, 'Méthode non admise.'); }
      ctx.params = t.params;
      const reponse = await t.route.gestionnaire(ctx);
      if (reponse !== undefined) repondreJson(ctx.res, 200, reponse);
      return true;
    },
    routeur: r,
  };
}
