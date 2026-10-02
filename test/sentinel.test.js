import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { demarrer } from '../src/main.js';
import { Client } from '../socle/essai/client.js';
import { adminComplet, membreInvite, MDP_ESSAI } from '../socle/essai/inscription.js';
import { execFileSync, spawnSync } from 'node:child_process';
import { fauxSynapse, fauxRfb, fauxCarte, fauxWs, captureUdp, fauxRedfish, fauxTlsCompteur, certificatsChaines } from './faux.js';
import { Coffre } from '../socle/src/chiffre.js';
import { lookupGarde, hoteInterdit } from '../src/reseau.js';
import { pont } from '../src/vncbridge.js';
import { observer, agentEpingle, empreinte } from '../src/tls.js';
import { connecter, Connexion } from '../src/websocket.js';
import { emettre, diffusionDirigee, sousReseau } from '../src/wol.js';
import { urlBureau, nodeValide } from '../src/mesh.js';
import https from 'node:https';

const JETON_HUB = 'jeton-du-hub-pour-les-essais-0123456789';
const INSTALL = 'jeton-installation-sentinel-essai';
const JETON_SYNAPSE = 'cer_sentinel_jeton-de-cerveau-des-essais';
const SILENCE = { info() {}, warn() {}, error() {} };
let s, syn, admin, membre, autre, lecteur, base, env;

// L'adresse de l'origine des consoles est connue avant le démarrage : son port
// est réservé ici, puis rendu pour qu'elle l'occupe.
async function portLibre() {
  const srv = net.createServer();
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  await new Promise(r => srv.close(r));
  return port;
}

async function lancer(dossier, extra = {}) {
  const consoles = await portLibre();
  env = {
    PORT: '0', HOTE: '127.0.0.1', DATA_DIR: dossier, SENTINEL_HUB_TOKEN: JETON_HUB, SENTINEL_ALLOW_EXEC: '1',
    SOCLE_CLE: crypto.randomBytes(32).toString('base64'), SOCLE_JETON_INSTALLATION: INSTALL,
    SYNAPSE_URL: syn.url, SYNAPSE_JETON: JETON_SYNAPSE,
    SENTINEL_CONSOLE_PORT: String(consoles), SENTINEL_CONSOLE_URL: `http://localhost:${consoles}`, ...extra,
  };
  const x = await demarrer(env, { log: SILENCE });
  return { ...x, port: x.serveur.address().port, client: () => new Client(x.serveur.address().port) };
}

// Enrôle un agent : code (membre) → jeton → première remontée.
async function enroler(cli, { site = 'Agents', nom = '', relais = false, hostname = 'poste-x' } = {}) {
  const info = (await cli.post('/api/enroll/info', { site, name: nom, relay: relais })).json;
  const conf = (await cli.post('/api/enroll/config', { code: info.code }, { origine: null })).json;
  const jeton = conf.token;
  const corps = { hostname, ip: '198.51.100.10', os: 'Ubuntu 24.04', oskind: 'lin', cpu: 12, ram: 40, disk: 55, av: 'à jour', fw: 'actif', enc: 'LUKS actif', patch: 0 };
  const r = await cli.req('POST', '/api/ingest', corps, { entetes: { 'x-agent-token': jeton }, origine: null });
  return { jeton, ingest: r, code: info.code };
}
function refMachineParHote(host) { return s.parc.db.prepare('SELECT ref FROM machines WHERE host = ?').get(host)?.ref; }

// Le renfort de l'administrateur retiré le temps d'un essai, puis rendu.
async function sansRenfort(fn) {
  const sessions = s.parc.db.prepare("SELECT id, renfort FROM socle_sessions WHERE compte = (SELECT id FROM socle_comptes WHERE identifiant = 'ana')").all();
  s.parc.db.prepare("UPDATE socle_sessions SET renfort = 0 WHERE compte = (SELECT id FROM socle_comptes WHERE identifiant = 'ana')").run();
  try { return await fn(); } finally { for (const x of sessions) s.parc.db.prepare('UPDATE socle_sessions SET renfort = ? WHERE id = ?').run(x.renfort, x.id); }
}

// Flux SSE d'un client connecté : renvoie les événements reçus au fil de l'eau.
async function ecouter(client) {
  const evenements = [];
  let pret;
  const ouvert = new Promise(r => { pret = r; });
  const req = http.request({ host: '127.0.0.1', port: s.port, path: '/api/activite', headers: {
    host: `localhost:${s.port}`, 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0',
    cookie: [...client.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
  } }, res => {
    let tampon = '';
    res.on('data', d => {
      tampon += d; pret();
      let i;
      while ((i = tampon.indexOf('\n\n')) >= 0) {
        const ligne = tampon.slice(0, i).split('\n').find(l => l.startsWith('data: '));
        tampon = tampon.slice(i + 2);
        if (ligne) evenements.push(JSON.parse(ligne.slice(6)));
      }
    });
  });
  req.on('error', () => { /* coupé à la fin de l'essai */ });
  req.end();
  await ouvert;
  return { evenements, fermer: () => req.destroy() };
}

before(async () => {
  syn = await fauxSynapse(JETON_SYNAPSE);
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-'));
  s = await lancer(base);
  admin = s.client();
  await adminComplet(admin, { jeton: INSTALL });
  ({ client: membre } = await membreInvite(admin, () => s.client(), { identifiant: 'bruno' }));
  ({ client: autre } = await membreInvite(admin, () => s.client(), { identifiant: 'chloe' }));
  ({ client: lecteur } = await membreInvite(admin, () => s.client(), { identifiant: 'lea', role: 'lecture' }));
});
after(async () => { await s?.arreter(); await syn?.fermer(); });

test('en-têtes de sécurité, nonce, health anonyme minimal, pas de page de doc', async () => {
  const c = s.client();
  const r = await new Promise(recu => http.get({ host: '127.0.0.1', port: s.port, path: '/', headers: { host: `localhost:${s.port}` } }, recu));
  let html = ''; for await (const m of r) html += m;
  const csp = r.headers['content-security-policy'];
  const nonce = /'nonce-([^']+)'/.exec(csp)[1];
  assert.ok(html.includes(`nonce="${nonce}"`), 'nonce de la page = nonce de l\'en-tête');
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.equal(r.headers['x-powered-by'], undefined);
  assert.deepEqual((await c.get('/api/health')).json, { ok: true }, 'health anonyme = {ok:true}');
  for (const p of ['/docs', '/openapi.json', '/api/state']) {
    const x = await c.get(p);
    assert.notEqual(x.status, 200, p);
  }
});

test('derrière un relais HTTPS déclaré : HSTS, cookie __Host- sécurisé, et la même session ouvre les WebSockets', async () => {
  const relaye = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-r-')), { SOCLE_PROXYS: '127.0.0.1/32' });
  try {
    // Un vrai nom public derrière le relais, comme en production (pas localhost,
    // que le navigateur et le socle traitent à part).
    const h = { host: 'sentinel.exemple.org', 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.7' };
    const origine = 'https://sentinel.exemple.org';
    // Chaque requête de ce client passe « par le relais ».
    class ClientRelaye extends Client {
      constructor(port) { super(port); this.origine = origine; }
      req(m, c, b, o = {}) { return super.req(m, c, b, { ...o, entetes: { ...h, ...(o.entetes || {}) } }); }
    }
    const c = new ClientRelaye(relaye.port);
    const r = await c.req('POST', '/api/compte/installation', { jeton: INSTALL, identifiant: 'ana', motDePasse: MDP_ESSAI });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.match(r.entetes['strict-transport-security'], /max-age=\d{8,}; includeSubDomains/);
    const cookie = r.setCookie.find(x => x.startsWith('__Host-sentinel-sid='));
    assert.ok(cookie, r.setCookie.join(' | '));
    for (const attr of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(cookie.includes(attr), attr);
    const auth = new (await import('../socle/essai/authentificateur.js')).Authentificateur();
    const o = await c.post('/api/compte/cles/options');
    assert.equal((await c.post('/api/compte/cles', { reponse: auth.creer(o.json, origine), nom: 'Essai' })).status, 200);
    const t = await c.post('/api/compte/totp');
    const { codeTotp } = await import('../socle/essai/inscription.js');
    assert.equal((await c.post('/api/compte/totp/confirmer', { code: codeTotp(t.json.secret) })).json?.niveau, 'complet');
    // La mise à niveau WebSocket reconnaît le cookie __Host- : autorisée, puis
    // 404 (aucune machine). Sans cookie : 401.
    const ws = { Host: h.host, 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': h['x-forwarded-for'], Origin: origine };
    const jeton = c.cookies.get('__Host-sentinel-sid');
    assert.match(await brancherWs(relaye.port, '/vnc/AAAAAAAAAAAAAAAA/0', { ...ws, Cookie: `__Host-sentinel-sid=${jeton}` }), / 404 /);
    assert.match(await brancherWs(relaye.port, '/vnc/AAAAAAAAAAAAAAAA/0', ws), / 401 /);
  } finally { await relaye.arreter(); }
});

test('autorisation : chaque route balayée sans session, en lecture seule et en membre', async () => {
  const cheminDe = r => r.re.source.replace(/^\^|\$$/g, '').replace(/\\([/.])/g, '$1').replace(/\(\[\^\/\]\+\)/g, 'AAAAAAAAAAAAAAAA');
  const anonyme = s.client(), ecarts = [], sansRole = [];
  let balayees = 0;
  for (const r of s.api.routeur.routes) {
    const o = r.options || {};
    if (o.public) continue;
    if (!['lecture', 'membre', 'admin'].includes(o.role)) { sansRole.push(`${r.methode} ${cheminDe(r)}`); continue; }
    balayees++;
    const chemin = cheminDe(r), lecture = r.methode === 'GET';
    const attendus = [['anonyme', anonyme, 401], ['lecture', lecteur, lecture && o.role === 'lecture' ? null : 403], ['membre', membre, o.role === 'admin' ? 403 : null]];
    for (const [nom, c, attendu] of attendus) {
      if (attendu === null) continue;
      const st = (await c.req(r.methode, chemin, lecture || r.methode === 'DELETE' ? undefined : {})).status;
      if (st !== attendu) ecarts.push(`${nom} ${r.methode} ${chemin} → ${st} (attendu ${attendu})`);
    }
  }
  assert.deepEqual(sansRole, [], 'chaque route non publique déclare son rôle');
  assert.deepEqual(ecarts, []);
  assert.equal(balayees, 28, 'routes non publiques balayées');
  // Les seules routes sans session : la sonde de santé, et ce qu'un agent
  // appelle avec son code d'inscription ou son jeton (vérifiés dans la route).
  const publiques = s.api.routeur.routes.filter(r => r.options?.public).map(r => `${r.methode} ${cheminDe(r)}`).sort();
  assert.deepEqual(publiques, ['GET /api/enroll/agent.py', 'GET /api/enroll/requirements.txt', 'GET /api/enroll/script', 'GET /api/health',
    'POST /api/agent/jobs', 'POST /api/agent/jobs/AAAAAAAAAAAAAAAA/result', 'POST /api/enroll/config', 'POST /api/ingest']);
  // Aucun GET ne change l'état : tirer un code, l'échanger et relever ses tâches sont des POST.
  for (const chemin of ['/api/enroll/info', '/api/enroll/config', '/api/agent/jobs']) assert.equal((await membre.get(chemin)).status, 405, `GET ${chemin}`);
  // La politique écrite ici plutôt que relue dans le routeur : une route
  // d'administration relâchée par erreur fait échouer cet essai.
  const admin = s.api.routeur.routes.filter(r => r.options?.role === 'admin').map(r => `${r.methode} ${cheminDe(r)}`).sort();
  assert.deepEqual(admin, ['DELETE /api/automations/AAAAAAAAAAAAAAAA', 'DELETE /api/machines/AAAAAAAAAAAAAAAA', 'GET /api/machines/AAAAAAAAAAAAAAAA/pin', 'POST /api/hosts', 'POST /api/machines/AAAAAAAAAAAAAAAA/pin',
    'PUT /api/machines/AAAAAAAAAAAAAAAA/consoles', 'PUT /api/machines/AAAAAAAAAAAAAAAA/mesh-node', 'PUT /api/machines/AAAAAAAAAAAAAAAA/redfish']);
  // Aucune console n'est plus servie sous l'origine de Sentinel.
  assert.equal((await membre.get('/console/AAAAAAAAAAAAAAAA/0/')).status, 404);
  // Paramètres : une référence mal formée ne désigne rien ; un paramètre de
  // requête non déclaré, ou hors de ses valeurs, est refusé.
  assert.equal((await membre.get('/api/machines/2/jobs')).status, 404);
  assert.equal((await membre.post('/api/alerts/..%2F..%2Fetc/ack')).status, 404);
  assert.equal((await membre.get('/api/state?limit=100000')).status, 400);
  assert.equal((await anonyme.get('/api/state?limit=100000')).status, 400);
  const auto = (await membre.post('/api/automations', { nom: 'Paramètres', kind: 'inventory' })).json.automations.find(a => a.nom === 'Paramètres').id;
  assert.equal((await membre.put(`/api/automations/${auto}?enabled=peut-etre`)).status, 400);
  assert.equal((await membre.put(`/api/automations/${auto}`)).status, 400, 'l\'état voulu est dit, jamais supposé');
  assert.equal((await anonyme.put(`/api/automations/${auto}?enabled=peut-etre`)).status, 401, 'l\'authentification passe avant le détail des paramètres');
  s.parc.db.prepare('DELETE FROM automatisations WHERE ref = ?').run(auto);
});

test('agent : code d\'inscription à usage unique, remontée, relève et résultat de SES tâches seulement', async () => {
  const info = (await membre.post('/api/enroll/info', { site: 'Prod' })).json;
  assert.match(info.code, /^[A-Za-z0-9_-]{22}$/, 'code de 128 bits');
  const empreinte = crypto.createHash('sha256').update('inscription:' + info.code).digest('hex');
  assert.deepEqual(s.parc.db.prepare('SELECT empreinte FROM enrolements').all().map(r => r.empreinte).filter(e => e === empreinte), [empreinte], 'gardé par son empreinte');
  assert.equal(s.parc.db.prepare('SELECT COUNT(*) n FROM enrolements WHERE empreinte = ?').get(info.code).n, 0, 'jamais en clair');
  const conf = (await membre.post('/api/enroll/config', { code: info.code })).json;
  assert.match(conf.token, /^sag_/);
  assert.equal((await membre.post('/api/enroll/config', { code: info.code })).status, 401, 'code consommé : usage unique');
  const jeton = conf.token;
  const remonter = h => membre.req('POST', '/api/ingest', { hostname: h, ip: '198.51.100.20', oskind: 'lin', cpu: 5, ram: 10, disk: 20, av: 'à jour', fw: 'actif', enc: 'LUKS actif', patch: 0 }, { entetes: { 'x-agent-token': jeton }, origine: null });
  assert.equal((await remonter('poste-un')).status, 200);
  const mref = refMachineParHote('poste-un');
  // une tâche pour cet agent
  const t = await membre.post(`/api/machines/${mref}/jobs`, { kind: 'inventory' });
  assert.equal(t.status, 200);
  // l'agent relève SES tâches (identifié par son jeton, pas par un nom)
  const releve = await membre.req('POST', '/api/agent/jobs', {}, { entetes: { 'x-agent-token': jeton }, origine: null });
  assert.equal(releve.status, 200);
  assert.equal(releve.json.jobs.length, 1);
  assert.equal(releve.json.jobs[0].id, t.json.id);
  // un autre agent ne voit pas cette tâche
  const en2 = await enroler(autre, { hostname: 'poste-deux' });
  const releve2 = await membre.req('POST', '/api/agent/jobs', {}, { entetes: { 'x-agent-token': en2.jeton }, origine: null });
  assert.equal(releve2.json.jobs.length, 0, 'aucun accès croisé aux tâches');
  // il ne peut pas rendre le résultat d'une tâche d'un autre
  assert.equal((await membre.req('POST', `/api/agent/jobs/${t.json.id}/result`, { output: 'volé', rc: 0 }, { entetes: { 'x-agent-token': en2.jeton } })).status, 404);
  // le bon agent rend son résultat
  assert.equal((await membre.req('POST', `/api/agent/jobs/${t.json.id}/result`, { output: 'ok', rc: 0 }, { entetes: { 'x-agent-token': jeton } })).status, 200);
  // jeton d'agent invalide refusé
  assert.equal((await membre.req('POST', '/api/ingest', { hostname: 'x', oskind: 'lin', cpu: 0, ram: 0, disk: 0 }, { entetes: { 'x-agent-token': 'sag_faux' }, origine: null })).status, 401);
  // un agent ne se déclare pas relais : le rôle vient du code d'inscription
  const role = () => s.parc.db.prepare("SELECT role FROM machines WHERE host = 'poste-un'").get().role;
  assert.equal((await membre.req('POST', '/api/ingest', { hostname: 'poste-un', oskind: 'lin', role: 'relais', cpu: 1, ram: 1, disk: 1 }, { entetes: { 'x-agent-token': jeton }, origine: null })).status, 200);
  assert.equal(role(), 'poste');
});

// La ligne de commande d'administration, lancée comme dans le conteneur, sur
// la base de l'instance qui tourne.
const CLI = path.join(import.meta.dirname, '..', 'src', 'cli.js');
const cli = (args, { dossier = s.cfg.donnees, entree } = {}) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, ...args],
  { env: { PATH: process.env.PATH, DATA_DIR: dossier }, input: entree, ...(entree === undefined ? { encoding: 'utf8' } : {}) });

test('révocation d\'un jeton d\'agent : aussitôt refusé, tâches dues abandonnées, la machine retrouvée à la réinscription', async () => {
  const { jeton } = await enroler(membre, { hostname: 'poste-revoque' });
  const mref = refMachineParHote('poste-revoque');
  const t = await membre.post(`/api/machines/${mref}/jobs`, { kind: 'install', payload: 'htop' });
  assert.equal(t.status, 200);
  const r = cli(['agents', 'revoquer', 'poste-revoque']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /poste-revoque : jeton révoqué, 1 tâche\(s\) abandonnée\(s\)/);
  const remonter = j => membre.req('POST', '/api/ingest', { hostname: 'poste-revoque', oskind: 'lin', cpu: 1, ram: 1, disk: 1 }, { entetes: { 'x-agent-token': j }, origine: null });
  assert.equal((await remonter(jeton)).status, 401, 'le jeton révoqué ne vaut plus rien');
  assert.equal(s.parc.db.prepare('SELECT status FROM taches WHERE ref = ?').get(t.json.id).status, 'echec', 'la tâche due ne partira pas');
  assert.equal(s.parc.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'agent.jeton_revoque' AND objet = 'poste-revoque'").get().n, 1);
  assert.equal(cli(['agents', 'revoquer', 'poste-revoque']).status, 1, 'plus rien à révoquer');
  const { ingest } = await enroler(membre, { hostname: 'poste-revoque' });
  assert.equal(ingest.status, 200);
  assert.equal(refMachineParHote('poste-revoque'), mref, 'réinscrit, l\'agent retrouve sa machine');
});

test('sauvegarde chiffrée pour une clé publique, restaurée ailleurs avec la clé privée seule', () => {
  const paire = () => crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  const { publicKey, privateKey } = paire();
  assert.notEqual(cli(['sauvegarde'], { entree: crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey }).status, 0, 'clé trop courte refusée');
  const sauv = cli(['sauvegarde'], { entree: publicKey });
  assert.equal(sauv.status, 0, String(sauv.stderr));
  assert.ok(!sauv.stdout.includes(Buffer.from('poste-revoque')) && !sauv.stdout.includes(Buffer.from('SQLite format')), 'rien en clair');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-restauration-'));
  const prive = path.join(d, 'prive.pem'), autre = path.join(d, 'autre.pem'), cible = path.join(d, 'restauree.db');
  fs.writeFileSync(prive, privateKey);
  fs.writeFileSync(autre, paire().privateKey);
  assert.notEqual(cli(['restaurer', autre, cible], { entree: sauv.stdout }).status, 0, 'une autre clé privée ne relit rien');
  assert.equal(cli(['restaurer', prive, cible], { entree: sauv.stdout }).status, 0);
  assert.notEqual(cli(['restaurer', prive, cible], { entree: sauv.stdout }).status, 0, 'jamais par-dessus un fichier');
  assert.equal(fs.statSync(cible).mode & 0o777, 0o600);
  const db = new DatabaseSync(cible, { readOnly: true });
  try {
    assert.equal(db.prepare('SELECT COUNT(*) n FROM machines').get().n, s.parc.db.prepare('SELECT COUNT(*) n FROM machines').get().n, 'le parc entier');
  } finally { db.close(); }
  assert.equal(s.parc.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'sauvegarde.faite'").get().n, 1, 'sauvegarde journalisée');
});

test('codes et jetons de machine : chaque échec compte pour l\'adresse, bloquée après dix, à part des connexions humaines', async () => {
  const x = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-echecs-')));
  try {
    const c = x.client();
    const machine = { origine: null };
    const statuts = [
      (await c.req('GET', '/api/summary', undefined, { ...machine, entetes: { authorization: 'Bearer jeton-du-hub-invente-pour-l-essai' } })).status,
      (await c.post('/api/enroll/config', { code: 'A'.repeat(22) }, machine)).status,
      (await c.get(`/api/enroll/agent.py?code=${'A'.repeat(22)}`)).status,
      (await c.req('POST', '/api/agent/jobs', {}, { ...machine, entetes: { 'x-agent-token': 'sag_jeton_invente' } })).status,
    ];
    for (let i = 0; i < 8; i++) statuts.push((await c.req('POST', '/api/ingest', { hostname: 'poste-x' }, { ...machine, entetes: { 'x-agent-token': 'sag_jeton_invente' } })).status);
    assert.deepEqual(statuts, [...Array(10).fill(401), 429, 429]);
    assert.equal((await c.req('GET', '/api/summary', undefined, { ...machine, entetes: { authorization: `Bearer ${JETON_HUB}` } })).status, 429, 'adresse bloquée : le bon jeton attend aussi');
    assert.equal(x.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'limite.verrou' AND objet = 'ip:machine:127.0.0.1'").get().n, 1, 'verrou journalisé');
    assert.ok(x.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'connexion.jeton'").get().n >= 1, 'échecs journalisés pour la vigie');
    assert.equal((await c.post('/api/compte/connexion', { identifiant: 'personne', motDePasse: 'mauvaise phrase de passe' })).status, 401, 'les connexions humaines gardent leur propre compteur');
  } finally { await x.arreter(); }
});

test('volumes : flux d\'activité, automatisations et mises à niveau WebSocket bornés ; jeton d\'agent inconnu refusé avant le corps', async () => {
  const x = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-volumes-')));
  const ouverts = [];
  try {
    const a = x.client();
    await adminComplet(a, { jeton: INSTALL });
    const cookie = [...a.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const ouvrirFlux = () => new Promise(resolve => {
      const req = http.request({ host: '127.0.0.1', port: x.port, path: '/api/activite', headers: { host: `localhost:${x.port}`, 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0', cookie } }, res => { resolve(res.statusCode); if (res.statusCode !== 200) res.resume(); });
      req.on('error', () => resolve('erreur'));
      ouverts.push(req);
      req.end();
    });
    const flux = [];
    for (let i = 0; i < 5; i++) flux.push(await ouvrirFlux());
    assert.deepEqual(flux, [200, 200, 200, 200, 429], 'quatre flux par session');

    const inserer = x.db.prepare("INSERT INTO automatisations(ref, nom, kind, cible) VALUES(?, ?, 'inventory', 'tous')");
    for (let i = 0; i < 199; i++) inserer.run(crypto.randomBytes(12).toString('base64url'), `Auto ${i}`);
    assert.equal((await a.post('/api/automations', { nom: 'La deux-centième', kind: 'inventory' })).status, 200);
    assert.equal((await a.post('/api/automations', { nom: 'Une de trop', kind: 'inventory' })).status, 409);
    assert.equal((await a.get('/api/automations')).json.automations.length, 200);

    // Le jeton d'abord : la réponse part sans attendre les 400 Kio annoncés.
    const statut = await new Promise(resolve => {
      const req = http.request({ host: '127.0.0.1', port: x.port, method: 'POST', path: '/api/ingest', headers: { 'content-type': 'application/json', 'content-length': 400000, 'x-agent-token': 'sag_jeton_invente' } }, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', () => resolve('erreur'));
      ouverts.push(req);
      req.flushHeaders();
    });
    assert.equal(statut, 401);

    const anonyme = x.client();
    while ((await anonyme.get('/api/health')).status === 200) { /* le débit de l'adresse s'épuise */ }
    assert.match(await brancherWs(x.port, '/vnc/AAAAAAAAAAAAAAAA/0', { Origin: anonyme.origine, Cookie: cookie }), / 429 /, 'une mise à niveau compte dans le débit');
  } finally { for (const r of ouverts) r.destroy(); await x.arreter(); }
});

test('tâches : charge validée selon le type, réveil réservé à sa route (opérateur, automatisation ou Hub)', async () => {
  await enroler(membre, { hostname: 'poste-charges' });
  const mref = refMachineParHote('poste-charges');
  const hub = { entetes: { authorization: `Bearer ${JETON_HUB}` }, origine: null };
  for (const [kind, payload, attendu] of [['install', 'paquet; rm -rf /', 422], ['install', '--config=/etc/shadow', 422], ['install', '', 422], ['uninstall', '$(id)', 422],
    ['update', 'a b', 422], ['inventory', 'quelque chose', 422], ['wol', '01:23:45:67:89:ab|203.0.113.9', 400], ['install', 'htop', 200], ['update', '', 200], ['inventory', '', 200]]) {
    assert.equal((await membre.post(`/api/machines/${mref}/jobs`, { kind, payload })).status, attendu, `${kind} « ${payload} »`);
  }
  assert.equal((await s.client().req('POST', `/api/machines/${mref}/jobs`, { kind: 'wol', payload: '01:23:45:67:89:ab|203.0.113.9' }, hub)).status, 400, 'le Hub non plus');
  assert.equal((await membre.post('/api/automations', { nom: 'Réveils', kind: 'wol', payload: '01:23:45:67:89:ab', cible: 'tous' })).status, 400);
  assert.equal((await membre.post('/api/automations', { nom: 'Paquet piégé', kind: 'install', payload: 'a;b', cible: 'tous' })).status, 422);
});

test('commande libre : rôle admin + renfort ; un membre ne peut pas', async () => {
  const en = await enroler(membre, { hostname: 'poste-cmd' });
  const mref = refMachineParHote('poste-cmd');
  assert.equal((await membre.post(`/api/machines/${mref}/jobs`, { kind: 'cmd', payload: 'id' })).status, 403, 'commande libre refusée au membre');
  const r = await admin.post(`/api/machines/${mref}/jobs`, { kind: 'cmd', payload: 'id' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  // la charge sensible n'est pas rendue en clair dans la liste
  const jobs = (await admin.get(`/api/machines/${mref}/jobs`)).json.jobs;
  assert.equal(jobs.find(j => j.id === r.json.id).payload, '', 'commande libre non rendue en clair');
  // ce qu'elle a affiché ne va qu'à un administrateur
  assert.equal((await membre.req('POST', '/api/agent/jobs', {}, { entetes: { 'x-agent-token': en.jeton }, origine: null })).status, 200);
  assert.equal((await membre.req('POST', `/api/agent/jobs/${r.json.id}/result`, { output: 'sortie sensible de la commande', rc: 0 }, { entetes: { 'x-agent-token': en.jeton }, origine: null })).status, 200);
  const sortie = async c => (await c.get(`/api/machines/${mref}/jobs`)).json.jobs.find(j => j.id === r.json.id).output;
  assert.equal(await sortie(admin), 'sortie sensible de la commande');
  assert.equal(await sortie(membre), '', 'un membre ne lit pas la sortie d\'une commande libre');
  assert.equal(await sortie(lecteur), '', 'la lecture seule non plus');
});

test('pont VNC : authentification DES côté serveur, puis poignée None au navigateur', async () => {
  const rfb = await fauxRfb({ motDePasse: 'secret-vnc' });
  try {
    const ws = fauxWs();
    const p = pont(ws, rfb.host, rfb.port, { motDePasse: 'secret-vnc' });
    // le pont envoie « RFB 003.008\n » au navigateur : on répond la version, le choix, etc.
    await attendre(() => ws.envoyes.some(b => b.toString('latin1').startsWith('RFB 003.008')));
    ws._pousser(Buffer.from('RFB 003.008\n'));            // version du navigateur
    await attendre(() => ws.envoyes.some(b => b.length === 2 && b[0] === 1 && b[1] === 1));
    ws._pousser(Buffer.from([1]));                         // choix None
    assert.equal(await rfb.authOk, true, 'authentification VNC réussie côté serveur');
    // après la poignée, les octets du serveur RFB arrivent au navigateur
    await attendre(() => ws.envoyes.some(b => b.toString('latin1').includes('APRES-AUTH')), 2000);
    ws.close(); await p.catch(() => { /* le pont s'arrête sur la fermeture : son issue n'est pas l'objet de l'essai */ });
  } finally { await rfb.fermer(); }
});

test('épinglage TLS : le certificat épinglé passe, une empreinte différente est refusée', async () => {
  const carte = await fauxCarte((req, res) => res.end('{"ok":true}'));
  const autreCarte = await fauxCarte((req, res) => res.end('{"ok":true}'));
  try {
    const vu = await observer(carte.host, carte.port);
    assert.match(vu.fp, /^sha256:[0-9a-f]{64}$/);
    // connexion épinglée sur la bonne carte : succès
    const agent = agentEpingle({ fp: vu.fp, pem: vu.pem });
    const ok = await new Promise((res, rej) => https.get({ host: carte.host, port: carte.port, path: '/', agent }, r => { r.resume(); res(r.statusCode); }).on('error', rej));
    assert.equal(ok, 200);
    // même empreinte épinglée, mais l'autre carte présente un autre certificat : refus
    await assert.rejects(new Promise((res, rej) => https.get({ host: autreCarte.host, port: autreCarte.port, path: '/', agent }, r => { r.resume(); res(r.statusCode); }).on('error', rej)), /épingl|certificat|self-signed|unable|verify/i);
  } finally { await carte.fermer(); await autreCarte.fermer(); }
});

test('épinglage TLS : un certificat signé par le certificat épinglé n\'est pas pour autant la carte épinglée', async () => {
  const { autorite, feuille } = certificatsChaines('carte-c');
  const s2 = https.createServer({ key: feuille.cle, cert: feuille.cert }, (req, res) => res.end('{"ok":true}'));
  await new Promise(r => s2.listen(0, '127.0.0.1', r));
  const joindre = agent => new Promise((res, rej) => https.get({ host: '127.0.0.1', port: s2.address().port, path: '/', agent }, r => { r.resume(); res(r.statusCode); }).on('error', rej));
  try {
    // La feuille est signée par le certificat épinglé, la chaîne se vérifie :
    // seule l'empreinte la distingue, et elle suffit à la refuser.
    const epinglee = empreinte(new crypto.X509Certificate(autorite.cert).fingerprint256);
    await assert.rejects(joindre(agentEpingle({ fp: epinglee, pem: autorite.cert })), /empreinte du certificat différente de celle épinglée/);
    await assert.rejects(connecter(`wss://127.0.0.1:${s2.address().port}/ws`, { pin: { fp: epinglee, pem: autorite.cert } }), /empreinte du certificat différente de celle épinglée/);
  } finally { await new Promise(f => { s2.close(f); s2.closeAllConnections(); }); }
});

test('Redfish : identifiants scellés jamais rendus ; alimentation refusée tant que le certificat n\'est pas épinglé', async () => {
  const en = await enroler(membre, { hostname: 'srv-redfish' });
  const mref = refMachineParHote('srv-redfish');
  const carte = await fauxCarte();
  try {
    const r = await admin.put(`/api/machines/${mref}/redfish`, { url: `https://127.0.0.1:${carte.port}`, user: 'root', password: 'motdepasse-carte' });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const m = r.json.machines.find(x => x.id === mref);
    assert.equal(m.redfish, true);
    assert.equal(m.rf_user, 'root');
    assert.ok(!JSON.stringify(m).includes('motdepasse-carte'), 'le mot de passe ne sort jamais');
    assert.ok(!s.parc.db.prepare('SELECT rf_secret FROM machines WHERE ref=?').get(mref).rf_secret.includes('motdepasse-carte'), 'scellé en base');
    // sans épinglage : l'alimentation est refusée (409), jamais rejectUnauthorized:false
    assert.equal((await membre.get(`/api/machines/${mref}/power`)).status, 409);
    // Basic sur HTTP : l'identifiant circulerait en clair, refusé à la pose.
    const clair = await admin.put(`/api/machines/${mref}/redfish`, { url: `http://127.0.0.1:${carte.port}`, user: 'root', password: 'motdepasse-carte' });
    assert.equal(clair.status, 422);
    assert.match(clair.json.error, /https/);
    // Une adresse en HTTP reprise d'une 1.x : jamais jointe.
    s.parc.db.prepare('UPDATE machines SET rf_url = ? WHERE ref = ?').run(`http://127.0.0.1:${carte.port}`, mref);
    const reprise = await membre.get(`/api/machines/${mref}/power`);
    assert.equal(reprise.status, 409);
    assert.match(reprise.json.error, /https/);
  } finally { await carte.fermer(); }
});

// Épingle le certificat de la carte Redfish d'une machine, comme l'administrateur.
async function epinglerRedfish(client, mref) {
  const vu = await client.get(`/api/machines/${mref}/pin?redfish=1`);
  assert.equal(vu.status, 200, JSON.stringify(vu.json));
  assert.equal((await client.post(`/api/machines/${mref}/pin`, { redfish: true, fp: vu.json.fp })).status, 200);
}

test('réveil réseau : paquet magique bien formé et capturé ; sans relais en ligne, 409', async () => {
  assert.equal(sousReseau('198.51.100.10'), '198.51.100');
  assert.equal(diffusionDirigee('198.51.100.10'), '198.51.100.255');
  const cap = await captureUdp();
  try {
    await emettre('01:23:45:67:89:ab', { diffusion: '127.0.0.1', ports: [cap.port] });
    await attendre(() => cap.paquets.length > 0, 2000);
    const pkt = cap.paquets[0];
    assert.equal(pkt.length, 102, '6 + 16×6');
    assert.ok(pkt.subarray(0, 6).equals(Buffer.alloc(6, 0xff)));
    assert.ok(pkt.subarray(6, 12).equals(Buffer.from('0123456789ab', 'hex')));
  } finally { await cap.fermer(); }
  // une machine sans MAC → 409 (aucun inventaire)
  const en = await enroler(membre, { hostname: 'poste-wol' });
  const mref = refMachineParHote('poste-wol');
  const r = await membre.post(`/api/machines/${mref}/wake`);
  assert.ok([409].includes(r.status), 'MAC inconnue → 409');
  // Avec l'adresse MAC relevée par l'inventaire, le relais du segment émet.
  const cible = await enroler(membre, { hostname: 'poste-a-reveiller' });
  assert.equal((await membre.req('POST', '/api/ingest', { hostname: 'poste-a-reveiller', ip: '198.51.100.10', oskind: 'lin', cpu: 1, ram: 1, disk: 1, inventory: { nics: [{ name: 'eth0', ip: '198.51.100.10', mac: '01-23-45-67-89-AB' }] } }, { entetes: { 'x-agent-token': cible.jeton }, origine: null })).status, 200);
  await enroler(membre, { hostname: 'relais-a', relais: true });
  const reveil = await membre.post(`/api/machines/${refMachineParHote('poste-a-reveiller')}/wake`);
  assert.equal(reveil.status, 200, JSON.stringify(reveil.json));
  assert.equal(reveil.json.methods[0], 'relais relais-a', 'le relais d\'abord');
  const idRelais = s.parc.idDe(refMachineParHote('relais-a'));
  assert.deepEqual({ ...s.parc.db.prepare("SELECT kind, payload FROM taches WHERE machine_id = ? AND kind = 'wol'").get(idRelais) }, { kind: 'wol', payload: '01:23:45:67:89:ab|198.51.100.255' });
  assert.equal(s.parc.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'reveil' AND objet = 'poste-a-reveiller'").get().n, 1, 'réveil journalisé');
});

test('consoles : mot de passe VNC scellé (admin+renfort), jamais rendu ; la cible du pont est côté serveur', async () => {
  const en = await enroler(membre, { hostname: 'poste-vnc' });
  const mref = refMachineParHote('poste-vnc');
  // un membre ne déclare aucun accès distant, avec ou sans mot de passe d'appareil
  assert.equal((await membre.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'vnc', target: '198.51.100.10:5900', label: 'KVM', vncpw: 'motdepasse-vnc' }] })).status, 403);
  assert.equal((await membre.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'url', target: 'http://198.51.100.10/', label: 'Web' }] })).status, 403, 'une adresse interne est choisie par un administrateur');
  assert.equal((await membre.put(`/api/machines/${mref}/mesh-node`, { mesh_node: 'node//abc' })).status, 403);
  await sansRenfort(async () => assert.equal((await admin.put(`/api/machines/${mref}/consoles`, { consoles: [] })).status, 403, 'renfort exigé'));
  // l'admin le peut ; le secret est scellé et ne ressort pas
  const r = await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'vnc', target: '198.51.100.10:5900', label: 'KVM', vncpw: 'motdepasse-vnc' }] });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const m = r.json.machines.find(x => x.id === mref);
  assert.equal(m.consoles[0].a_mdp, true);
  assert.ok(!JSON.stringify(m.consoles).includes('motdepasse-vnc'));
  assert.ok(!JSON.stringify(m.consoles).includes('vncpw'), 'ni la clé en clair ni le scellé ne sortent');
  const trace = s.parc.db.prepare("SELECT acteur, objet, details FROM socle_journal WHERE action = 'consoles.modifiees' ORDER BY n DESC LIMIT 1").get();
  assert.equal(trace.objet, 'poste-vnc', 'accès distant journalisé');
  assert.ok(!trace.details.includes('motdepasse-vnc'), 'jamais le secret au journal');
});

test('origine des consoles : la carte s\'affiche hors de l\'origine de Sentinel, par une passe liée à la session', async () => {
  const recus = [];
  const carte = await fauxCarte((req, res) => {
    recus.push({ url: req.url, cookie: req.headers.cookie || '' });
    res.setHeader('Set-Cookie', ['session-carte=posee; Path=/', 'sentinel-sid=volee; Path=/', '__Host-autre=x; Path=/; Secure']);
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Type', 'text/html');
    res.end('<html><head></head><body><img src="/logo.png">carte</body></html>');
  });
  const { client: victor } = await membreInvite(admin, () => s.client(), { identifiant: 'victor' });
  try {
    await enroler(membre, { hostname: 'srv-mandataire' });
    const mref = refMachineParHote('srv-mandataire');
    assert.equal((await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'idrac', target: `https://127.0.0.1:${carte.port}`, label: 'iDRAC', embed: true }] })).status, 200);
    assert.equal((await victor.post(`/api/machines/${mref}/remote`, { idx: 0 })).status, 409, 'pas de passe tant que le certificat n\'est pas épinglé');
    const vu = await admin.get(`/api/machines/${mref}/pin?idx=0`);
    assert.equal((await admin.post(`/api/machines/${mref}/pin`, { idx: 0, fp: vu.json.fp })).status, 200);
    assert.equal((await lecteur.post(`/api/machines/${mref}/remote`, { idx: 0 })).status, 403, 'lecture seule : aucune passe');
    assert.equal((await victor.post(`/api/machines/${mref}/remote`, { idx: 0 }, { origine: 'https://ailleurs.exemple.org' })).status, 403, 'une page d\'un autre site ne tire pas de passe');

    const r = await victor.post(`/api/machines/${mref}/remote`, { idx: 0 });
    assert.equal(r.status, 200);
    const u = new URL(r.json.url);
    assert.equal(u.origin, s.consoles.origine, 'la console est servie par l\'origine des consoles');
    assert.notEqual(u.origin, victor.origine);
    assert.match(u.pathname, /^\/c\/[A-Za-z0-9_-]{43}\/$/);
    const trace = s.parc.db.prepare("SELECT acteur, objet, details FROM socle_journal WHERE action = 'console.ouverte' ORDER BY n DESC LIMIT 1").get();
    assert.equal(trace.objet, 'srv-mandataire', 'ouverture journalisée');
    assert.ok(!trace.details.includes(u.pathname.slice(3, -1)), 'jamais la passe au journal');

    const vitrine = new Client(Number(u.port));
    // Un navigateur n'enverrait pas les cookies de Sentinel à une autre origine ;
    // s'il le faisait, ils ne partiraient pas vers la carte, seuls ou avec les siens.
    vitrine.cookies.set('sentinel-sid', victor.cookies.get('sentinel-sid'));
    assert.equal((await vitrine.get(u.pathname)).status, 200);
    assert.equal(recus.at(-1).cookie, '', 'aucun cookie de Sentinel ne part vers la carte');
    vitrine.cookies.set('session-carte', 'ouverte');
    const page = await vitrine.get(u.pathname);
    assert.equal(page.status, 200, page.texte.slice(0, 200));
    assert.equal(recus.at(-1).cookie, 'session-carte=ouverte', 'seul le cookie de la carte lui parvient');
    assert.deepEqual(page.setCookie.map(c => c.split('=')[0]), ['session-carte'], 'la carte ne pose aucun cookie au nom du service');
    assert.equal(page.entetes['content-security-policy'], `frame-ancestors ${victor.origine}`, 'seule la page de Sentinel qui a tiré la passe l\'encadre');
    assert.equal(page.entetes['x-frame-options'], undefined);
    assert.equal(page.entetes['x-content-type-options'], 'nosniff');
    assert.equal(page.entetes['cache-control'], 'no-store');
    assert.match(page.entetes['permissions-policy'], /camera=\(\), microphone=\(\), geolocation=\(\).*fullscreen=\(self\)/, 'capacités fermées, sauf plein écran et presse-papiers');
    assert.equal(page.entetes['cross-origin-opener-policy'], 'same-origin');
    assert.ok(page.texte.includes(`<base href="${u.pathname}"><script src="/reancrage.js" data-prefixe="${u.pathname}"></script>`), 'réancrage par un script servi, jamais en ligne');
    assert.ok(page.texte.includes(`<img src="${u.pathname}logo.png">`), 'liens absolus sous le préfixe');
    const script = await vitrine.get('/reancrage.js');
    assert.equal(script.status, 200);
    assert.match(script.entetes['content-type'], /^text\/javascript/);
    // Rien de Sentinel ne vit sur cette origine, et une passe inventée n'ouvre rien.
    for (const chemin of ['/', '/index.html', '/app.js', '/api/compte/etat', `/api/machines/${mref}`, `/c/${'A'.repeat(43)}/`]) {
      assert.equal((await vitrine.get(chemin)).status, 404, chemin);
    }
    assert.equal((await vitrine.post(`${u.pathname}connexion`, {}, { origine: victor.origine })).status, 403, 'une écriture ne vient que d\'une page de la console');
    assert.equal((await s.client().get(`/c/${u.pathname.slice(3)}`)).status, 404, 'la passe ne vaut rien sur l\'origine de Sentinel');

    // WebSocket de la carte, par la même passe et la même origine.
    assert.match(await brancherWs(Number(u.port), `${u.pathname}ws`, { Origin: victor.origine }), / 403 /, 'origine étrangère refusée');
    const refus = s.parc.db.prepare("SELECT objet, details FROM socle_journal WHERE action = 'acces.refuse' AND objet = '/c/' ORDER BY n DESC LIMIT 1").get();
    assert.ok(refus && !refus.details.includes(u.pathname.slice(3, -1)), 'refus de l\'origine des consoles journalisé, sans la passe');
    assert.match(await brancherWs(Number(u.port), `/c/${'A'.repeat(43)}/ws`, { Origin: u.origin }), / 404 /);
    const ws = await connecter(`ws://localhost:${u.port}${u.pathname}ws?canal=1`, { entetes: { Origin: u.origin } });
    const echos = [];
    ws.on('texte', t => echos.push(t));
    ws.envoyerTexte('bonjour');
    await attendre(() => echos.length === 1, 3000);
    assert.deepEqual(echos, ['carte:bonjour']);
    assert.equal(carte.upgrades.at(-1).url, '/ws?canal=1');
    ws.close();

    // La passe meurt avec la session qui l'a tirée.
    assert.equal((await victor.post('/api/compte/deconnexion')).status, 200);
    assert.equal((await vitrine.get(u.pathname)).status, 404, 'passe morte après la déconnexion');
  } finally { await carte.fermer(); }
});

test('hôte sans agent (carte de gestion) et refus d\'URL interdite', async () => {
  const carte = { host: 'serveur-b', ip: '198.51.100.30', ctype: 'idrac', target: 'https://198.51.100.30', label: 'iDRAC' };
  assert.equal((await membre.post('/api/hosts', carte)).status, 403, 'un membre ne déclare pas une carte');
  const r = await admin.post('/api/hosts', carte);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.ok(r.json.machines.some(m => m.host === 'serveur-b' && m.source === 'kvm'));
  assert.equal(s.parc.db.prepare("SELECT COUNT(*) n FROM socle_journal WHERE action = 'machine.ajoutee' AND objet = 'serveur-b'").get().n, 1);
  // métadonnées de nuage refusées
  assert.equal((await admin.post('/api/hosts', { host: 'piege', ctype: 'url', target: 'http://169.254.169.254/latest/' })).status, 422);
  // javascript: refusé
  assert.equal((await admin.post('/api/hosts', { host: 'piege2', ctype: 'url', target: 'javascript:alert(1)' })).status, 422);
  // Une carte injoignable : la cause, jamais le message réseau ni l'adresse.
  assert.equal((await admin.post('/api/hosts', { host: 'serveur-eteint', ctype: 'idrac', target: 'https://127.0.0.1:1' })).status, 200);
  const eteint = await admin.get(`/api/machines/${refMachineParHote('serveur-eteint')}/pin?idx=0`);
  assert.equal(eteint.status, 502);
  assert.match(eteint.json.error, /^Carte : injoignable \(réf\. [0-9a-f]{8}\)\.$/);
});

test('automatisations : création, activation, exécution ; un cmd exige l\'admin', async () => {
  const a = await membre.post('/api/automations', { nom: 'Inventaire nuit', kind: 'inventory', cible: 'tous' });
  assert.equal(a.status, 200, JSON.stringify(a.json));
  const ref = a.json.automations.find(x => x.nom === 'Inventaire nuit').id;
  assert.equal((await membre.post(`/api/automations/${ref}/run`)).status, 200);
  assert.equal((await membre.put(`/api/automations/${ref}?enabled=false`)).status, 200);
  assert.equal((await membre.del(`/api/automations/${ref}`)).status, 403, 'une suppression revient à l\'administrateur');
  assert.equal((await admin.del(`/api/automations/${ref}`)).status, 200);
  const traces = s.parc.db.prepare("SELECT action FROM socle_journal WHERE objet = 'Inventaire nuit' ORDER BY n").all().map(l => l.action);
  assert.deepEqual(traces, ['automatisation.creee', 'automatisation.lancee', 'automatisation.suspendue', 'automatisation.supprimee']);
  // une automatisation « commande libre » demande le rôle admin, à chaque geste
  assert.equal((await membre.post('/api/automations', { nom: 'Cmd', kind: 'cmd', payload: 'id', cible: 'tous' })).status, 403);
  const c = await admin.post('/api/automations', { nom: 'Cmd', kind: 'cmd', payload: 'id', cible: 'tous' });
  assert.equal(c.status, 200);
  const cref = c.json.automations.find(x => x.nom === 'Cmd').id;
  assert.equal((await membre.post(`/api/automations/${cref}/run`)).status, 403);
  assert.equal((await membre.put(`/api/automations/${cref}?enabled=false`)).status, 403);
  assert.equal((await membre.put(`/api/automations/${cref}?enabled=true`)).status, 403);
  assert.equal((await admin.del(`/api/automations/${cref}`)).status, 200);
});

test('écritures groupées : un passage d\'automatisation interrompu au milieu ne laisse ni tâche ni passage compté', async () => {
  for (const h of ['poste-lot-a', 'poste-lot-b', 'poste-lot-c']) await enroler(membre, { hostname: h, site: 'Lot' });
  const a = await membre.post('/api/automations', { nom: 'Lot', kind: 'inventory', cible: 'site', cible_val: 'Lot' });
  const ref = a.json.automations.find(x => x.nom === 'Lot').id;
  const taches = () => s.parc.db.prepare("SELECT COUNT(*) n FROM taches WHERE auteur = 'auto:Lot'").get().n;
  s.parc.db.exec("CREATE TEMP TRIGGER coupure BEFORE INSERT ON taches WHEN (SELECT COUNT(*) FROM taches WHERE auteur = 'auto:Lot') >= 2 BEGIN SELECT RAISE(ABORT, 'coupure au milieu du passage'); END");
  try {
    const r = await membre.post(`/api/automations/${ref}/run`);
    assert.equal(r.status, 500);
    assert.match(r.json.error, /^Erreur interne \(réf\. /, 'rien de la base ne sort');
  } finally { s.parc.db.exec('DROP TRIGGER coupure'); }
  assert.equal(taches(), 0, 'aucune tâche à moitié posée');
  assert.equal(s.parc.db.prepare('SELECT runs FROM automatisations WHERE ref = ?').get(ref).runs, 0, 'passage non compté');
  assert.equal((await membre.post(`/api/automations/${ref}/run`)).json.queued, 3);
  assert.equal(taches(), 3);
});

test('commande libre désactivée : ni créée, ni lancée, ni réactivée, ni exécutée par la ronde des automatisations', async () => {
  const x = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-noexec-')), { SENTINEL_ALLOW_EXEC: '0' });
  try {
    const a = x.client();
    await adminComplet(a, { jeton: INSTALL });
    const { jeton } = await enroler(a, { hostname: 'poste-sans-cmd' });
    assert.ok(jeton);
    assert.equal((await a.post(`/api/machines/${x.db.prepare("SELECT ref FROM machines WHERE host = 'poste-sans-cmd'").get().ref}/jobs`, { kind: 'cmd', payload: 'id' })).status, 403, 'ni en tâche');
    assert.equal((await a.post('/api/automations', { nom: 'Cmd', kind: 'cmd', payload: 'id', cible: 'tous' })).status, 403);
    const refus = x.db.prepare("SELECT objet, details FROM socle_journal WHERE action = 'acces.refuse' ORDER BY n DESC LIMIT 1").get();
    assert.equal(refus.objet, '/api/automations', 'refus décidé par Sentinel, journalisé comme ceux du socle');
    assert.match(refus.details, /SENTINEL_ALLOW_EXEC/);
    // Une automatisation « commande libre » d'avant la désactivation (ou reprise de la 1.x).
    x.db.prepare("INSERT INTO automatisations(ref, nom, kind, payload, cible, toutes_h, heure, actif) VALUES('EEEEEEEEEEEEEEEE', 'Ancienne', 'cmd', 'id', 'tous', 1, 0, 0)").run();
    x.db.prepare("INSERT INTO automatisations(ref, nom, kind, payload, cible, toutes_h, heure, actif) VALUES('FFFFFFFFFFFFFFFF', 'Inventaire', 'inventory', '', 'tous', 1, 0, 1)").run();
    assert.equal((await a.put('/api/automations/EEEEEEEEEEEEEEEE?enabled=true')).status, 403);
    assert.equal((await a.post('/api/automations/EEEEEEEEEEEEEEEE/run')).status, 403);
    x.db.prepare("UPDATE automatisations SET actif = 1 WHERE ref = 'EEEEEEEEEEEEEEEE'").run();
    x.taches.tour();
    assert.deepEqual(x.db.prepare('SELECT kind FROM taches').all().map(t => t.kind), ['inventory'], 'la ronde laisse la commande libre de côté');
  } finally { await x.arreter(); }
});

test('le jeton du Hub n\'ouvre que l\'état, les tâches et le réveil', async () => {
  const h = { authorization: `Bearer ${JETON_HUB}` };
  const hub = s.client();
  assert.equal((await hub.req('GET', '/api/summary', undefined, { entetes: h })).status, 200);
  assert.equal((await hub.req('GET', '/api/state', undefined, { entetes: h })).status, 200);
  // fermé : comptes, réglages, consoles, suppression
  for (const [m, p] of [['GET', '/api/compte/admin/comptes'], ['GET', '/api/automations'], ['GET', '/api/settings'], ['DELETE', '/api/machines/AAAAAAAAAAAAAAAA']]) {
    assert.equal((await hub.req(m, p, m === 'DELETE' ? undefined : undefined, { entetes: h, origine: null })).status !== 200, true, `${m} ${p} fermé au Hub`);
  }
  // jeton faux refusé
  assert.equal((await hub.req('GET', '/api/summary', undefined, { entetes: { authorization: 'Bearer faux' } })).status, 401);
  // une commande libre ne passe jamais par le Hub, et le refus est journalisé
  await enroler(membre, { hostname: 'poste-hub-cmd' });
  const refuse = await s.client().req('POST', `/api/machines/${refMachineParHote('poste-hub-cmd')}/jobs`, { kind: 'cmd', payload: 'id' }, { entetes: h, origine: null });
  assert.equal(refuse.status, 403, JSON.stringify(refuse.json));
  assert.match(s.parc.db.prepare("SELECT details FROM socle_journal WHERE action = 'acces.refuse' ORDER BY n DESC LIMIT 1").get().details, /jamais par le Hub/);
});

test('données d\'un compte : export sous renfort (tâches lancées, alertes acquittées), neutralisées à la suppression', async () => {
  const { client: dora } = await membreInvite(admin, () => s.client(), { identifiant: 'dora' });
  const { jeton } = await enroler(dora, { hostname: 'poste-dora' });
  const mref = refMachineParHote('poste-dora');
  const t = await dora.post(`/api/machines/${mref}/jobs`, { kind: 'install', payload: 'htop' });
  assert.equal(t.status, 200);
  await dora.req('POST', '/api/ingest', { hostname: 'poste-dora', oskind: 'lin', cpu: 1, ram: 1, disk: 1, av: 'absent', fw: 'actif', enc: 'LUKS actif' }, { entetes: { 'x-agent-token': jeton }, origine: null });
  const alerte = s.parc.db.prepare("SELECT ref FROM alertes WHERE regle = 'antivirus' AND etat = 'ouverte' AND machine_id = ?").get(s.parc.idDe(mref)).ref;
  assert.equal((await dora.post(`/api/alerts/${alerte}/ack`)).status, 200);
  const r = await dora.get('/api/compte/export');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.compte.identifiant, 'dora');
  assert.deepEqual(r.json.sentinel.taches_lancees.map(x => [x.id, x.machine, x.kind, x.payload]), [[t.json.id, 'poste-dora', 'install', 'htop']]);
  assert.deepEqual(r.json.sentinel.alertes_acquittees.map(x => [x.id, x.regle]), [[alerte, 'antivirus']]);
  const id = s.parc.db.prepare("SELECT id FROM socle_comptes WHERE identifiant='dora'").get().id;
  assert.equal((await dora.post('/api/compte/supprimer', { identifiant: 'dora' })).status, 200);
  assert.equal(s.parc.db.prepare('SELECT COUNT(*) n FROM socle_comptes WHERE id=?').get(id).n, 0);
  assert.deepEqual({ ...s.parc.db.prepare('SELECT auteur, auteur_compte FROM taches WHERE ref = ?').get(t.json.id) }, { auteur: 'compte supprimé', auteur_compte: null });
  assert.deepEqual({ ...s.parc.db.prepare('SELECT acquitte_par, acquitte_compte FROM alertes WHERE ref = ?').get(alerte) }, { acquitte_par: 'compte supprimé', acquitte_compte: null });
  assert.equal(s.parc.db.prepare("SELECT COUNT(*) n FROM taches WHERE auteur = 'dora' OR auteur_compte = ?").get(id).n, 0, 'plus rien ne désigne le compte');
});

test('CSRF : une écriture de session sans jeton anti-CSRF est refusée', async () => {
  assert.equal((await membre.post('/api/automations', { nom: 'x', kind: 'inventory' }, { sansCsrf: true })).status, 403);
});

test('MeshCentral : nœud validé, URL de bureau construite ; jeton de connexion AES-GCM', () => {
  assert.equal(nodeValide('node//abc$def@ghi'), true);
  assert.equal(nodeValide('mauvais node'), false);
  assert.equal(nodeValide('a?b'), false);
  const u = urlBureau('node//abc', { meshUrl: 'https://mesh.exemple.org', user: 'op', cle: '00'.repeat(32), viewmode: '11' });
  assert.match(u, /^https:\/\/mesh\.exemple\.org\/\?login=/);
  assert.match(u, /gotonode=node%2F%2Fabc|gotonode=node\/\/abc/);
});

test('SYNAPSE informé des enrôlements et des tâches (jamais le contenu sensible)', async () => {
  await enroler(membre, { hostname: 'poste-synapse' });
  await new Promise(r => setTimeout(r, 2600));
  assert.ok(syn.evenements.some(e => e.kind === 'machine.enrolled'), 'enrôlement raconté');
  assert.ok(syn.evenements.every(e => !JSON.stringify(e).includes('motdepasse')), 'aucun secret raconté');
});

test('SYNAPSE : une redirection n\'est jamais suivie, le jeton ne part qu\'à l\'adresse configurée', async () => {
  const ailleurs = [];
  const piege = http.createServer((req, res) => { ailleurs.push(req.headers.authorization || ''); res.end('{}'); });
  const redirige = http.createServer((req, res) => { req.resume(); res.writeHead(307, { location: `http://127.0.0.1:${piege.address().port}/v1/ingest/batch` }); res.end(); });
  await new Promise(r => piege.listen(0, '127.0.0.1', r));
  await new Promise(r => redirige.listen(0, '127.0.0.1', r));
  try {
    const { Synapse } = await import('../src/synapse.js');
    const x = new Synapse({ url: `http://127.0.0.1:${redirige.address().port}`, jeton: JETON_SYNAPSE, log: SILENCE });
    x.raconter('essai', 'Un événement');
    clearTimeout(x.minuterie);
    await x.vider();
    clearTimeout(x.minuterie);
    assert.deepEqual(ailleurs, [], 'rien n\'atteint la cible de la redirection');
    assert.equal(x.etat.echecs, 1);
    assert.equal(x.file.length, 1, 'l\'événement reste dans la file');
  } finally { await new Promise(r => piege.close(r)); await new Promise(r => redirige.close(r)); }
});

test('migration 1.1.0 : comptes, machines, automatisations reprises ; l\'agent se réenrôle par son nom', async () => {
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-v1-'));
  const db = new DatabaseSync(path.join(dossier, 'sentinel.db'));
  // empreinte scrypt de la 1.x (format hashpw : scrypt$sel$empreinte) pour « ancienne phrase de passe sentinel ».
  const sel = crypto.randomBytes(16);
  const dk = crypto.scryptSync('ancienne phrase de passe sentinel', sel, 32, { N: 16384, r: 8, p: 1 });
  const empreinte = `scrypt$${sel.toString('hex')}$${dk.toString('hex')}`;
  db.exec(`CREATE TABLE auth(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT, pw_hash TEXT, totp_secret TEXT, pending_secret TEXT, must_change INTEGER DEFAULT 1, tfa_enabled INTEGER DEFAULT 0);
    CREATE TABLE agents(id INTEGER PRIMARY KEY, host TEXT, ip TEXT, site TEXT, os TEXT, oskind TEXT, role TEXT, online INTEGER, risk INTEGER, cpu INTEGER, ram INTEGER, disk INTEGER, av TEXT, fw TEXT, enc TEXT, patch INTEGER, hist TEXT, source TEXT, last_report REAL, mesh_node TEXT, consoles TEXT, rf_url TEXT, rf_user TEXT, rf_secret TEXT, inventory TEXT, software TEXT, updates TEXT, mac TEXT, inv_at REAL);
    CREATE TABLE alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, sev TEXT, txt TEXT, host_id INTEGER, created REAL);
    CREATE TABLE automations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT, payload TEXT, target TEXT, target_val TEXT, every INTEGER, at_hour INTEGER, enabled INTEGER, last_run REAL, last_status TEXT, runs INTEGER);
    CREATE TABLE feed(id INTEGER PRIMARY KEY AUTOINCREMENT, html TEXT, ip TEXT, created REAL);`);
  db.prepare('INSERT INTO auth(id,username,pw_hash,totp_secret,must_change,tfa_enabled) VALUES(1,?,?,?,0,1)').run('operateur', empreinte, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
  db.prepare("INSERT INTO agents(id,host,ip,site,oskind,role,source,consoles,last_report) VALUES(1,'poste-legacy','198.51.100.40','Prod','win','poste','agent',?,?)").run(JSON.stringify([{ type: 'vnc', target: '198.51.100.40:5900', label: 'KVM', vncpw_enc: 'ancien-scelle' }]), Date.now() / 1000);
  db.prepare("INSERT INTO agents(id,host,ip,site,oskind,role,source,consoles) VALUES(2,'serveur-legacy','198.51.100.41','Prod','hw','matériel','kvm',?)").run(JSON.stringify([{ type: 'idrac', target: 'https://198.51.100.41', label: 'iDRAC' }, { type: 'type-obsolete', target: 'https://198.51.100.41/vm', label: 'VM' }]));
  db.prepare("INSERT INTO automations(name,kind,payload,target,every,at_hour,enabled,runs) VALUES('MAJ','update','','all',24,3,1,4)").run();
  db.close();
  const v1 = await lancer(dossier);
  try {
    const lignes = v1.serveur; void lignes;
    const dbv = v1.db;
    assert.deepEqual(dbv.prepare('SELECT identifiant, role FROM socle_comptes').all().map(r => ({ identifiant: r.identifiant, role: r.role })), [{ identifiant: 'operateur', role: 'admin' }]);
    const totp = dbv.prepare("SELECT totp FROM socle_comptes WHERE identifiant='operateur'").get().totp;
    assert.ok(totp.startsWith('v1.') && !totp.includes('JBSWY3DP'), 'TOTP scellé');
    assert.equal(dbv.prepare("SELECT COUNT(*) n FROM machines").get().n, 2, 'machines reprises');
    const leg = dbv.prepare("SELECT jeton_hash, consoles FROM machines WHERE host='poste-legacy'").get();
    assert.equal(leg.jeton_hash, null, 'agent legacy sans jeton : se réenrôle');
    assert.ok(!leg.consoles.includes('vncpw_enc'), 'ancien secret scellé retiré');
    const consServeur = JSON.parse(dbv.prepare("SELECT consoles FROM machines WHERE host='serveur-legacy'").get().consoles);
    assert.ok(consServeur.some(x => x.type === 'idrac'), 'type de console connu conservé');
    assert.ok(consServeur.some(x => x.type === 'hyperviseur'), 'type de console disparu ramené sur le type générique');
    assert.equal(dbv.prepare('SELECT COUNT(*) n FROM automatisations').get().n, 1);
    assert.equal(dbv.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE name IN ('agents','auth','alerts')").get().n, 0, 'tables 1.x retirées');
    // l'opérateur se reconnecte avec l'ancien mot de passe (l'empreinte scrypt se relit)
    const c = new Client(v1.port);
    const r = await c.post('/api/compte/connexion', { identifiant: 'operateur', motDePasse: 'ancienne phrase de passe sentinel', preuve: undefined });
    assert.ok([200, 428].includes(r.status), 'empreinte scrypt relue');
    // le réenrôlement d'un agent legacy le rattache à sa machine par le nom d'hôte
  } finally { await v1.arreter(); }
});

test('migration 1.1.0 : l\'opérateur resté au mot de passe d\'amorçage reçoit au journal un lien qui lui rend l\'accès', async () => {
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-v1-'));
  const db = new DatabaseSync(path.join(dossier, 'sentinel.db'));
  db.exec('CREATE TABLE auth(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT, pw_hash TEXT, totp_secret TEXT, pending_secret TEXT, must_change INTEGER DEFAULT 1, tfa_enabled INTEGER DEFAULT 0)');
  db.prepare('INSERT INTO auth(id, username, pw_hash) VALUES(1, ?, ?)').run('operateur', 'scrypt$00$00');
  db.close();
  const avertis = [];
  const log = { ...SILENCE, warn: m => avertis.push(String(m)) };
  const base = { PORT: '0', HOTE: '127.0.0.1', DATA_DIR: dossier, SENTINEL_HUB_TOKEN: JETON_HUB, SOCLE_CLE: crypto.randomBytes(32).toString('base64'), SYNAPSE_URL: syn.url, SYNAPSE_JETON: JETON_SYNAPSE };
  let x = await demarrer(base, { log });
  try {
    const lien = avertis.find(m => m.includes('#reinit='));
    assert.ok(lien, 'lien de secours écrit au journal');
    const c = new Client(x.serveur.address().port);
    const r = await c.post('/api/compte/jeton', { usage: 'reinit', jeton: /#reinit=([\w-]+)/.exec(lien)[1], motDePasse: 'phrase de passe neuve pour sentinel' });
    assert.equal(r.status, 200);
    assert.equal(r.json.etape, 'connexion');
  } finally { await x.arreter(); }
  // L'administrateur tient un mot de passe : le démarrage suivant n'écrit plus de lien.
  avertis.length = 0;
  x = await demarrer(base, { log });
  try { assert.ok(!avertis.some(m => m.includes('#reinit=')), 'aucun lien une fois l\'accès rendu'); } finally { await x.arreter(); }
});

test('base des premières 2.0 : codes d\'inscription en clair écartés, table reprise sous sa forme hachée', async () => {
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-codes-'));
  const db = new DatabaseSync(path.join(dossier, 'sentinel.db'));
  db.exec("CREATE TABLE enrolements(code TEXT PRIMARY KEY, expire REAL NOT NULL, site TEXT NOT NULL DEFAULT 'Agents', nom TEXT DEFAULT '', relais INTEGER NOT NULL DEFAULT 0, cree REAL NOT NULL)");
  db.prepare('INSERT INTO enrolements(code, expire, cree) VALUES(?,?,?)').run('codeenclairdunevieillebase', Date.now() / 1000 + 3600, Date.now() / 1000);
  db.close();
  const x = await lancer(dossier);
  try {
    assert.deepEqual(x.db.prepare("SELECT name FROM pragma_table_info('enrolements')").all().map(c => c.name).slice(0, 2), ['empreinte', 'expire']);
    assert.equal(x.db.prepare('SELECT COUNT(*) n FROM enrolements').get().n, 0);
  } finally { await x.arreter(); }
});

test('une configuration invalide arrête le démarrage', async () => {
  await assert.rejects(() => demarrer({ ...env, DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 's-')), SENTINEL_HUB_TOKEN: 'court', PORT: 'abc' }, { log: SILENCE }), /PORT|SENTINEL_HUB_TOKEN/);
  // Un démarrage qui aboutirait est arrêté aussitôt : l'essai échoue au lieu de laisser un serveur ouvert.
  const erreurDe = async extra => {
    let x;
    try { x = await demarrer({ ...env, DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 's-')), ...extra }, { log: SILENCE }); } catch (e) { return e.message; }
    await x.arreter();
    return 'démarré';
  };
  const vide = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 's-')), 'socle_cle');
  fs.writeFileSync(vide, '\n');
  assert.match(await erreurDe({ SOCLE_CLE: '', SOCLE_CLE_FILE: vide }), /SOCLE_CLE_FILE/, 'secret vide : la clé n\'est jamais tirée dans le volume');
  for (const [variable, valeur] of [['SENTINEL_MESH_LOGIN_KEY', 'abcd'], ['SENTINEL_MESH_LOGIN_KEY', '0'.repeat(63)], ['SYNAPSE_JETON', 'court'], ['SYNAPSE_JETON', 'changeme-changeme-changeme'], ['SENTINEL_CONSOLE_URL', 'http://consoles.exemple.org/chemin']]) {
    assert.match(await erreurDe({ [variable]: valeur }), new RegExp(variable), `${variable}=${valeur}`);
  }
});

test('WebSocket : origine étrangère refusée, version non 13 refusée', async () => {
  // mise à niveau /vnc avec une origine étrangère → 403, sans session → 401
  const r = await brancherWs(s.port, '/vnc/AAAAAAAAAAAAAAAA/0', { origin: 'https://mechant.exemple.org' });
  assert.match(r, /403|401/);
});

test('WebSocket : trames de contrôle démesurées ou fragmentées refusées, jamais renvoyées', () => {
  const trame = (octet0, charge) => {
    const cle = crypto.randomBytes(4), masquee = Buffer.from(charge.map((o, k) => o ^ cle[k & 3]));
    const tete = charge.length < 126 ? Buffer.from([octet0, 0x80 | charge.length]) : Buffer.from([octet0, 0x80 | 126, charge.length >> 8, charge.length & 0xff]);
    return Buffer.concat([tete, cle, masquee]);
  };
  for (const [nom, t] of [['ping de 126 octets', trame(0x89, [...Buffer.alloc(126, 1)])], ['ping fragmenté', trame(0x09, [1, 2, 3])]]) {
    const ecrits = [];
    const socket = { on(evt, fn) { this[evt] = fn; }, write: b => ecrits.push(Buffer.from(b)), end() {}, destroy() { this.destroyed = true; }, setTimeout() {}, destroyed: false };
    new Connexion(socket).on('texte', () => {});
    socket.data(t);
    assert.equal(ecrits.length, 1, nom);
    assert.equal(ecrits[0][0], 0x88, `${nom} : fermeture, pas de pong`);
    assert.equal(ecrits[0].readUInt16BE(2), 1002, `${nom} : erreur de protocole`);
    assert.equal(socket.destroyed, true);
  }
});

function attendre(cond, ms = 1500) {
  return new Promise((res, rej) => {
    const t0 = Date.now();
    const i = setInterval(() => { if (cond()) { clearInterval(i); res(); } else if (Date.now() - t0 > ms) { clearInterval(i); rej(new Error('délai')); } }, 15);
  });
}
function brancherWs(port, chemin, entetes = {}) {
  return new Promise(resolve => {
    const sock = net.connect(port, '127.0.0.1', () => {
      const cle = crypto.randomBytes(16).toString('base64');
      const t = [`GET ${chemin} HTTP/1.1`, `Host: ${entetes.Host || `localhost:${port}`}`, 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Key: ${cle}`, 'Sec-WebSocket-Version: 13'];
      for (const [k, v] of Object.entries(entetes)) if (k !== 'Host') t.push(`${k}: ${v}`);
      sock.write(t.join('\r\n') + '\r\n\r\n');
    });
    let buf = '';
    sock.on('data', d => { buf += d; if (buf.includes('\r\n\r\n')) { sock.destroy(); resolve(buf.split('\r\n')[0]); } });
    sock.on('error', () => resolve('erreur'));
    setTimeout(() => { sock.destroy(); resolve(buf.split('\r\n')[0] || 'délai'); }, 2000);
  });
}

test('alertes : chaque règle s\'ouvre sur une remontée, puis se résout d\'elle-même', async () => {
  const hote = 'poste-alertes';
  const { jeton } = await enroler(membre, { hostname: hote });
  const sain = { hostname: hote, ip: '198.51.100.50', os: 'Ubuntu 24.04', oskind: 'lin', cpu: 5, ram: 20, disk: 40, av: 'à jour', fw: 'actif', enc: 'LUKS actif', patch: 0 };
  const remonter = async (extra = {}) => assert.equal((await membre.req('POST', '/api/ingest', { ...sain, ...extra }, { entetes: { 'x-agent-token': jeton }, origine: null })).status, 200);
  const alertes = async () => (await membre.get('/api/state')).json.alertes.filter(a => a.machine?.host === hote);
  const ouvertes = async regle => (await alertes()).filter(a => a.etat === 'ouverte' && (!regle || a.regle === regle));
  const mref = refMachineParHote(hote);
  const flux = await ecouter(membre);
  try {
    await remonter();
    assert.deepEqual(await ouvertes(), [], 'poste sain : aucune alerte');
    for (const [regle, mauvais, attendu] of [
      ['antivirus', { av: 'inactif' }, /Antivirus inactif/], ['antivirus', { av: 'absent' }, /Antivirus absent/],
      ['pare-feu', { fw: 'inactif' }, /Pare-feu inactif/], ['chiffrement', { enc: 'non chiffré' }, /non chiffré/],
      ['disque', { disk: 95 }, /95 %/],
    ]) {
      await remonter(mauvais);
      const o = await ouvertes(regle);
      assert.equal(o.length, 1, `${regle} ouverte`);
      assert.match(o[0].txt, attendu);
      await remonter();
      assert.equal((await ouvertes(regle)).length, 0, `${regle} résolue`);
      assert.ok((await alertes()).some(a => a.regle === regle && a.etat === 'resolue' && a.resolue >= a.cree), `${regle} : résolution horodatée`);
    }
    // Score de risque : plusieurs défauts constatés ensemble.
    await remonter({ av: 'absent', fw: 'inactif', enc: 'non chiffré' });
    assert.match((await ouvertes('risque'))[0]?.txt || '', /Score de risque 75/);
    await remonter();
    assert.deepEqual(await ouvertes(), []);
    // Correctifs de sécurité : pas d'alerte le premier jour, alerte passé N jours,
    // résolue quand la liste n'en contient plus.
    await remonter({ updates: [{ name: 'openssl', security: true, kind: 'Système' }, { name: 'vim', security: false, kind: 'Système' }] });
    assert.equal((await ouvertes('correctifs')).length, 0);
    s.parc.db.prepare('UPDATE machines SET sec_depuis = ? WHERE ref = ?').run(Date.now() / 1000 - 8 * 86400, mref);
    await remonter();
    assert.match((await ouvertes('correctifs'))[0]?.txt || '', /^1 correctif\(s\) de sécurité en attente depuis plus de 7 jour/);
    await remonter({ updates: [] });
    assert.equal((await ouvertes('correctifs')).length, 0);
    // Hors ligne : ouverte par la collecte, résolue par la remontée suivante.
    s.parc.db.prepare('UPDATE machines SET last_report = ? WHERE ref = ?').run(Date.now() / 1000 - 20 * 60, mref);
    assert.equal((await membre.post('/api/collect')).status, 200);
    assert.match((await ouvertes('hors-ligne'))[0]?.txt || '', /Aucune remontée depuis 20 min/);
    await remonter();
    assert.equal((await ouvertes('hors-ligne')).length, 0);
    // Une valeur illisible n'ouvre ni ne résout rien.
    await remonter({ av: 'absent' });
    await remonter({ av: 'inconnu', fw: 'inconnu', enc: 'inconnu' });
    assert.equal((await ouvertes('antivirus')).length, 1, 'le silence ne résout pas');
    assert.equal((await ouvertes('pare-feu')).length, 0, 'l\'inconnu n\'ouvre pas');
    await remonter();
    assert.deepEqual(await ouvertes(), []);
    // Événements poussés en direct à l'ouverture et à la résolution.
    await attendre(() => flux.evenements.some(e => e.t === 'alerte' && e.etat === 'resolue' && e.alerte.regle === 'antivirus'), 2000);
    assert.ok(flux.evenements.some(e => e.t === 'alerte' && e.etat === 'ouverte' && e.alerte.regle === 'disque' && e.alerte.machine.host === hote));
  } finally { flux.fermer(); }
});

test('alertes : jamais de doublon, acquittement, résumé, SYNAPSE', async () => {
  const hote = 'poste-doublon';
  const { jeton } = await enroler(membre, { hostname: hote });
  const corps = disk => ({ hostname: hote, ip: '198.51.100.51', oskind: 'lin', cpu: 5, ram: 20, disk, av: 'à jour', fw: 'actif', enc: 'LUKS actif', patch: 0 });
  for (const d of [95, 96, 97]) await membre.req('POST', '/api/ingest', corps(d), { entetes: { 'x-agent-token': jeton }, origine: null });
  const mid = s.parc.idDe(refMachineParHote(hote));
  const lignes = s.parc.db.prepare("SELECT * FROM alertes WHERE machine_id = ? AND regle = 'disque'").all(mid);
  assert.equal(lignes.length, 1, 'une seule alerte pour (machine, règle)');
  assert.match(lignes[0].txt, /97 %/, 'le texte suit la mesure');
  assert.throws(() => s.parc.db.prepare("INSERT INTO alertes(ref, regle, sev, txt, machine_id, etat, cree) VALUES('BBBBBBBBBBBBBBBB','disque','warn','x',?,'ouverte',0)").run(mid), /UNIQUE/, 'la base refuse un doublon ouvert');
  assert.equal((await new Client(s.port).req('GET', '/api/summary', undefined, { entetes: { authorization: `Bearer ${JETON_HUB}` } })).json.alertes,
    s.parc.db.prepare("SELECT COUNT(*) n FROM alertes WHERE etat = 'ouverte'").get().n, 'le résumé compte les alertes ouvertes');
  // Acquitter : vu, pris en charge — l'alerte reste ouverte tant que la cause dure.
  const ref = lignes[0].ref;
  assert.equal((await lecteur.post(`/api/alerts/${ref}/ack`)).status, 403);
  assert.equal((await membre.post('/api/alerts/CCCCCCCCCCCCCCCC/ack')).status, 404);
  const r = await membre.post(`/api/alerts/${ref}/ack`);
  assert.equal(r.status, 200);
  const vue = r.json.alertes.find(a => a.id === ref);
  assert.equal(vue.etat, 'ouverte');
  assert.equal(vue.acquitte_par, 'bruno');
  assert.ok(vue.acquittee);
  await membre.req('POST', '/api/ingest', corps(40), { entetes: { 'x-agent-token': jeton }, origine: null });
  assert.equal(s.parc.db.prepare('SELECT etat FROM alertes WHERE ref = ?').get(ref).etat, 'resolue', 'résolue par la mesure, acquittement gardé');
  // Une alerte sans règle (reprise de la 1.x) se ferme à l'acquittement.
  s.parc.db.prepare("INSERT INTO alertes(ref, sev, txt, machine_id, cree) VALUES('DDDDDDDDDDDDDDDD','crit','Reprise de la 1.x',?,?)").run(mid, Date.now() / 1000);
  assert.equal((await membre.post('/api/alerts/DDDDDDDDDDDDDDDD/ack')).json.alertes.find(a => a.id === 'DDDDDDDDDDDDDDDD').etat, 'resolue');
  await attendre(() => syn.evenements.some(e => e.kind === 'alert.resolved' && e.meta?.host === hote), 4000);
  assert.ok(syn.evenements.some(e => e.kind === 'alert.opened' && e.meta?.regle === 'disque' && e.meta?.host === hote), 'ouverture racontée à SYNAPSE');
});

test('alimentation : allumer reste au membre ; couper, arrêter, redémarrer, forcer exigent admin + renfort', async () => {
  const carte = await fauxRedfish();
  try {
    await enroler(membre, { hostname: 'srv-alim' });
    const mref = refMachineParHote('srv-alim');
    assert.equal((await admin.put(`/api/machines/${mref}/redfish`, { url: carte.url, user: 'root', password: 'motdepasse-carte' })).status, 200);
    await epinglerRedfish(admin, mref);
    const etat = await membre.get(`/api/machines/${mref}/power`);
    assert.equal(etat.status, 200, JSON.stringify(etat.json));
    assert.equal(etat.json.power, 'On');
    assert.equal((await membre.post(`/api/machines/${mref}/power`, { action: 'on' })).status, 200);
    for (const action of ['off', 'arret', 'redemarrer', 'cycle']) {
      assert.equal((await membre.post(`/api/machines/${mref}/power`, { action })).status, 403, `${action} refusé au membre`);
    }
    assert.equal((await lecteur.post(`/api/machines/${mref}/power`, { action: 'on' })).status, 403);
    await sansRenfort(async () => {
      const r = await admin.post(`/api/machines/${mref}/power`, { action: 'off' });
      assert.equal(r.status, 403);
      assert.equal(r.json.details?.renfort, true, 'renfort redemandé');
    });
    assert.equal((await admin.post(`/api/machines/${mref}/power`, { action: 'redemarrer' })).status, 200);
    assert.deepEqual(carte.actions, ['On', 'ForceRestart'], 'seules les actions permises ont atteint la carte');
    assert.equal(carte.refus(), 0, 'identifiants rescellés correctement déchiffrés');
    // Une carte qui refuse : une cause et une référence, jamais sa réponse ni son adresse.
    assert.equal((await admin.put(`/api/machines/${mref}/redfish`, { url: carte.url, user: 'root', password: 'mauvais-mot-de-passe' })).status, 200);
    const refusee = await membre.get(`/api/machines/${mref}/power`);
    assert.equal(refusee.status, 502);
    assert.match(refusee.json.error, /^Alimentation illisible : refusée par la carte \(réf\. [0-9a-f]{8}\)\.$/);
  } finally { await carte.fermer(); }
});

test('sonde TLS : admin + renfort seulement, aucun octet applicatif, empreinte et sujet seuls', async () => {
  const carte = await fauxTlsCompteur();
  try {
    await enroler(membre, { hostname: 'srv-sonde' });
    const mref = refMachineParHote('srv-sonde');
    assert.equal((await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'idrac', target: `https://127.0.0.1:${carte.port}`, label: 'iDRAC' }] })).status, 200);
    const chemin = `/api/machines/${mref}/pin?idx=0`;
    assert.equal((await s.client().get(chemin)).status, 401);
    assert.equal((await lecteur.get(chemin)).status, 403);
    assert.equal((await membre.get(chemin)).status, 403);
    assert.notEqual((await s.client().req('GET', chemin, undefined, { entetes: { authorization: `Bearer ${JETON_HUB}` }, origine: null })).status, 200, 'le Hub ne sonde pas');
    await sansRenfort(async () => assert.equal((await admin.get(chemin)).status, 403));
    assert.equal(carte.connexions.length, 0, 'aucun refus n\'a touché la carte');
    const vu = await admin.get(chemin);
    assert.equal(vu.status, 200, JSON.stringify(vu.json));
    assert.deepEqual(Object.keys(vu.json).sort(), ['fp', 'sujet'], 'rien d\'autre que l\'empreinte et le sujet');
    assert.equal(vu.json.sujet, 'carte-b');
    assert.equal((await admin.post(`/api/machines/${mref}/pin`, { idx: 0, fp: 'ab'.repeat(32) })).status, 409, 'autre empreinte : refusée');
    // Empreinte confirmée sous sa forme nue (sans l'étiquette sha256:) : acceptée.
    assert.equal((await admin.post(`/api/machines/${mref}/pin`, { idx: 0, fp: vu.json.fp.replace(/^sha256:/, '').toUpperCase() })).status, 200);
    await attendre(() => carte.connexions.length === 3 && carte.connexions.every(c => c.duree !== null), 3000);
    for (const c of carte.connexions) {
      assert.equal(c.poignee, true, 'poignée TLS menée à son terme');
      assert.equal(c.octets, 0, 'aucun octet applicatif après la poignée');
      assert.ok(c.duree < 1500, `connexion fermée aussitôt (${c.duree} ms)`);
    }
  } finally { await carte.fermer(); }
});

test('inscription : scripts Windows (Python + venv), Linux et macOS ; valeurs piégées refusées', async () => {
  const info = (await membre.post('/api/enroll/info', { site: 'Prod', name: 'serveur-a' })).json;
  assert.match(info.commands.windows, /^powershell -ExecutionPolicy Bypass -Command "irm '[^']+&name=serveur-a' \| iex"$/);
  assert.match(info.commands.linux, /&name=serveur-a' \| sudo bash$/);
  const anon = s.client();
  const w = await anon.get(`/api/enroll/script?os=windows&code=${info.code}&site=Prod&name=serveur-a`);
  assert.equal(w.status, 200);
  assert.match(w.entetes['content-disposition'], /installer-sentinel\.ps1/);
  for (const attendu of [`$Code = '${info.code}'`, "$Site = 'Prod'", "$Nom = 'serveur-a'", 'function Find-Python', '*WindowsApps*', 'Python.Python.3.12',
    '-m venv "$Dir\\venv"', 'requirements.txt?code=$Code', 'icacls $Dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"', 'pip install -q --require-hashes --prefer-binary -r "$Dir\\requirements.txt"', 'sentinel-agent.py" --enroller', '$LASTEXITCODE -ne 0']) {
    assert.ok(w.texte.includes(attendu), `script Windows : ${attendu}`);
  }
  for (const systeme of ['linux', 'macos']) {
    const r = await anon.get(`/api/enroll/script?os=${systeme}&code=${info.code}&site=Prod&name=serveur-a`);
    assert.equal(r.status, 200);
    assert.ok(r.texte.includes('-m venv') && r.texte.includes('--enroller'));
    assert.ok(r.texte.includes('pip" install -q --require-hashes --prefer-binary -r "$DIR/requirements.txt"'), `${systeme} : dépendances vérifiées par empreinte`);
    assert.doesNotMatch(r.texte, /--upgrade/, `${systeme} : aucune version tirée au hasard`);
    const f = path.join(fs.mkdtempSync(path.join(base, 'script-')), 'installer.sh');
    fs.writeFileSync(f, r.texte);
    execFileSync('bash', ['-n', f]);   // syntaxe bash valide
  }
  const exigences = await anon.get(`/api/enroll/requirements.txt?code=${info.code}`);
  assert.equal(exigences.status, 200);
  assert.equal(exigences.texte, fs.readFileSync(path.join(import.meta.dirname, '..', 'agent', 'requirements.txt'), 'utf8'));
  const paquets = exigences.texte.split(/(?<!\\)\n/).filter(l => /^[a-z]/.test(l));
  assert.ok(paquets.length >= 6 && paquets.every(l => /^[a-z0-9-]+==[0-9.]+( ; [^\\]+)? \\\n(\s+--hash=sha256:[0-9a-f]{64}( \\\n)?)+$/.test(l)), 'chaque dépendance : une version exacte et ses empreintes');
  assert.equal((await anon.post('/api/enroll/config', { code: info.code })).status, 200, 'télécharger les scripts ne consomme pas le code');
  // Rien de ce qui entre dans un script root ne peut en sortir.
  const avant = s.parc.db.prepare('SELECT COUNT(*) n FROM enrolements').get().n;
  for (const piege of ["x';id;'", 'x"$(id)"', 'a`id`', 'a\\b']) {
    assert.equal((await membre.post('/api/enroll/info', { site: piege })).status, 422, piege);
    assert.equal((await membre.post('/api/enroll/info', { name: piege })).status, 422, piege);
    assert.equal((await membre.get(`/api/enroll/script?os=linux&code=${encodeURIComponent(piege)}`)).status, 422, `code ${piege} (session)`);
  }
  assert.equal(s.parc.db.prepare('SELECT COUNT(*) n FROM enrolements').get().n, avant, 'aucun code tiré pour une demande refusée');
  assert.equal((await membre.get('/api/enroll/script?os=__proto__&code=AAAAAAAAAAAA')).status, 404);
});

test('rotation de SOCLE_CLE : secrets d\'appareils rescellés, jetons d\'agents intacts ; secret resté sous l\'ancienne clé : arrêt tant qu\'elle manque', async () => {
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-rot-'));
  const cle = () => crypto.randomBytes(32).toString('base64');
  const k1 = cle(), k2 = cle();
  const carte = await fauxRedfish();
  let x = await lancer(dossier, { SOCLE_CLE: k1 });
  try {
    const a = x.client();
    await adminComplet(a, { jeton: INSTALL });
    const { jeton } = await enroler(a, { hostname: 'srv-rotation' });
    const ref = x.db.prepare("SELECT ref FROM machines WHERE host = 'srv-rotation'").get().ref;
    assert.equal((await a.put(`/api/machines/${ref}/consoles`, { consoles: [{ type: 'vnc', target: '198.51.100.60:5900', label: 'KVM', vncpw: 'vnc-avant-rotation' }] })).status, 200);
    assert.equal((await a.put(`/api/machines/${ref}/redfish`, { url: carte.url, user: 'root', password: 'motdepasse-carte' })).status, 200);
    await epinglerRedfish(a, ref);
    const avant = x.db.prepare('SELECT consoles, rf_secret FROM machines WHERE ref = ?').get(ref);
    const lisibles = inst => {
      const m = inst.parc.machineParRef(ref);
      assert.equal(inst.parc.ouvrirVncPw(inst.parc.consolesEffectives(m)[0], ref), 'vnc-avant-rotation');
      assert.equal(inst.parc.redfishConf(m).password, 'motdepasse-carte');
    };
    await x.arreter();

    x = await lancer(dossier, { SOCLE_CLE: k2, SOCLE_CLE_ANCIENNE: k1 });
    const apres = x.db.prepare('SELECT consoles, rf_secret FROM machines WHERE ref = ?').get(ref);
    assert.notEqual(apres.rf_secret, avant.rf_secret, 'identifiant Redfish rescellé');
    assert.notEqual(apres.consoles, avant.consoles, 'mot de passe VNC rescellé');
    lisibles(x);
    const ingest = await new Client(x.port).req('POST', '/api/ingest', { hostname: 'srv-rotation', oskind: 'lin', cpu: 1, ram: 1, disk: 1 }, { entetes: { 'x-agent-token': jeton }, origine: null });
    assert.equal(ingest.status, 200, 'le jeton d\'agent, haché, ne dépend pas de la clé');
    await x.arreter();

    x = await lancer(dossier, { SOCLE_CLE: k2 });
    lisibles(x);
    // Un secret resté sous k1 (arrêt entre la rotation du socle et celle-ci) :
    // sans l'ancienne clé, le démarrage s'arrête au lieu de le perdre.
    x.db.prepare('UPDATE machines SET rf_secret = ? WHERE ref = ?').run(new Coffre({ cle: k1 }).scelle('redfish', 'motdepasse-carte', ref), ref);
    await x.arreter();
    x = null;
    await assert.rejects(lancer(dossier, { SOCLE_CLE: k2 }), /SOCLE_CLE_ANCIENNE/);
    x = await lancer(dossier, { SOCLE_CLE: k2, SOCLE_CLE_ANCIENNE: k1 });
    lisibles(x);
  } finally { await x?.arreter(); await carte.fermer(); }
});

test('garde de sortie : métadonnées et plages réservées refusées, en littéral comme à la résolution', async () => {
  assert.equal(hoteInterdit('169.254.169.254'), true);
  assert.equal(hoteInterdit('[fe80::1]'), true);
  assert.equal(hoteInterdit('198.51.100.7'), false);
  await assert.rejects(new Promise((res, rej) => lookupGarde('169.254.169.254', {}, (e, a) => (e ? rej(e) : res(a)))), /interdite/);
  const bon = await new Promise((res, rej) => lookupGarde('localhost', { all: true }, (e, a) => (e ? rej(e) : res(a))));
  assert.ok(bon.length >= 1);
  await enroler(membre, { hostname: 'srv-garde' });
  const mref = refMachineParHote('srv-garde');
  assert.equal((await admin.put(`/api/machines/${mref}/redfish`, { url: 'https://169.254.169.254/redfish', user: 'root', password: 'x' })).status, 422);
  await assert.rejects(observer('169.254.169.254', 443), /interdite/);
});

test('pont VNC de bout en bout : mise à niveau WebSocket sous session, mot de passe ouvert côté serveur', async () => {
  const rfb = await fauxRfb({ motDePasse: 'secret-bout' });
  try {
    await enroler(membre, { hostname: 'srv-vnc-ws' });
    const mref = refMachineParHote('srv-vnc-ws');
    assert.equal((await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'vnc', target: `127.0.0.1:${rfb.port}`, label: 'KVM', vncpw: 'secret-bout' }] })).status, 200);
    const origine = `http://127.0.0.1:${s.port}`;
    const cookies = c => [...c.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    await assert.rejects(connecter(`ws://127.0.0.1:${s.port}/vnc/${mref}/0`, { entetes: { Origin: origine, Cookie: cookies(lecteur) } }), /401/, 'lecture seule : refusé');
    const ws = await connecter(`ws://127.0.0.1:${s.port}/vnc/${mref}/0`, { entetes: { Origin: origine, Cookie: cookies(membre) } });
    const recus = [];
    ws.on('binaire', d => recus.push(Buffer.from(d)));
    const tout = () => Buffer.concat(recus).toString('latin1');
    await attendre(() => tout().startsWith('RFB 003.008\n'), 3000);
    ws.envoyerBinaire(Buffer.from('RFB 003.008\n'));
    await attendre(() => Buffer.concat(recus).length >= 14, 3000);
    ws.envoyerBinaire(Buffer.from([1]));
    assert.equal(await rfb.authOk, true, 'mot de passe VNC ouvert et utilisé côté serveur');
    await attendre(() => tout().includes('APRES-AUTH'), 3000);
    assert.ok(!tout().includes('secret-bout'), 'le mot de passe ne traverse jamais le WebSocket');
    ws.close();
  } finally { await rfb.fermer(); }
});

test('thème : la page porte la gamme posée par la page Thème du Hub ; SOMA hors Hub', async () => {
  assert.match((await s.client().get('/')).texte, /<html lang="fr" data-gamme="soma">/);
  const x = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-gamme-')), { SOCLE_THEME: 'console' });
  try { assert.match((await x.client().get('/')).texte, /data-gamme="console"/); } finally { await x.arreter(); }
  const lire = f => fs.readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
  assert.match(lire('deploy/compose.hub.yml'), /^ {6}SOCLE_THEME: "\{\{hub\.theme\}\}"$/m);
  assert.equal(JSON.parse(lire('hub.json')).minHubVersion, '0.7.0', '{{hub.theme}} vient avec le Hub 0.7.0');
});

test('comptes depuis le Hub : manifeste et Compose relient le jeton d’administration ; ni le jeton de service ni lui n’ouvrent l’autre côté', async () => {
  const lire = f => fs.readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
  const manifeste = JSON.parse(lire('hub.json'));
  assert.equal(manifeste.accounts.tokenKey, 'HUB_ADMIN_TOKEN');
  assert.equal(manifeste.accounts.invitation, true);
  assert.equal(manifeste.config.find(c => c.key === 'HUB_ADMIN_TOKEN').type, 'secret');
  assert.match(lire('deploy/compose.hub.yml'), /^ {6}SOCLE_JETON_ADMIN_HUB: "\{\{config\.HUB_ADMIN_TOKEN\}\}"$/m);
  const jeton = 'jeton-admin-hub-sentinel-' + 'b'.repeat(32);
  const x = await lancer(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-hub-')), { SOCLE_JETON_ADMIN_HUB: jeton });
  try {
    const c = x.client();
    const porteur = j => ({ entetes: { authorization: `Bearer ${j}` }, sansCsrf: true, origine: null });
    const r = await c.get('/api/compte/hub/comptes', porteur(jeton));
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json));
    assert.equal((await c.get('/api/compte/hub/comptes', porteur(JETON_HUB))).status, 401, 'le jeton de service n’administre pas les comptes');
    assert.notEqual((await c.get('/api/machines', porteur(jeton))).status, 200, 'le jeton d’administration n’ouvre pas l’API');
  } finally { await x.arreter(); }
});
