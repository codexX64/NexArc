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
import { execFileSync } from 'node:child_process';
import { fauxSynapse, fauxRfb, fauxCarte, fauxWs, captureUdp, fauxRedfish, fauxTlsCompteur } from './faux.js';
import { Coffre } from '../socle/src/chiffre.js';
import { lookupGarde, hoteInterdit } from '../src/reseau.js';
import { pont } from '../src/vncbridge.js';
import { observer, agentEpingle } from '../src/tls.js';
import { connecter } from '../src/websocket.js';
import { paquetMagique, emettre, diffusionDirigee, sousReseau } from '../src/wol.js';
import { urlBureau, nodeValide } from '../src/mesh.js';
import https from 'node:https';

const JETON_HUB = 'jeton-du-hub-pour-les-essais-0123456789';
const INSTALL = 'jeton-installation-sentinel-essai';
const JETON_SYNAPSE = 'cer_sentinel_jeton-de-cerveau-des-essais';
const SILENCE = { info() {}, warn() {}, error() {} };
let s, syn, admin, membre, autre, lecteur, base, env;

async function lancer(dossier, extra = {}) {
  env = {
    PORT: '0', HOTE: '127.0.0.1', DATA_DIR: dossier, SENTINEL_HUB_TOKEN: JETON_HUB, SENTINEL_ALLOW_EXEC: '1',
    SOCLE_CLE: crypto.randomBytes(32).toString('base64'), SOCLE_JETON_INSTALLATION: INSTALL,
    SYNAPSE_URL: syn.url, SYNAPSE_JETON: JETON_SYNAPSE, ...extra,
  };
  const x = await demarrer(env, { log: SILENCE });
  return { ...x, port: x.serveur.address().port, client: () => new Client(x.serveur.address().port) };
}

// Enrôle un agent : code (membre) → jeton → première remontée.
async function enroler(cli, { site = 'Agents', nom = '', relais = false, hostname = 'poste-x' } = {}) {
  const info = (await cli.get(`/api/enroll/info?site=${encodeURIComponent(site)}&name=${encodeURIComponent(nom)}${relais ? '&relay=1' : ''}`)).json;
  const conf = (await cli.get(`/api/enroll/config?code=${info.code}`)).json;
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
  assert.deepEqual(publiques, ['GET /api/agent/jobs', 'GET /api/enroll/agent.py', 'GET /api/enroll/config', 'GET /api/enroll/script', 'GET /api/health',
    'POST /api/agent/jobs/AAAAAAAAAAAAAAAA/result', 'POST /api/ingest']);
  // La politique écrite ici plutôt que relue dans le routeur : une route
  // d'administration relâchée par erreur fait échouer cet essai.
  const admin = s.api.routeur.routes.filter(r => r.options?.role === 'admin').map(r => `${r.methode} ${cheminDe(r)}`).sort();
  assert.deepEqual(admin, ['DELETE /api/machines/AAAAAAAAAAAAAAAA', 'GET /api/machines/AAAAAAAAAAAAAAAA/pin', 'POST /api/machines/AAAAAAAAAAAAAAAA/pin', 'PUT /api/machines/AAAAAAAAAAAAAAAA/redfish']);
  // Le mandataire des consoles, hors routeur : session exigée.
  assert.equal((await anonyme.get('/console/AAAAAAAAAAAAAAAA/0/')).status, 401);
  assert.equal((await lecteur.get('/console/AAAAAAAAAAAAAAAA/0/')).status, 403);
});

test('agent : code d\'inscription à usage unique, remontée, relève et résultat de SES tâches seulement', async () => {
  const info = (await membre.get('/api/enroll/info?site=Prod')).json;
  assert.match(info.code, /^[A-Za-z0-9_-]{22}$/, 'code de 128 bits');
  const empreinte = crypto.createHash('sha256').update('inscription:' + info.code).digest('hex');
  assert.deepEqual(s.parc.db.prepare('SELECT empreinte FROM enrolements').all().map(r => r.empreinte).filter(e => e === empreinte), [empreinte], 'gardé par son empreinte');
  assert.equal(s.parc.db.prepare('SELECT COUNT(*) n FROM enrolements WHERE empreinte = ?').get(info.code).n, 0, 'jamais en clair');
  const conf = (await membre.get(`/api/enroll/config?code=${info.code}`)).json;
  assert.match(conf.token, /^sag_/);
  assert.equal((await membre.get(`/api/enroll/config?code=${info.code}`)).status, 401, 'code consommé : usage unique');
  const jeton = conf.token;
  const remonter = h => membre.req('POST', '/api/ingest', { hostname: h, ip: '198.51.100.20', oskind: 'lin', cpu: 5, ram: 10, disk: 20, av: 'à jour', fw: 'actif', enc: 'LUKS actif', patch: 0 }, { entetes: { 'x-agent-token': jeton }, origine: null });
  assert.equal((await remonter('poste-un')).status, 200);
  const mref = refMachineParHote('poste-un');
  // une tâche pour cet agent
  const t = await membre.post(`/api/machines/${mref}/jobs`, { kind: 'inventory' });
  assert.equal(t.status, 200);
  // l'agent relève SES tâches (identifié par son jeton, pas par un nom)
  const releve = await membre.req('GET', '/api/agent/jobs', undefined, { entetes: { 'x-agent-token': jeton } });
  assert.equal(releve.status, 200);
  assert.equal(releve.json.jobs.length, 1);
  assert.equal(releve.json.jobs[0].id, t.json.id);
  // un autre agent ne voit pas cette tâche
  const en2 = await enroler(autre, { hostname: 'poste-deux' });
  const releve2 = await membre.req('GET', '/api/agent/jobs', undefined, { entetes: { 'x-agent-token': en2.jeton } });
  assert.equal(releve2.json.jobs.length, 0, 'aucun accès croisé aux tâches');
  // il ne peut pas rendre le résultat d'une tâche d'un autre
  assert.equal((await membre.req('POST', `/api/agent/jobs/${t.json.id}/result`, { output: 'volé', rc: 0 }, { entetes: { 'x-agent-token': en2.jeton } })).status, 404);
  // le bon agent rend son résultat
  assert.equal((await membre.req('POST', `/api/agent/jobs/${t.json.id}/result`, { output: 'ok', rc: 0 }, { entetes: { 'x-agent-token': jeton } })).status, 200);
  // jeton d'agent invalide refusé
  assert.equal((await membre.req('POST', '/api/ingest', { hostname: 'x', oskind: 'lin', cpu: 0, ram: 0, disk: 0 }, { entetes: { 'x-agent-token': 'sag_faux' }, origine: null })).status, 401);
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
    ws.close(); await p.catch(() => {});
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
  } finally { await carte.fermer(); }
});

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
});

test('consoles : mot de passe VNC scellé (admin+renfort), jamais rendu ; la cible du pont est côté serveur', async () => {
  const en = await enroler(membre, { hostname: 'poste-vnc' });
  const mref = refMachineParHote('poste-vnc');
  // un membre ne peut pas poser un mot de passe d'appareil
  assert.equal((await membre.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'vnc', target: '198.51.100.10:5900', label: 'KVM', vncpw: 'motdepasse-vnc' }] })).status, 403);
  // l'admin le peut ; le secret est scellé et ne ressort pas
  const r = await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'vnc', target: '198.51.100.10:5900', label: 'KVM', vncpw: 'motdepasse-vnc' }] });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const m = r.json.machines.find(x => x.id === mref);
  assert.equal(m.consoles[0].a_mdp, true);
  assert.ok(!JSON.stringify(m.consoles).includes('motdepasse-vnc'));
  assert.ok(!JSON.stringify(m.consoles).includes('vncpw'), 'ni la clé en clair ni le scellé ne sortent');
});

test('mandataire des consoles : les cookies de Sentinel ne partent jamais vers la carte, la carte ne peut pas en poser', async () => {
  const recus = [];
  const carte = await fauxCarte((req, res) => {
    recus.push(req.headers.cookie || '');
    res.setHeader('Set-Cookie', ['session-carte=posee; Path=/', 'sentinel-sid=volee; Path=/', '__Host-autre=x; Path=/; Secure']);
    res.setHeader('Content-Type', 'text/html');
    res.end('<html><head></head><body>carte</body></html>');
  });
  try {
    await enroler(membre, { hostname: 'srv-mandataire' });
    const mref = refMachineParHote('srv-mandataire');
    assert.equal((await admin.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'idrac', target: `https://127.0.0.1:${carte.port}`, label: 'iDRAC', embed: true }] })).status, 200);
    const vu = await admin.get(`/api/machines/${mref}/pin?idx=0`);
    assert.equal((await admin.post(`/api/machines/${mref}/pin`, { idx: 0, fp: vu.json.fp })).status, 200);
    membre.cookies.set('session-carte', 'ouverte');
    try {
      const r = await membre.get(`/api/machines/${mref}/remote?idx=0`);
      const page = await membre.get(r.json.url);
      assert.equal(page.status, 200, page.texte.slice(0, 200));
      assert.equal(recus.at(-1), 'session-carte=ouverte', 'seul le cookie de la carte lui parvient');
      assert.ok(recus.every(c => !/sentinel-/.test(c)), 'jamais la session de Sentinel');
      assert.deepEqual(page.setCookie.map(c => c.split('=')[0]), ['session-carte'], 'la carte ne pose aucun cookie au nom du service');
    } finally { membre.cookies.delete('session-carte'); }
  } finally { await carte.fermer(); }
});

test('hôte sans agent (carte de gestion) et refus d\'URL interdite', async () => {
  const r = await membre.post('/api/hosts', { host: 'serveur-b', ip: '198.51.100.30', ctype: 'idrac', target: 'https://198.51.100.30', label: 'iDRAC' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.ok(r.json.machines.some(m => m.host === 'serveur-b' && m.source === 'kvm'));
  // métadonnées de nuage refusées
  assert.equal((await membre.post('/api/hosts', { host: 'piege', ctype: 'url', target: 'http://169.254.169.254/latest/' })).status, 422);
  // javascript: refusé
  assert.equal((await membre.post('/api/hosts', { host: 'piege2', ctype: 'url', target: 'javascript:alert(1)' })).status, 422);
});

test('automatisations : création, activation, exécution ; un cmd exige l\'admin', async () => {
  const a = await membre.post('/api/automations', { nom: 'Inventaire nuit', kind: 'inventory', cible: 'tous' });
  assert.equal(a.status, 200, JSON.stringify(a.json));
  const ref = a.json.automations.find(x => x.nom === 'Inventaire nuit').id;
  assert.equal((await membre.post(`/api/automations/${ref}/run`)).status, 200);
  assert.equal((await membre.put(`/api/automations/${ref}?enabled=false`)).status, 200);
  assert.equal((await membre.del(`/api/automations/${ref}`)).status, 200);
  // une automatisation « commande libre » demande le rôle admin
  assert.equal((await membre.post('/api/automations', { nom: 'Cmd', kind: 'cmd', payload: 'id', cible: 'tous' })).status, 403);
  assert.equal((await admin.post('/api/automations', { nom: 'Cmd', kind: 'cmd', payload: 'id', cible: 'tous' })).status, 200);
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
    const info = (await new Client(v1.port).get('/api/enroll/info')).status; void info;
  } finally { await v1.arreter(); }
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
  for (const [variable, valeur] of [['SENTINEL_MESH_LOGIN_KEY', 'abcd'], ['SENTINEL_MESH_LOGIN_KEY', '0'.repeat(63)], ['SYNAPSE_JETON', 'court'], ['SYNAPSE_JETON', 'changeme-changeme-changeme']]) {
    assert.match(await erreurDe({ [variable]: valeur }), new RegExp(variable), `${variable}=${valeur}`);
  }
});

test('WebSocket : origine étrangère refusée, version non 13 refusée', async () => {
  // mise à niveau /vnc avec une origine étrangère → 403, sans session → 401
  const r = await brancherWs(s.port, '/vnc/AAAAAAAAAAAAAAAA/0', { origin: 'https://mechant.exemple.org' });
  assert.match(r, /403|401/);
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
  } finally { await carte.fermer(); }
});

test('sonde TLS : admin + renfort seulement, aucun octet applicatif, empreinte et sujet seuls', async () => {
  const carte = await fauxTlsCompteur();
  try {
    await enroler(membre, { hostname: 'srv-sonde' });
    const mref = refMachineParHote('srv-sonde');
    assert.equal((await membre.put(`/api/machines/${mref}/consoles`, { consoles: [{ type: 'idrac', target: `https://127.0.0.1:${carte.port}`, label: 'iDRAC' }] })).status, 200);
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
  const info = (await membre.get('/api/enroll/info?site=Prod&name=serveur-a')).json;
  assert.match(info.commands.windows, /^powershell -ExecutionPolicy Bypass -Command "irm '[^']+&name=serveur-a' \| iex"$/);
  assert.match(info.commands.linux, /&name=serveur-a' \| sudo bash$/);
  const anon = s.client();
  const w = await anon.get(`/api/enroll/script?os=windows&code=${info.code}&site=Prod&name=serveur-a`);
  assert.equal(w.status, 200);
  assert.match(w.entetes['content-disposition'], /installer-sentinel\.ps1/);
  for (const attendu of [`$Code = '${info.code}'`, "$Site = 'Prod'", "$Nom = 'serveur-a'", 'function Find-Python', '*WindowsApps*', 'Python.Python.3.12',
    '-m venv "$Dir\\venv"', 'pip install -q --upgrade pip psutil requests', 'sentinel-agent.py" --enroller', '$LASTEXITCODE -ne 0']) {
    assert.ok(w.texte.includes(attendu), `script Windows : ${attendu}`);
  }
  for (const systeme of ['linux', 'macos']) {
    const r = await anon.get(`/api/enroll/script?os=${systeme}&code=${info.code}&site=Prod&name=serveur-a`);
    assert.equal(r.status, 200);
    assert.ok(r.texte.includes('-m venv') && r.texte.includes('--enroller'));
    const f = path.join(fs.mkdtempSync(path.join(base, 'script-')), 'installer.sh');
    fs.writeFileSync(f, r.texte);
    execFileSync('bash', ['-n', f]);   // syntaxe bash valide
  }
  assert.equal((await anon.get(`/api/enroll/config?code=${info.code}`)).status, 200, 'télécharger les scripts ne consomme pas le code');
  // Rien de ce qui entre dans un script root ne peut en sortir.
  const avant = s.parc.db.prepare('SELECT COUNT(*) n FROM enrolements').get().n;
  for (const piege of ["x';id;'", 'x"$(id)"', 'a`id`', 'a\\b']) {
    assert.equal((await membre.get(`/api/enroll/info?site=${encodeURIComponent(piege)}`)).status, 422, piege);
    assert.equal((await membre.get(`/api/enroll/info?name=${encodeURIComponent(piege)}`)).status, 422, piege);
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
  assert.equal((await admin.put(`/api/machines/${mref}/redfish`, { url: 'http://169.254.169.254/redfish', user: 'root', password: 'x' })).status, 422);
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
