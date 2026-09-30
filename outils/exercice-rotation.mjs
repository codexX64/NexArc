// Exercice de rotation de bout en bout : Sentinel lancé comme en production
// (processus à part, clé maîtresse lue dans un fichier _FILE), un compte avec
// TOTP, clé d'accès et codes de secours, un agent enrôlé, une console VNC à mot
// de passe et une carte Redfish ; puis SOCLE_CLE tournée comme le dit le README,
// et tout ce qui existait revérifié par les vrais chemins (connexion, pont VNC,
// alimentation, remontée d'agent). Dure un peu plus de trente secondes (un pas
// TOTP).
//   node outils/exercice-rotation.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
const RACINE = path.resolve(import.meta.dirname, '..');
const { Client, connexion } = await import(`${RACINE}/socle/essai/client.js`);
const { Authentificateur } = await import(`${RACINE}/socle/essai/authentificateur.js`);
const totp = await import(`${RACINE}/socle/src/totp.js`);
const { connecter } = await import(`${RACINE}/src/websocket.js`);
const { fauxRfb, fauxRedfish } = await import(`${RACINE}/test/faux.js`);

const D = fs.mkdtempSync(path.join(os.tmpdir(), 'exercice-')), S = path.join(D, 'secrets');
fs.mkdirSync(S, { mode: 0o700 });
const PORT = 18000 + crypto.randomInt(1000), JETON = crypto.randomBytes(24).toString('base64url'), MDP = 'phrase de passe de l’exercice de rotation';
const cle = () => crypto.randomBytes(32).toString('base64');
const poser = (f, v) => fs.writeFileSync(path.join(S, f), v, { mode: 0o600 });
const lire = f => fs.readFileSync(path.join(S, f), 'utf8');
const rapport = [];
let proc, sortie = '';
const rfb = await fauxRfb({ motDePasse: 'vnc-de-l-exercice' });
const carte = await fauxRedfish({ utilisateur: 'root', motDePasse: 'redfish-de-l-exercice' });
const fin = async code => { try { proc?.kill('SIGKILL'); } catch { /* déjà arrêté */ } await rfb.fermer(); await carte.fermer(); fs.rmSync(D, { recursive: true, force: true }); process.exit(code); };
const note = async (ok, quoi) => { rapport.push(`${ok ? 'OK ' : 'ÉCHEC'} ${quoi}`); if (!ok) { console.log(rapport.join('\n')); console.log(sortie.slice(-2000)); await fin(1); } };
const jusqua = async (cond, ms = 4000) => { const t0 = Date.now(); while (!cond()) { if (Date.now() - t0 > ms) return false; await new Promise(r => setTimeout(r, 20)); } return true; };
const cookies = c => [...c.cookies].map(([k, v]) => `${k}=${v}`).join('; ');

poser('socle_cle', cle()); poser('socle_cle_ancienne', '');
async function demarrer() {
  sortie = '';
  proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/main.js'], { cwd: RACINE, env: {
    PATH: process.env.PATH, PORT: String(PORT), HOTE: '127.0.0.1', DATA_DIR: path.join(D, 'data'),
    SOCLE_CLE_FILE: path.join(S, 'socle_cle'), SOCLE_CLE_ANCIENNE_FILE: path.join(S, 'socle_cle_ancienne'),
    SOCLE_JETON_INSTALLATION: JETON,
  } });
  proc.stdout.on('data', d => { sortie += d; }); proc.stderr.on('data', d => { sortie += d; });
  const arret = new Promise(r => proc.on('exit', c => r({ code: c })));
  for (let i = 0; i < 100; i++) {
    const r = await Promise.race([fetch(`http://127.0.0.1:${PORT}/api/health`).then(x => x.status, () => 0), arret]);
    if (r === 200) return { code: null };
    if (typeof r === 'object') return r;
    await new Promise(r => setTimeout(r, 200));
  }
  return { code: 'délai' };
}
const arreter = () => new Promise(r => { proc.on('exit', r); proc.kill('SIGTERM'); });

// Le pont VNC ouvre la console avec le mot de passe scellé : s'il ne se
// déchiffre plus, le serveur RFB refuse l'authentification.
async function vncOuvre(client, ref) {
  const avant = rfb.reussites();
  let ws;
  try { ws = await connecter(`ws://127.0.0.1:${PORT}/vnc/${ref}/0`, { entetes: { Origin: `http://127.0.0.1:${PORT}`, Cookie: cookies(client) } }); } catch { return false; }
  const recus = [];
  ws.on('binaire', d => recus.push(Buffer.from(d)));
  const ok = await jusqua(() => Buffer.concat(recus).toString('latin1').startsWith('RFB 003.008\n'))
    && (ws.envoyerBinaire(Buffer.from('RFB 003.008\n')), await jusqua(() => Buffer.concat(recus).length >= 14))
    && (ws.envoyerBinaire(Buffer.from([1])), await jusqua(() => rfb.reussites() > avant));
  ws.close();
  return ok;
}
const alimentationLue = async (client, ref) => (await client.get(`/api/machines/${ref}/power`)).json?.power === 'On';
const agentRemonte = async jeton => (await new Client(PORT).req('POST', '/api/ingest', { hostname: 'serveur-a', ip: '198.51.100.12', oskind: 'lin', cpu: 3, ram: 20, disk: 30, av: 'à jour', fw: 'actif', enc: 'LUKS actif' }, { entetes: { 'x-agent-token': jeton }, origine: null })).status === 200
  && (await new Client(PORT).req('POST', '/api/agent/jobs', {}, { entetes: { 'x-agent-token': jeton }, origine: null })).status === 200;

await note((await demarrer()).code === null, 'démarrage sous la SOCLE_CLE initiale (lue dans un fichier)');
const a = new Client(PORT), auth = new Authentificateur();
await note((await a.post('/api/compte/installation', { jeton: JETON, identifiant: 'ana', motDePasse: MDP })).status === 200, 'installation du premier compte');
const secret = (await a.post('/api/compte/totp')).json.secret;
await note((await a.post('/api/compte/totp/confirmer', { code: totp.code(secret, totp.pasCourant(Date.now())) })).status === 200, 'TOTP inscrit');
const o = await a.post('/api/compte/cles/options');
await note((await a.post('/api/compte/cles', { reponse: auth.creer(o.json, a.origine), nom: 'Exercice' })).json?.niveau === 'complet', 'clé d’accès inscrite');
const codes = (await a.post('/api/compte/secours')).json.codes;
const info = (await a.post('/api/enroll/info', { site: 'Exercice' })).json;
const jetonAgent = (await new Client(PORT).post('/api/enroll/config', { code: info.code }, { origine: null })).json?.token;
await note(!!jetonAgent && await agentRemonte(jetonAgent), 'agent enrôlé : son jeton remonte et relève ses tâches');
const ref = (await a.get('/api/state')).json.machines.find(m => m.host === 'serveur-a')?.id;
await note((await a.put(`/api/machines/${ref}/consoles`, { consoles: [{ type: 'vnc', target: `127.0.0.1:${rfb.port}`, label: 'KVM', vncpw: 'vnc-de-l-exercice' }] })).status === 200, 'mot de passe VNC enregistré (scellé)');
await note((await a.put(`/api/machines/${ref}/redfish`, { url: carte.url, user: 'root', password: 'redfish-de-l-exercice' })).status === 200, 'identifiants Redfish enregistrés (scellés)');
const vu = (await a.get(`/api/machines/${ref}/pin?redfish=1`)).json;
await note((await a.post(`/api/machines/${ref}/pin`, { redfish: true, fp: vu?.fp })).status === 200, 'certificat de la carte Redfish épinglé');
await note(await vncOuvre(a, ref), 'pont VNC : la console s’ouvre avec le mot de passe scellé');
await note(await alimentationLue(a, ref), 'alimentation lue sur la carte Redfish');
await arreter();

poser('socle_cle_ancienne', lire('socle_cle')); poser('socle_cle', cle());
await note((await demarrer()).code === null, 'redémarrage avec la clé neuve et l’ancienne posée');
await note(/\[coffre\] Clé tournée : 1 secret\(s\) TOTP rescellé\(s\), 10 code\(s\) de secours/.test(sortie), 'socle : ' + (sortie.match(/\[coffre\] Clé tournée : [^.]*\./)?.[0] || 'aucune trace'));
await note(/\[coffre\] Secrets d'appareils rescellés sous SOCLE_CLE : 1 mot\(s\) de passe VNC, 1 identifiant\(s\) Redfish\./.test(sortie), 'Sentinel : ' + (sortie.match(/\[coffre\] Secrets d'appareils[^.]*\./)?.[0] || 'aucune trace'));
let c = new Client(PORT);
await note((await connexion(c, 'ana', MDP)).json?.etape === 'second', 'mot de passe accepté');
await new Promise(r => setTimeout(r, 31_000));
await note((await c.post('/api/compte/connexion/totp', { code: totp.code(secret, totp.pasCourant(Date.now())) })).json?.niveau === 'complet', 'TOTP inscrit avant la rotation accepté');
await note(await vncOuvre(c, ref), 'pont VNC : mot de passe rescellé, console ouverte');
await note(await alimentationLue(c, ref) && carte.refus() === 0, 'Redfish : identifiants rescellés, carte jointe sans refus');
await note(await agentRemonte(jetonAgent), 'jeton d’agent toujours valide (haché, indépendant de la clé)');
c = new Client(PORT); await connexion(c, 'ana', MDP);
await note((await c.post('/api/compte/connexion/secours', { code: codes[4] })).status === 200, 'code de secours d’avant la rotation accepté');
await arreter();

poser('socle_cle_ancienne', '');
await note((await demarrer()).code === null, 'redémarrage, ancienne clé retirée');
c = new Client(PORT);
const oc = await c.post('/api/compte/connexion/cle/options');
await note((await c.post('/api/compte/connexion/cle', { reponse: auth.signer(oc.json, c.origine) })).json?.niveau === 'complet', 'connexion par clé d’accès');
await note(await vncOuvre(c, ref) && await alimentationLue(c, ref), 'secrets d’appareils lisibles sous la seule clé neuve');
await note(await agentRemonte(jetonAgent), 'jeton d’agent toujours valide');
await arreter();

poser('socle_cle', cle());
const r = await demarrer();
await note(r.code !== null && /n’est pas la clé qui a écrit cette base/.test(sortie), 'clé inconnue : démarrage refusé');
console.log(`Exercice de rotation, ${new Date().toISOString()}\n${rapport.join('\n')}\n${rapport.length} vérifications réussies.`);
await fin(0);
