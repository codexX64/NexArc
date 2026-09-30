// Exercice du runbook d'incident (README, « Sécurité » ; SECURITY.md,
// « Incident runbook ») sur une instance lancée comme en production : chaque
// geste de confinement et de reprise est joué par son vrai chemin, et son effet
// vérifié. Dure une trentaine de secondes.
//   node outils/exercice-incident.mjs
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
const RACINE = path.resolve(import.meta.dirname, '..');
const { Client, connexion } = await import(`${RACINE}/socle/essai/client.js`);
const { adminComplet, membreInvite, MDP_ESSAI } = await import(`${RACINE}/socle/essai/inscription.js`);

const D = fs.mkdtempSync(path.join(os.tmpdir(), 'exercice-incident-')), DONNEES = path.join(D, 'data');
const PORT = 19000 + crypto.randomInt(1000), JETON = crypto.randomBytes(24).toString('base64url');
const SOCLE_CLE = crypto.randomBytes(32).toString('base64');
const rapport = [];
let proc, sortie = '';
const fin = code => { try { proc?.kill('SIGKILL'); } catch { /* déjà arrêté */ } fs.rmSync(D, { recursive: true, force: true }); process.exit(code); };
const note = (ok, quoi) => { rapport.push(`${ok ? 'OK ' : 'ÉCHEC'} ${quoi}`); if (!ok) { console.log(rapport.join('\n')); console.log(sortie.slice(-2000)); fin(1); } };
const cli = (args, entree) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/cli.js', ...args], { cwd: RACINE, env: { PATH: process.env.PATH, DATA_DIR: DONNEES }, input: entree });

async function demarrer(env) {
  sortie = '';
  proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/main.js'], { cwd: RACINE, env: {
    PATH: process.env.PATH, PORT: String(PORT), HOTE: '127.0.0.1', DATA_DIR: DONNEES, SOCLE_CLE, SOCLE_JETON_INSTALLATION: JETON, ...env,
  } });
  proc.stdout.on('data', d => { sortie += d; }); proc.stderr.on('data', d => { sortie += d; });
  for (let i = 0; i < 100; i++) {
    if ((await fetch(`http://127.0.0.1:${PORT}/api/health`).then(x => x.status, () => 0)) === 200) return true;
    await new Promise(r => setTimeout(r, 200));
  }
  return false;
}
const arreter = () => new Promise(r => { proc.on('exit', r); proc.kill('SIGTERM'); });
const hub = jeton => ({ entetes: { authorization: `Bearer ${jeton}` }, origine: null });
const agent = jeton => ({ entetes: { 'x-agent-token': jeton }, origine: null });
const remontee = { hostname: 'serveur-a', ip: '198.51.100.12', oskind: 'lin', cpu: 3, ram: 20, disk: 30 };

const HUB1 = crypto.randomBytes(24).toString('base64url'), HUB2 = crypto.randomBytes(24).toString('base64url');
note(await demarrer({ SENTINEL_HUB_TOKEN: HUB1, SENTINEL_ALLOW_EXEC: '1' }), 'démarrage : commande libre permise, jeton du Hub n° 1');
const admin = new Client(PORT);
const { auth } = await adminComplet(admin, { jeton: JETON });
const { client: membre } = await membreInvite(admin, () => new Client(PORT), { identifiant: 'bruno' });
const info = (await membre.post('/api/enroll/info', { site: 'Exercice' })).json;
const jetonAgent = (await new Client(PORT).post('/api/enroll/config', { code: info.code }, { origine: null })).json.token;
note((await new Client(PORT).req('POST', '/api/ingest', remontee, agent(jetonAgent))).status === 200, 'un agent enrôlé remonte');
const ref = (await admin.get('/api/state')).json.machines.find(m => m.host === 'serveur-a').id;
const tache = (await admin.post(`/api/machines/${ref}/jobs`, { kind: 'cmd', payload: 'id' })).json.id;
note(!!tache, 'une commande libre attend l’agent');

// 1. Détecter
note((await membre.del(`/api/machines/${ref}`)).status === 403, 'un geste interdit est refusé');
const journal = (await admin.get('/api/compte/admin/journal')).json;
note(journal.lignes.some(l => l.action === 'acces.refuse') && journal.integrite.ok, 'détecter : le refus est au journal, chaîne intacte');
// 2. Fermer toutes les sessions sauf la sienne
note((await admin.post('/api/compte/admin/sessions/fermer-tout')).status === 200, 'toutes les sessions fermées');
note((await membre.get('/api/state')).status === 401 && (await admin.get('/api/state')).status === 200, 'la session du membre est morte, pas celle de l’administrateur');
// 3. Couper la commande libre, 4. couper le Hub
await arreter();
note(await demarrer({ SENTINEL_HUB_TOKEN: HUB2, SENTINEL_ALLOW_EXEC: '0' }), 'redéploiement : commande libre coupée, jeton du Hub n° 2');
note((await admin.post(`/api/machines/${ref}/jobs`, { kind: 'cmd', payload: 'id' })).status === 403, 'plus aucune commande libre créée');
note((await new Client(PORT).req('GET', '/api/summary', undefined, hub(HUB1))).status === 401 && (await new Client(PORT).req('GET', '/api/summary', undefined, hub(HUB2))).status === 200, 'l’ancien jeton du Hub ne vaut plus rien, le nouveau ouvre');
// 5. Révoquer les jetons d'agents
const revocation = cli(['agents', 'revoquer', '--tous']);
note(revocation.status === 0 && /serveur-a : jeton révoqué, 1 tâche\(s\) abandonnée\(s\)/.test(String(revocation.stdout)), 'tous les jetons d’agents révoqués, la commande due abandonnée');
note((await new Client(PORT).req('POST', '/api/ingest', remontee, agent(jetonAgent))).status === 401, 'l’agent révoqué est refusé');
// 6. Forcer un nouveau mot de passe
const comptes = (await admin.get('/api/compte/admin/comptes')).json.comptes;
const bruno = comptes.find(c => c.identifiant === 'bruno');
const reinit = await admin.post(`/api/compte/admin/comptes/${bruno.id}/reinit`);
note(reinit.status === 200, 'lien de réinitialisation émis pour le membre');
const nouveau = MDP_ESSAI + ' après incident';
note((await new Client(PORT).post('/api/compte/jeton', { usage: 'reinit', jeton: reinit.json.lien.split('#reinit=')[1], motDePasse: nouveau })).status === 200, 'le membre pose un nouveau mot de passe');
note((await connexion(new Client(PORT), 'bruno', MDP_ESSAI + ' bruno')).status === 401, 'l’ancien mot de passe ne vaut plus rien');
note((await connexion(new Client(PORT), 'bruno', nouveau)).json?.etape === 'second', 'le nouveau ouvre, et le second facteur reste exigé');
// 7. Restaurer depuis une sauvegarde
const paire = crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const sauv = cli(['sauvegarde'], paire.publicKey);
note(sauv.status === 0 && sauv.stdout.length > 0, 'sauvegarde chiffrée tirée pendant que le service tourne');
note((await admin.get('/api/compte/admin/journal')).json.lignes.some(l => l.action === 'sauvegarde.faite'), 'la sauvegarde est inscrite au journal');
await arreter();
const prive = path.join(D, 'prive.pem'), restauree = path.join(D, 'restauree.db');
fs.writeFileSync(prive, paire.privateKey);
note(cli(['restaurer', prive, restauree], sauv.stdout).status === 0, 'restaurée ailleurs avec la clé privée seule');
for (const f of ['sentinel.db', 'sentinel.db-wal', 'sentinel.db-shm']) fs.rmSync(path.join(DONNEES, f), { force: true });
fs.copyFileSync(restauree, path.join(DONNEES, 'sentinel.db'));
fs.chmodSync(path.join(DONNEES, 'sentinel.db'), 0o600);
note(await demarrer({ SENTINEL_HUB_TOKEN: HUB2 }), 'redémarrage sur la base restaurée');
const c = new Client(PORT);
const options = await c.post('/api/compte/connexion/cle/options');
note((await c.post('/api/compte/connexion/cle', { reponse: auth.signer(options.json, c.origine) })).json?.niveau === 'complet', 'l’administrateur se reconnecte avec sa clé d’accès');
note((await c.get('/api/state')).json.machines.some(m => m.host === 'serveur-a'), 'le parc est revenu');
// 8. Vérifier la chaîne du journal
const apres = (await c.get('/api/compte/admin/journal')).json;
note(apres.integrite.ok && ['sessions.toutes_fermees', 'agent.jeton_revoque', 'compte.reinit_emis'].every(a => apres.lignes.some(l => l.action === a)), 'base restaurée : chaîne du journal intacte, chaque geste d’avant la sauvegarde inscrit');
await arreter();
console.log(`Exercice du runbook d'incident, ${new Date().toISOString()}\n${rapport.join('\n')}\n${rapport.length} vérifications réussies.`);
fin(0);
