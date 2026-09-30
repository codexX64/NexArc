// Administration de Sentinel en ligne de commande, dans le conteneur :
//   docker exec <sentinel> node src/cli.js <commande>
//
// Chaque geste laisse sa trace au journal de sécurité, chaîné comme celui du
// service, qui tourne pendant ce temps : la base est en WAL, les deux écrivent
// sans se bloquer.
//
// La sauvegarde est chiffrée pour une clé publique dont la clé privée ne vit
// pas sur la machine de Sentinel : qui prend la machine ne relit pas les
// sauvegardes. Elle garde les secrets scellés sous SOCLE_CLE : sans une copie
// de cette clé, une base restaurée ne rouvre ni TOTP ni secrets d'appareils.
import fs from 'node:fs';
import { lireConfigSentinel, VERSION } from './config.js';
import { ouvrirBase } from './base.js';
import { Agents } from './agents.js';
import { Journal, sauvegarder, dechiffrer } from '../socle/src/index.js';

const [, , cmd, ...rest] = process.argv;

function die(m) { console.error('erreur : ' + m); process.exit(1); }

// Sur la machine qui garde la clé privée : aucune base, aucune configuration.
function restaurer(prive, cible) {
  if (!prive || !cible) die('usage : restaurer <clé-privée.pem> <cible.db> < sentinel.sauv');
  if (fs.existsSync(cible)) die(`${cible} existe déjà : la restauration écrit un fichier neuf`);
  let lu;
  try { lu = dechiffrer(fs.readFileSync(0), fs.readFileSync(prive, 'utf8')); } catch (e) { die(`sauvegarde illisible avec cette clé (${e.message})`); }
  if (lu.entete.service !== 'sentinel') die(`sauvegarde de ${lu.entete.service}, pas de Sentinel`);
  fs.writeFileSync(cible, lu.base, { mode: 0o600, flag: 'wx' });
  process.stderr.write(`Base de Sentinel ${lu.entete.version} du ${lu.entete.date} restaurée dans ${cible}.\n`);
}
if (cmd === 'restaurer') { restaurer(rest[0], rest[1]); process.exit(0); }

function usage() {
  console.log(`Sentinel — administration

  agents lister
  agents revoquer <hôte>        le jeton de ce poste cesse aussitôt
  agents revoquer --tous        tout le parc (runbook d'incident)
  sauvegarde < clé-publique.pem > sentinel.sauv
  restaurer <clé-privée.pem> <cible.db> < sentinel.sauv     (sur une autre machine)

Un agent révoqué se réinscrit avec un nouveau code d'inscription et retrouve sa
machine par son nom d'hôte. Les comptes humains se gèrent dans l'interface.`);
}

const db = ouvrirBase(lireConfigSentinel().donnees);
const journal = new Journal(db);
const trace = (action, objet, details) => journal.ecrire({ action, objet, details: { par: 'ligne de commande', ...details } });

function lister() {
  const lignes = db.prepare("SELECT host, site, jeton_hash IS NOT NULL AS jeton, last_report FROM machines WHERE source = 'agent' ORDER BY host").all();
  if (!lignes.length) return console.log('aucun agent');
  for (const l of lignes) {
    const vu = l.last_report ? new Date(l.last_report * 1000).toISOString().slice(0, 16).replace('T', ' ') : 'jamais';
    console.log(`${l.host.padEnd(32)} ${String(l.site).padEnd(16)} ${l.jeton ? 'jeton actif ' : 'sans jeton  '} ${vu}`);
  }
}

function revoquer(cible) {
  if (!cible) die('usage : agents revoquer <hôte> | --tous');
  const tous = cible === '--tous';
  const { machines, attente } = new Agents(db, {}).revoquer(tous ? { tous } : { hote: cible });
  if (!machines.length && !attente) die(tous ? 'aucun jeton d\'agent actif' : `aucun agent actif nommé « ${cible} »`);
  for (const m of machines) {
    trace('agent.jeton_revoque', m.host, { taches: m.taches });
    console.log(`${m.host} : jeton révoqué${m.taches ? `, ${m.taches} tâche(s) abandonnée(s)` : ''}`);
  }
  if (attente) {
    trace('agent.jetons_attente_revoques', null, { n: attente });
    console.log(`${attente} jeton(s) tiré(s) mais jamais présenté(s) : révoqué(s)`);
  }
}

// La clé publique arrive sur l'entrée, la sauvegarde part sur la sortie : rien
// de sensible n'est écrit dans le conteneur.
async function sauvegarde() {
  if (process.stdout.isTTY) die('redirige la sortie : node src/cli.js sauvegarde < sauvegarde.pub > sentinel.sauv');
  let sortie;
  try { sortie = await sauvegarder(db, fs.readFileSync(0, 'utf8'), { service: 'sentinel', version: VERSION }); } catch (e) { die(e.message); }
  trace('sauvegarde.faite', null, { octets: sortie.length });
  process.stdout.write(sortie);
}

switch (cmd) {
  case 'agents':
    if (rest[0] === 'lister') lister();
    else if (rest[0] === 'revoquer') revoquer(rest[1]);
    else usage();
    break;
  case 'sauvegarde': await sauvegarde(); break;
  default: usage();
}
db.close();
