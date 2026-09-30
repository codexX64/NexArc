// Administration de Sentinel en ligne de commande, dans le conteneur :
//   docker exec <sentinel> node src/cli.js <commande>
//
// Chaque geste laisse sa trace au journal de sécurité, chaîné comme celui du
// service, qui tourne pendant ce temps : la base est en WAL, les deux écrivent
// sans se bloquer.
import { lireConfigSentinel } from './config.js';
import { ouvrirBase } from './base.js';
import { Agents } from './agents.js';
import { Journal } from '../socle/src/index.js';

const [, , cmd, ...rest] = process.argv;

function die(m) { console.error('erreur : ' + m); process.exit(1); }

function usage() {
  console.log(`Sentinel — administration

  agents lister
  agents revoquer <hôte>        le jeton de ce poste cesse aussitôt
  agents revoquer --tous        tout le parc (runbook d'incident)

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

switch (cmd) {
  case 'agents':
    if (rest[0] === 'lister') lister();
    else if (rest[0] === 'revoquer') revoquer(rest[1]);
    else usage();
    break;
  default: usage();
}
db.close();
