// Redfish : alimentation native des cartes de gestion (iDRAC, iLO, IPMI/BMC).
//
// Redfish est exposé par toute carte moderne : Sentinel lit l'état
// d'alimentation et agit dessus sans ouvrir l'interface de la carte, et sans
// licence Enterprise (celle-ci ne verrouille que la console virtuelle, pas
// l'alimentation). Les identifiants sont scellés par le Coffre du socle, et ne
// partent qu'en HTTPS : le certificat auto-signé de la carte est épinglé (voir
// tls.js) et vérifié.
import https from 'node:https';
import { agentEpingle } from './tls.js';
import { hoteInterdit, lookupGarde } from './reseau.js';

// Valeurs ResetType exposées, dans l'ordre d'essai (les cartes en supportent un
// sous-ensemble).
export const ACTIONS = {
  on: ['On'],
  off: ['ForceOff'],
  arret: ['GracefulShutdown', 'ForceOff'],
  redemarrer: ['ForceRestart', 'GracefulRestart'],
  cycle: ['PowerCycle', 'ForceRestart'],
};
export const LIBELLES = { on: 'Allumer', off: 'Éteindre (forcé)', arret: 'Arrêter proprement', redemarrer: 'Redémarrer', cycle: 'Cycle d\'alimentation' };

function requete(base, chemin, { user, password, pin, methode = 'GET', corps = null, timeout = 20000 } = {}) {
  const u = new URL(base.replace(/\/+$/, '') + chemin);
  if (u.protocol !== 'https:') throw new Error('schéma refusé : HTTPS exigé');
  if (!pin) throw new Error('certificat non épinglé : confirme l\'empreinte de la carte');
  if (hoteInterdit(u.hostname)) throw new Error('adresse interdite');
  const entetes = { authorization: 'Basic ' + Buffer.from(`${user}:${password}`).toString('base64'), accept: 'application/json' };
  let data = null;
  if (corps) { data = JSON.stringify(corps); entetes['content-type'] = 'application/json'; entetes['content-length'] = Buffer.byteLength(data); }
  const opts = { method: methode, headers: entetes, timeout, lookup: lookupGarde, agent: agentEpingle(pin) };
  return new Promise((resolve, reject) => {
    const req = https.request(u, opts, res => {
      const morceaux = []; let taille = 0;
      res.on('data', c => { taille += c.length; if (taille > 512 * 1024) { req.destroy(new Error('réponse trop volumineuse')); } else morceaux.push(c); });
      res.on('end', () => {
        const texte = Buffer.concat(morceaux).toString('utf8');
        let json = null; try { json = JSON.parse(texte); } catch { /* pas du JSON */ }
        resolve({ status: res.statusCode, json, texte });
      });
    });
    req.on('timeout', () => req.destroy(new Error('délai dépassé')));
    req.on('error', reject);
    if (data) req.end(data); else req.end();
  });
}

async function premierSysteme(base, auth) {
  const r = await requete(base, '/redfish/v1/Systems', auth);
  if (r.status >= 400 || !r.json) throw new Error(`la carte répond ${r.status}`);
  const membres = r.json.Members || [];
  if (!membres.length) throw new Error('aucun système exposé');
  const chemin = membres[0]['@odata.id'];
  const s = await requete(base, chemin, auth);
  if (s.status >= 400 || !s.json) throw new Error(`système illisible (${s.status})`);
  return { chemin, sys: s.json };
}

export async function etat(base, auth) {
  const { sys } = await premierSysteme(base, auth);
  return {
    power: sys.PowerState || 'Unknown', model: sys.Model || sys.SKU || '', manufacturer: sys.Manufacturer || '',
    serial: sys.SerialNumber || '', bios: sys.BiosVersion || '',
    cpus: (sys.ProcessorSummary || {}).Count ?? null, memory_gib: (sys.MemorySummary || {}).TotalSystemMemoryGiB ?? null,
    health: (sys.Status || {}).Health ?? null, hostname: sys.HostName || '',
  };
}

export async function agir(base, auth, action) {
  if (!ACTIONS[action]) throw new Error('action inconnue');
  const { chemin, sys } = await premierSysteme(base, auth);
  const reset = ((sys.Actions || {})['#ComputerSystem.Reset']) || {};
  const cible = reset.target || `${chemin}/Actions/ComputerSystem.Reset`;
  const permis = reset['ResetType@Redfish.AllowableValues'] || [];
  const cheminReset = /^https?:\/\//i.test(cible) ? new URL(cible).pathname : cible;
  let dernier = null;
  for (const rt of ACTIONS[action]) {
    if (permis.length && !permis.includes(rt)) continue;
    const r = await requete(base, cheminReset, { ...auth, methode: 'POST', corps: { ResetType: rt } });
    if ([200, 202, 204].includes(r.status)) return rt;
    dernier = `${r.status} ${r.texte.slice(0, 120)}`;
  }
  throw new Error(dernier || 'aucun ResetType accepté par la carte');
}
