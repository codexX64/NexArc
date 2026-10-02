// Consoles rattachées à une machine.
//
// Deux familles : « mesh » (un identifiant de nœud MeshCentral, l'URL est bâtie
// depuis le réglage du serveur) et les autres, une interface d'administration
// hors bande jointe par sa propre URL (iDRAC, iLO, JetKVM, IPMI, hyperviseur…).
// Seul http(s) est accepté : ces URL finissent dans un href ou une iframe.
import { classer } from './reseau.js';

// type → métadonnées. url : attend une URL (vs un nœud mesh). vnc : console VNC
// intégrée (hôte:port). screen/embed/power : ce que le type apporte. note : ce
// que l'opérateur doit savoir avant de choisir.
export const TYPES = {
  jetkvm: { label: 'JetKVM', url: true, screen: true, embed: true, power: false, recommande: true,
    note: 'Écran + BIOS sans licence, boîtier HDMI/USB. S\'intègre bien dans NEXARC.' },
  idrac: { label: 'Dell iDRAC', url: true, screen: 'licence', embed: 'partiel', power: true, recommande: false,
    note: 'Alimentation via Redfish (sans licence Enterprise). Écran : active le serveur VNC de l\'iDRAC puis ajoute une console « VNC intégrée ».' },
  ilo: { label: 'HPE iLO', url: true, screen: 'licence', embed: 'partiel', power: true, recommande: false,
    note: 'Alimentation via Redfish. Écran : avec iLO Advanced, active le serveur VNC et ajoute une console « VNC intégrée ».' },
  ipmi: { label: 'IPMI / BMC', url: true, screen: 'variable', embed: 'partiel', power: true, recommande: false,
    note: 'Dépend du constructeur. L\'alimentation passe par Redfish si la carte le supporte.' },
  hyperviseur: { label: 'Hyperviseur (VM)', url: true, screen: true, embed: true, power: false, recommande: false,
    note: 'Console noVNC des machines virtuelles, ouverte dans une iframe. Cible : l\'URL de l\'interface d\'administration de l\'hyperviseur.' },
  xcpng: { label: 'XCP-ng / XOA', url: true, screen: true, embed: true, power: false, recommande: false,
    note: 'Console des VM via Xen Orchestra.' },
  mesh: { label: 'MeshCentral', url: false, screen: true, embed: 'partiel', power: false, recommande: false,
    note: 'Bureau distant d\'un poste avec OS démarré — pas d\'accès BIOS.' },
  vnc: { label: 'Console VNC (intégrée)', url: false, vnc: true, screen: true, embed: true, power: false, recommande: true,
    note: 'Console plein écran dans NEXARC, sans Java. iDRAC/iLO VNC, hyperviseurs, tout KVM VNC. Cible : hôte:port (ex. 198.51.100.10:5900).' },
  url: { label: 'Interface web', url: true, screen: false, embed: 'partiel', power: false, recommande: false,
    note: 'Toute interface d\'administration web.' },
};

const MAX_CONSOLES = 8;

// hôte:port pour une cible VNC ; hôte = IP ou nom, port 1..65535.
function hostPortValide(cible) {
  if (typeof cible !== 'string' || !cible.includes(':')) return false;
  const i = cible.lastIndexOf(':');
  const host = cible.slice(0, i).trim(), port = cible.slice(i + 1);
  if (!host || host.length > 255 || host.includes('/') || host.includes(' ')) return false;
  const p = Number(port);
  return Number.isInteger(p) && p >= 1 && p <= 65535;
}

function urlValide(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (!u.host || String(url).length > 500) return false;
  if (u.username || u.password) return false;
  if ([...String(url)].some(ch => ch.charCodeAt(0) < 32)) return false;
  return true;
}

// L'hôte d'une cible ne doit jamais viser des métadonnées de nuage, un lien
// local ni une plage réservée — même saisi par un administrateur.
function hostDe(cible) {
  try {
    if (hostPortValide(cible)) return cible.slice(0, cible.lastIndexOf(':')).trim();
    return new URL(cible).hostname.replace(/^\[|\]$/g, '');
  } catch { return ''; }
}
export function cibleInterdite(cible) {
  const h = hostDe(cible);
  // Une adresse littérale interdite (métadonnées, lien local) est refusée tout
  // de suite ; un nom d'hôte est contrôlé à la résolution, à chaque connexion
  // (lookupGarde, dans reseau.js).
  return /^[0-9a-f:.]+$/i.test(h) && classer(h) === 'interdite';
}

function nettoyerLabel(label, ctype) {
  let l = String(label || '').trim().slice(0, 40);
  l = [...l].filter(ch => ch.charCodeAt(0) >= 32).join('');
  return l || TYPES[ctype]?.label || 'Console';
}

// Valide une liste de consoles. Lève une erreur au premier défaut. Les mots de
// passe VNC en clair restent sous la clé « vncpw » : la couche de stockage les
// scelle, ils ne repassent jamais tels quels.
export function normaliser(items, nodeValide) {
  if (!Array.isArray(items)) throw new Error('format invalide');
  if (items.length > MAX_CONSOLES) throw new Error(`${MAX_CONSOLES} accès maximum par machine`);
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== 'object') throw new Error('format invalide');
    const ctype = String(it.type || '').trim().toLowerCase();
    if (!TYPES[ctype]) throw new Error(`type inconnu : ${ctype}`);
    const cible = String(it.target || '').trim();
    if (TYPES[ctype].vnc) {
      if (!hostPortValide(cible)) throw new Error('cible VNC invalide (attendu hôte:port, ex. 198.51.100.10:5900)');
    } else if (TYPES[ctype].url) {
      if (!urlValide(cible)) throw new Error('URL invalide (http/https attendu)');
    } else if (!nodeValide(cible)) {
      throw new Error('nœud MeshCentral invalide');
    }
    if (TYPES[ctype].url && cibleInterdite(cible)) throw new Error('adresse interdite (métadonnées, lien local ou plage réservée)');
    const entree = { type: ctype, target: cible, label: nettoyerLabel(it.label, ctype), embed: !!it.embed };
    if (TYPES[ctype].vnc) {
      const pw = String(it.vncpw || '').slice(0, 64);
      if (pw) entree.vncpw = pw;   // scellé par la couche de stockage
      entree.embed = true;
    }
    out.push(entree);
  }
  return out;
}

export function typesPublics(meshActif) {
  return Object.entries(TYPES).filter(([k]) => k !== 'mesh' || meshActif).map(([id, v]) => ({
    id, label: v.label, url: !!v.url, vnc: !!v.vnc, screen: v.screen, embed: v.embed, power: !!v.power, recommande: v.recommande, note: v.note,
  })).sort((a, b) => (b.recommande - a.recommande) || a.label.localeCompare(b.label));
}
