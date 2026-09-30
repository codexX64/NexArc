// Nœud MeshCentral : bâtit l'URL qui ouvre le bureau distant d'un poste.
//
// Sans clé de connexion, l'URL s'appuie sur la session MeshCentral de
// l'opérateur (déjà connecté à son Mesh). Avec une clé, on forge un jeton de
// connexion MeshCentral de courte durée pour ouvrir le bureau sans second
// login (compte de service Mesh SANS second facteur). Le format reprend
// encodeCookie de MeshCentral : AES-256-GCM, base64( iv(12) + tag(16) + chiffré ),
// puis « + »→« @ » et « / »→« $ » pour l'URL. AES-GCM est natif à node:crypto :
// aucune dépendance de chiffrement tierce.
import crypto from 'node:crypto';

// Les identifiants de nœud utilisent un alphabet restreint : refuser tout ce qui
// pourrait s'échapper de la chaîne de requête.
const INTERDITS = new Set([...' \t\r\n"\'<>&?#%']);

export function nodeValide(node) {
  return typeof node === 'string' && node.length > 0 && node.length <= 200 && ![...node].some(c => INTERDITS.has(c));
}

export function jetonConnexion(user, cleHex, ttl = 60) {
  const cle = Buffer.from(cleHex, 'hex').subarray(0, 32);
  if (cle.length !== 32) throw new Error('clé de connexion Mesh invalide (32 octets hex attendus)');
  const iv = crypto.randomBytes(12);
  const payload = Buffer.from(JSON.stringify({ a: 3, u: `user//${user.toLowerCase()}`, time: Math.floor(Date.now() / 1000) }));
  const c = crypto.createCipheriv('aes-256-gcm', cle, iv);
  const chiffre = Buffer.concat([c.update(payload), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([iv, tag, chiffre]).toString('base64').replace(/\+/g, '@').replace(/\//g, '$').replace(/=+$/, '');
}

export function urlBureau(node, { meshUrl, user = '', cle = '', viewmode = '11', hide = '' }) {
  if (!nodeValide(node)) throw new Error('nœud MeshCentral invalide');
  const params = [`gotonode=${node}`, `viewmode=${viewmode}`];
  if (hide) params.push(`hide=${hide}`);
  if (cle && user) params.unshift(`login=${encodeURIComponent(jetonConnexion(user, cle))}`);
  return `${meshUrl.replace(/\/+$/, '')}/?` + params.join('&');
}
