// TLS des cartes de gestion : jamais la vérification désactivée pour le trafic.
//
// Une carte iDRAC / iLO / JetKVM / BMC présente un certificat auto-signé. On
// l'épingle : l'empreinte SHA-256 et le certificat vus à l'enregistrement sont
// gardés, montrés à l'administrateur qui les confirme (confiance au premier
// usage). Toute connexion d'exploitation les revérifie — le certificat épinglé
// sert d'unique autorité (rejectUnauthorized reste vrai), et checkServerIdentity
// exige que la feuille soit exactement celle épinglée, sans se fier au nom.
//
// La seule connexion sans autorité est la sonde d'enregistrement, observer(),
// bornée par les trois garanties écrites au-dessus d'elle.
import tls from 'node:tls';
import https from 'node:https';
import net from 'node:net';
import { hoteInterdit, lookupGarde } from './reseau.js';

// Empreinte normalisée : 'sha256:aabb…' en minuscules, sans séparateurs. On
// retire d'abord une étiquette « sha256 » éventuelle : ses caractères hexa (a,
// 2, 5, 6) ne doivent pas se retrouver collés au condensat.
export function empreinte(certOuFp) {
  const brut = typeof certOuFp === 'string' ? certOuFp : (certOuFp?.fingerprint256 || '');
  const hex = String(brut).replace(/^\s*sha-?256\s*[:=]?\s*/i, '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return 'sha256:' + hex;
}

// Sonde de confiance au premier usage : lire le certificat auto-signé d'une
// carte pour que l'administrateur en confirme l'empreinte. Aucune autorité ne
// signe ce certificat, d'où l'absence de vérification sur CETTE connexion, et
// trois garanties qui la bornent :
//   1. Elle n'est atteignable que par une route admin + renfort récent
//      (GET et POST /api/machines/:ref/pin) : ni membre, ni lecture, ni Hub.
//   2. Elle n'envoie aucune donnée applicative : la poignée TLS se fait, rien
//      n'est écrit sur la socket, fermée dès la poignée finie (fin TLS
//      ordinaire, puis destruction au plus tard une seconde après).
//   3. Elle ne rend que l'empreinte SHA-256 et le sujet. Le certificat ne sert
//      qu'à l'épinglage, une fois l'empreinte montrée confirmée par l'admin (le
//      POST revérifie qu'elle n'a pas changé entre-temps).
// Les connexions d'exploitation, elles, exigent ce certificat (agentEpingle).
export function observer(host, port, { timeout = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    if (hoteInterdit(host)) return reject(new Error('adresse interdite'));
    const s = tls.connect({
      host, port, servername: net.isIP(host) ? undefined : host, lookup: lookupGarde, timeout,
      rejectUnauthorized: false, // sonde de confiance au premier usage : voir les trois garanties
    }, () => {
      const c = s.getPeerCertificate(false);
      // end() et non destroy() : la poignée se termine vraiment côté carte
      // (destroy() jetterait le dernier message de poignée), rien n'est écrit.
      s.end();
      setTimeout(() => s.destroy(), 1000).unref();
      if (!c || !c.raw) return reject(new Error('aucun certificat présenté'));
      resolve({ fp: empreinte(c), sujet: nomDe(c.subject), pem: derVersPem(c.raw) });
    });
    s.once('timeout', () => { s.destroy(); reject(new Error('délai dépassé')); });
    s.once('error', e => reject(e));
  });
}

// Agent HTTPS épinglé : le certificat épinglé est l'unique autorité, et la
// feuille présentée doit avoir exactement l'empreinte confirmée.
export function agentEpingle({ fp, pem }) {
  const attendue = empreinte(fp);
  return new https.Agent({
    ca: [pem],
    rejectUnauthorized: true,
    checkServerIdentity: (_hote, cert) => {
      if (empreinte(cert) !== attendue) return new Error('empreinte du certificat différente de celle épinglée');
      return undefined; // le nom n'est pas vérifié : l'empreinte épinglée EST l'identité
    },
  });
}

function derVersPem(raw) {
  const b64 = Buffer.from(raw).toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}
function nomDe(x) {
  if (!x || typeof x !== 'object') return '';
  return x.CN || x.O || Object.values(x).join(' ') || '';
}
