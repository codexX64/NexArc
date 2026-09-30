// Pont WebSocket ↔ TCP pour une console VNC intégrée (noVNC dans le navigateur,
// RFB brut vers le serveur VNC de la carte).
//
// La cible hôte:port n'est jamais prise du client : l'appelant résout un
// identifiant de console opaque en une cible côté serveur, si bien que le
// navigateur ne peut pas demander une adresse arbitraire (aucun SSRF par la
// console). Si un mot de passe est configuré, le pont répond lui-même au défi
// d'authentification VNC (DES du RFB) : le secret ne quitte jamais le serveur,
// et le navigateur voit un flux « None » déjà authentifié.
import net from 'node:net';
import crypto from 'node:crypto';
import { hoteInterdit, lookupGarde } from './reseau.js';

// DES du RFB : chaque octet de la clé a ses bits inversés, puis DES-ECB. On le
// réalise par 3DES à trois sous-clés égales (DES simple), sans remplissage.
function desRfb(cle8, bloc8) {
  const rk = Buffer.from([...cle8].map(b => parseInt([...b.toString(2).padStart(8, '0')].reverse().join(''), 2)));
  const c = crypto.createCipheriv('des-ede3-ecb', Buffer.concat([rk, rk, rk]), null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(bloc8), c.final()]);
}

function reponseVnc(motDePasse, defi16) {
  const pw = Buffer.alloc(8);
  Buffer.from(String(motDePasse), 'latin1').subarray(0, 8).copy(pw);
  return Buffer.concat([desRfb(pw, defi16.subarray(0, 8)), desRfb(pw, defi16.subarray(8, 16))]);
}

// Lecteur d'octets sur un flux poussé morceau par morceau : lire(n) attend n
// octets exactement ; reste() rend ce qui a déjà été reçu au-delà.
class Lecteur {
  constructor() { this.buf = Buffer.alloc(0); this.attente = null; this.fini = false; }
  pousser(d) { this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d; this._servir(); }
  finir() { this.fini = true; if (this.attente) { const a = this.attente; this.attente = null; a.rej(new Error('flux clos')); } }
  _servir() {
    if (this.attente && this.buf.length >= this.attente.n) {
      const { n, res } = this.attente; this.attente = null;
      const out = this.buf.subarray(0, n); this.buf = this.buf.subarray(n); res(out);
    }
  }
  lire(n) {
    return new Promise((res, rej) => {
      if (this.fini) return rej(new Error('flux clos'));
      this.attente = { n, res, rej }; this._servir();
    });
  }
  reste() { const r = this.buf; this.buf = Buffer.alloc(0); return r; }
}

async function authServeur(lecteur, tcp, motDePasse) {
  const version = await lecteur.lire(12);            // ex. « RFB 003.008\n »
  tcp.write(Buffer.from('RFB 003.008\n'));
  const [n] = await lecteur.lire(1);
  if (n === 0) throw new Error('le serveur VNC a refusé la connexion');
  const types = await lecteur.lire(n);
  if (types.includes(2)) {                            // authentification VNC
    tcp.write(Buffer.from([2]));
    const defi = await lecteur.lire(16);
    tcp.write(reponseVnc(motDePasse, defi));
    const res = (await lecteur.lire(4)).readUInt32BE(0);
    if (res !== 0) throw new Error('mot de passe VNC refusé');
  } else if (types.includes(1)) {                     // None
    tcp.write(Buffer.from([1]));
    if (version.toString('latin1') >= 'RFB 003.008') await lecteur.lire(4);
  } else {
    throw new Error('méthode d\'authentification VNC non supportée');
  }
}

export async function pont(ws, host, port, { motDePasse = '', connexionTimeout = 8000 } = {}) {
  if (hoteInterdit(host)) throw new Error('adresse interdite');
  const tcp = net.connect({ host, port, lookup: lookupGarde });
  const lecteurTcp = new Lecteur();
  const lecteurWs = new Lecteur();
  let raccorde = false, clos = false;

  const finir = () => { if (clos) return; clos = true; lecteurTcp.finir(); lecteurWs.finir(); try { tcp.destroy(); } catch { /* déjà fermé */ } try { ws.close(); } catch { /* idem */ } };
  tcp.setTimeout(connexionTimeout, () => { if (!raccorde) { tcp.destroy(); ws.fermerCode(1011, 'VNC injoignable'); } });
  tcp.on('data', d => { if (raccorde) ws.envoyerBinaire(d); else lecteurTcp.pousser(d); });
  tcp.on('close', finir);
  tcp.on('error', () => { if (!raccorde) ws.fermerCode(1011, 'VNC injoignable'); finir(); });
  // Un seul gestionnaire de fermeture, jamais réécrit : la socket TCP est
  // toujours détruite quand le navigateur part.
  ws.on('fermeture', finir);

  await new Promise((res, rej) => { tcp.once('connect', res); tcp.once('error', rej); }).catch(() => { ws.fermerCode(1011, 'VNC injoignable'); throw new Error('connexion VNC échouée'); });
  tcp.setTimeout(0);

  if (motDePasse) {
    // 1) authentifier vers le vrai serveur, côté serveur ;
    try { await authServeur(lecteurTcp, tcp, motDePasse); } catch (e) { ws.fermerCode(1011, String(e.message).slice(0, 100)); return finir(); }
    // 2) présenter au navigateur une poignée « None » : version, un seul type
    //    (None=1), SecurityResult = OK ; ensuite tout est relayé brut.
    ws.on('binaire', d => lecteurWs.pousser(d));
    try {
      ws.envoyerBinaire(Buffer.from('RFB 003.008\n'));
      await lecteurWs.lire(12);
      ws.envoyerBinaire(Buffer.from([1, 1]));
      await lecteurWs.lire(1);
      ws.envoyerBinaire(Buffer.from([0, 0, 0, 0]));
    } catch (e) { ws.fermerCode(1011, 'poignée navigateur interrompue'); return finir(); }
    // Bascule en relais : les octets déjà reçus des deux côtés sont écoulés.
    raccorde = true;
    const resteWs = lecteurWs.reste(); if (resteWs.length) tcp.write(resteWs);
    ws.on('binaire', d => tcp.write(d));
    const resteTcp = lecteurTcp.reste(); if (resteTcp.length) ws.envoyerBinaire(resteTcp);
  } else {
    // Sans mot de passe : le navigateur mène sa propre poignée avec le serveur.
    raccorde = true;
    ws.on('binaire', d => tcp.write(d));
    const resteTcp = lecteurTcp.reste(); if (resteTcp.length) ws.envoyerBinaire(resteTcp);
  }
}

export { reponseVnc, desRfb };
