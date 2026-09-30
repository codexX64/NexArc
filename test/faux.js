// Faux serveurs pour les essais : SYNAPSE, un serveur RFB (VNC), une carte de
// gestion HTTPS auto-signée, une carte Redfish, un serveur TLS qui compte ce
// qu'il reçoit, un WebSocket simulé pour le pont, et une capture UDP pour le
// paquet magique. De vrais serveurs, avec les vrais protocoles.
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import { certificatEssai } from '../socle/essai/smtp.js';
import { reponseVnc } from '../src/vncbridge.js';

export async function fauxSynapse(jeton = 'cer_sentinel_essai') {
  const evenements = [];
  const s = http.createServer((req, res) => {
    let corps = ''; req.on('data', c => { corps += c; }); req.on('end', () => {
      if (req.headers.authorization !== `Bearer ${jeton}`) { res.writeHead(401); return res.end('{}'); }
      try { evenements.push(...(JSON.parse(corps).events || [])); } catch { /* ignore */ }
      res.end('{"ok":true}');
    });
  });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, evenements, fermer: () => new Promise(f => s.close(f)) };
}

// Serveur RFB 3.8. Avec mot de passe : exige l'authentification VNC et vérifie
// la réponse DES. La promesse `authOk` se résout à la première authentification
// réussie ; `reussites()` les compte toutes.
export async function fauxRfb({ motDePasse = '' } = {}) {
  let resoudreAuth, reussites = 0; const authOk = new Promise(r => { resoudreAuth = r; });
  const s = net.createServer(async sock => {
    const lu = [];
    let attente = null;
    sock.on('data', d => { lu.push(...d); servir(); });
    const lire = n => new Promise(res => { attente = { n, res }; servir(); });
    function servir() { if (attente && lu.length >= attente.n) { const { n, res } = attente; attente = null; res(Buffer.from(lu.splice(0, n))); } }
    try {
      sock.write(Buffer.from('RFB 003.008\n'));
      await lire(12);
      if (motDePasse) {
        sock.write(Buffer.from([1, 2]));            // un type : VNC auth (2)
        await lire(1);
        const defi = Buffer.alloc(16, 7);
        sock.write(defi);
        const reponse = await lire(16);
        const attendu = reponseVnc(motDePasse, defi);
        sock.write(Buffer.from([0, 0, 0, reponse.equals(attendu) ? 0 : 1]));
        if (reponse.equals(attendu)) { reussites++; resoudreAuth(true); sock.write(Buffer.from('APRES-AUTH')); }
      } else {
        sock.write(Buffer.from([1, 1]));            // None
        await lire(1);
        sock.write(Buffer.from([0, 0, 0, 0]));
        reussites++; resoudreAuth(true);
        sock.write(Buffer.from('APRES-NONE'));
      }
    } catch { /* connexion coupée */ }
  });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { host: '127.0.0.1', port: s.address().port, authOk, reussites: () => reussites, fermer: () => new Promise(f => s.close(f)) };
}

// Carte de gestion HTTPS auto-signée : sert `reponse` (HTML ou JSON) selon le chemin.
export async function fauxCarte(reponse = (req, res) => res.end('<html><head></head><body>carte</body></html>')) {
  const c = certificatEssai('carte-a');
  const s = https.createServer({ key: c.cle, cert: c.cert }, reponse);
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { host: '127.0.0.1', port: s.address().port, cert: c.cert, fermer: () => new Promise(f => s.close(f)) };
}

// WebSocket simulé côté navigateur, pour piloter pont() sans vraie socket.
export function fauxWs() {
  const envoyes = [];
  const gest = {};
  let ferme = false;
  return {
    envoyes, ferme: () => ferme,
    on(evt, fn) { gest[evt] = fn; return this; },
    envoyerBinaire(b) { envoyes.push(Buffer.from(b)); },
    envoyerTexte(t) { envoyes.push(Buffer.from(String(t))); },
    fermerCode() { ferme = true; gest.fermeture?.(); },
    close() { ferme = true; gest.fermeture?.(); },
    _pousser(b) { gest.binaire?.(Buffer.from(b)); },
  };
}

export async function captureUdp() {
  const paquets = [];
  const s = dgram.createSocket('udp4');
  s.on('message', m => paquets.push(Buffer.from(m)));
  await new Promise(r => s.bind(0, '127.0.0.1', r));
  return { port: s.address().port, paquets, fermer: () => new Promise(f => s.close(f)) };
}

// Carte Redfish en HTTP : exige ses identifiants (Basic), expose un système et
// son action Reset. `actions` garde les ResetType reçus, `refus` les accès sans
// les bons identifiants.
export async function fauxRedfish({ utilisateur = 'root', motDePasse = 'motdepasse-carte' } = {}) {
  const actions = [];
  let refus = 0;
  const attendu = 'Basic ' + Buffer.from(`${utilisateur}:${motDePasse}`).toString('base64');
  const systeme = '/redfish/v1/Systems/1', reset = `${systeme}/Actions/ComputerSystem.Reset`;
  const s = http.createServer((req, res) => {
    let corps = ''; req.on('data', c => { corps += c; }); req.on('end', () => {
      if (req.headers.authorization !== attendu) { refus++; res.writeHead(401); return res.end(); }
      const json = o => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.method === 'GET' && req.url === '/redfish/v1/Systems') return json({ Members: [{ '@odata.id': systeme }] });
      if (req.method === 'GET' && req.url === systeme) {
        return json({ PowerState: 'On', Model: 'Serveur A', Actions: { '#ComputerSystem.Reset': { target: reset, 'ResetType@Redfish.AllowableValues': ['On', 'ForceOff', 'GracefulShutdown', 'ForceRestart', 'PowerCycle'] } } });
      }
      if (req.method === 'POST' && req.url === reset) { actions.push(JSON.parse(corps).ResetType); res.writeHead(204); return res.end(); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, actions, refus: () => refus, fermer: () => new Promise(f => s.close(f)) };
}

// Serveur TLS auto-signé qui compte, par connexion, les octets applicatifs
// reçus après la poignée de main, et combien de temps le client est resté.
export async function fauxTlsCompteur() {
  const c = certificatEssai('carte-b');
  const connexions = [];
  const s = tls.createServer({ key: c.cle, cert: c.cert });
  s.on('connection', brut => {
    const x = { poignee: false, octets: 0, duree: null };
    const debut = Date.now();
    connexions.push(x);
    brut.on('close', () => { x.duree = Date.now() - debut; });
  });
  s.on('secureConnection', sock => {
    const x = connexions.at(-1);
    x.poignee = true;
    sock.on('data', d => { x.octets += d.length; });
    sock.on('error', () => { /* le client coupe sans politesse : attendu */ });
  });
  s.on('tlsClientError', () => { /* idem, pendant la poignée */ });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { host: '127.0.0.1', port: s.address().port, connexions, fermer: () => new Promise(f => s.close(f)) };
}
