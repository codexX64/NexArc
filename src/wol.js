// Réveil par le réseau (Wake-on-LAN).
//
// Un paquet magique est 6×0xFF suivis de l'adresse MAC répétée 16 fois, en
// diffusion UDP. Une diffusion ne franchit pas les routeurs : un paquet émis
// par Sentinel n'atteint que son propre segment. Pour réveiller une machine
// d'un autre VLAN, Sentinel confie l'émission à un agent en ligne du même
// segment (tâche « wol »), qui diffuse localement.
import dgram from 'node:dgram';

const MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;

export function normaliserMac(mac) {
  const m = String(mac || '').trim();
  if (!MAC_RE.test(m)) return null;
  return m.replace(/-/g, ':').toLowerCase();
}

export function paquetMagique(mac) {
  const propre = String(mac).replace(/[:-]/g, '');
  if (propre.length !== 12 || !/^[0-9a-fA-F]{12}$/.test(propre)) throw new Error('adresse MAC invalide');
  const corps = Buffer.from(propre, 'hex');
  const pkt = Buffer.alloc(6 + 16 * 6, 0xff);
  for (let i = 0; i < 16; i++) corps.copy(pkt, 6 + i * 6);
  return pkt;
}

// /24 : approximation raisonnable du même segment L2 sur un réseau à plat.
export function sousReseau(ip) {
  const p = String(ip || '').split('.');
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255) ? p.slice(0, 3).join('.') : '';
}

// Diffusion dirigée : l'adresse de diffusion du /24 de la cible, calculée et
// validée (quatre octets décimaux) avant tout envoi.
export function diffusionDirigee(ip) {
  const sub = sousReseau(ip);
  return sub ? `${sub}.255` : '';
}

// Émission locale (seulement si le conteneur est sur le réseau de l'hôte).
export function emettre(mac, { diffusion = '255.255.255.255', ports = [9, 7] } = {}) {
  return new Promise((resolve, reject) => {
    const normalisee = normaliserMac(mac);
    if (!normalisee) return reject(new Error('adresse MAC invalide'));
    const pkt = paquetMagique(normalisee);
    const s = dgram.createSocket('udp4');
    s.once('error', e => { try { s.close(); } catch { /* déjà fermé */ } reject(e); });
    s.bind(() => {
      s.setBroadcast(true);
      let restants = ports.length;
      const fini = () => { if (--restants <= 0) { try { s.close(); } catch { /* déjà fermé */ } resolve(); } };
      for (const port of ports) s.send(pkt, port, diffusion, err => { if (err) { /* meilleur effort : un port de plus ne rate pas le réveil */ } fini(); });
    });
  });
}
