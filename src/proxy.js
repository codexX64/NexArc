// Mandataire inverse des consoles web (iDRAC, iLO, JetKVM, IPMI…), servi par
// l'origine des consoles (origine-consoles.js), jamais par celle de Sentinel.
//
// Ces cartes envoient X-Frame-Options / CSP frame-ancestors : un navigateur
// refuse de les afficher dans Sentinel. Chaque requête arrive sous
// /c/{passe}/… , est transmise à la cible RÉSOLUE CÔTÉ SERVEUR (jamais fournie
// par le client), et la politique de cadrage de la carte est remplacée par la
// seule page de Sentinel qui a demandé la passe. Le certificat auto-signé de la
// carte est épinglé et vérifié.
import http from 'node:http';
import https from 'node:https';
import { agentEpingle } from './tls.js';
import { hoteInterdit, lookupGarde } from './reseau.js';

const STRIP_RESPONSE = new Set([
  'x-frame-options', 'content-security-policy', 'content-security-policy-report-only',
  'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'public-key-pins', 'strict-transport-security', 'set-cookie', 'location',
  'cache-control', 'x-content-type-options', 'referrer-policy',
]);
const STRIP_REQUEST = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate', 'cookie2', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade', 'accept-encoding',
]);

// Un navigateur ne distingue pas les cookies par port : servie sur le même hôte
// que Sentinel, l'origine des consoles reçoit les cookies de Sentinel (session,
// cérémonie). Ils ne partent jamais vers la carte, et la carte ne peut pas en
// poser un du même nom. Les préfixes __Host- et __Secure- sont réservés au
// service.
export const COOKIES_DU_SERVICE = /^(?:__Host-|__Secure-)?sentinel-|^__(?:Host|Secure)-/i;

export function cookiesPourLaCarte(entete) {
  const gardes = String(entete || '').split(';').map(c => c.trim()).filter(c => c && !COOKIES_DU_SERVICE.test(c.split('=')[0].trim()));
  return gardes.length ? gardes.join('; ') : null;
}

const RE_HEAD = /<head[^>]*>/i;
const RE_ABS = /\b(src|href|action|data-src)\s*=\s*(["'])\/(?!\/)/gi;

// Les liens absolus du balisage passent sous le préfixe ; ceux que la page
// construit à l'exécution, par le script de réancrage (web/reancrage.js), que
// l'origine des consoles sert elle-même. Le préfixe n'est fait que de
// caractères base64url : il entre tel quel dans l'attribut.
export function reecrireHtml(body, prefix) {
  const p = prefix.replace(/\/$/, '');
  let s = body.toString('utf8').replace(RE_ABS, (_m, a, q) => `${a}=${q}${p}/`);
  const tete = `<base href="${prefix}"><script src="/reancrage.js" data-prefixe="${prefix}"></script>`;
  const m = RE_HEAD.exec(s);
  return Buffer.from(m ? s.slice(0, m.index + m[0].length) + tete + s.slice(m.index + m[0].length) : tete + s, 'utf8');
}

export function reecrireSetCookie(valeur, prefix) {
  const parts = valeur.split(';').map(p => p.trim());
  const out = [parts[0]];
  let aPath = false;
  for (const p of parts.slice(1)) {
    const low = p.toLowerCase();
    if (low.startsWith('domain=') || low === 'secure') continue;
    if (low.startsWith('path=')) { aPath = true; const chemin = p.split('=', 2)[1] || '/'; out.push('Path=' + prefix.replace(/\/$/, '') + (chemin.startsWith('/') ? chemin : '/' + chemin)); continue; }
    if (low.startsWith('samesite=')) { out.push('SameSite=Lax'); continue; }
    out.push(p);
  }
  if (!aPath) out.push('Path=' + prefix);
  return out.join('; ');
}

export function reecrireLocation(valeur, amont, prefix) {
  if (valeur.startsWith(amont)) return prefix.replace(/\/$/, '') + valeur.slice(amont.length);
  if (valeur.startsWith('/')) return prefix.replace(/\/$/, '') + valeur;
  return valeur;
}

export function cibleAmont(base, chemin, query) {
  const url = base.replace(/\/+$/, '') + (chemin ? '/' + chemin : '/');
  return url + (query ? '?' + query : '');
}

// Transmet une requête HTTP vers la console. `pin` (certificat épinglé) est
// requis pour une cible https ; `parent`, l'origine de la page de Sentinel
// qui encadre la console.
export function mandaterHttp(req, res, { base, reste, prefix, pin, corps, parent }) {
  const cible = new URL(cibleAmont(base, reste || '', new URL(req.url, 'http://x').search.slice(1)));
  const secure = cible.protocol === 'https:';
  const entetes = {};
  for (const [k, v] of Object.entries(req.headers)) if (!STRIP_REQUEST.has(k.toLowerCase())) entetes[k] = v;
  delete entetes.cookie;
  const cookies = cookiesPourLaCarte(req.headers.cookie);
  if (cookies) entetes.cookie = cookies;
  entetes.host = cible.host;
  if (hoteInterdit(cible.hostname)) { res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end('{"error":"Adresse interdite."}'); }
  const opts = { method: req.method, headers: entetes, lookup: lookupGarde };
  if (secure) {
    if (!pin) { res.writeHead(409, { 'Content-Type': 'application/json' }); return res.end('{"error":"Certificat de la carte non épinglé : confirme son empreinte."}'); }
    opts.agent = agentEpingle(pin);
  }
  const mod = secure ? https : http;
  const amontBase = `${cible.protocol}//${cible.host}`;
  const up = mod.request(cible, opts, ru => {
    const sortie = {};
    const poses = [];
    for (const [k, v] of Object.entries(ru.headers)) {
      const low = k.toLowerCase();
      if (STRIP_RESPONSE.has(low)) {
        if (low === 'set-cookie') for (const c of [].concat(v)) if (!COOKIES_DU_SERVICE.test(c.split('=')[0].trim())) poses.push(reecrireSetCookie(c, prefix));
        if (low === 'location') sortie.Location = reecrireLocation([].concat(v)[0], amontBase, prefix);
        continue;
      }
      sortie[k] = v;
    }
    sortie['Content-Security-Policy'] = `frame-ancestors ${parent}`;
    sortie['Referrer-Policy'] = 'no-referrer';
    sortie['X-Content-Type-Options'] = 'nosniff';
    sortie['Cache-Control'] = 'no-store';
    const ctype = String(ru.headers['content-type'] || '');
    if (/text\/html/i.test(ctype)) {
      const morceaux = []; let taille = 0;
      ru.on('data', c => { taille += c.length; if (taille > 8 * 1024 * 1024) up.destroy(new Error('page trop volumineuse')); else morceaux.push(c); });
      ru.on('end', () => {
        const html = reecrireHtml(Buffer.concat(morceaux), prefix);
        sortie['Content-Length'] = Buffer.byteLength(html);
        if (poses.length) sortie['Set-Cookie'] = poses;
        res.writeHead(ru.statusCode, sortie);
        res.end(req.method === 'HEAD' ? undefined : html);
      });
    } else {
      if (poses.length) sortie['Set-Cookie'] = poses;
      res.writeHead(ru.statusCode, sortie);
      ru.pipe(res);
    }
  });
  up.on('error', () => { if (!res.headersSent) { res.writeHead(502, { 'Content-Type': 'application/json' }); res.end('{"error":"Console injoignable."}'); } });
  if (corps && corps.length) up.end(corps); else up.end();
}

export { STRIP_REQUEST, STRIP_RESPONSE };
