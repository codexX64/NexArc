// Mandataire inverse des consoles intégrées (iDRAC, iLO, JetKVM, IPMI…).
//
// Ces cartes envoient X-Frame-Options / CSP frame-ancestors : un navigateur
// refuse de les afficher dans Sentinel. Pour les intégrer, on les sert depuis
// l'origine de Sentinel : chaque requête va sous /console/{ref}/{idx}/… , est
// transmise à la cible RÉSOLUE CÔTÉ SERVEUR (jamais fournie par le client), et
// les en-têtes de cadrage tombent au retour. Le certificat auto-signé de la
// carte est épinglé et vérifié (jamais rejectUnauthorized:false).
import http from 'node:http';
import https from 'node:https';
import { agentEpingle } from './tls.js';
import { hoteInterdit, lookupGarde } from './reseau.js';

const STRIP_RESPONSE = new Set([
  'x-frame-options', 'content-security-policy', 'content-security-policy-report-only',
  'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'public-key-pins', 'strict-transport-security', 'set-cookie', 'location',
]);
const STRIP_REQUEST = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate', 'cookie2', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade', 'accept-encoding',
]);

const RE_HEAD = /<head[^>]*>/i;
const RE_ABS = /\b(src|href|action|data-src)\s*=\s*(["'])\/(?!\/)/gi;

// Réancre fetch/XHR/WebSocket construits à l'exécution, sans toucher au code de
// la carte.
const SHIM = p => `<script>(function(){var P=${JSON.stringify(p)};function fix(u){try{if(typeof u!=="string")return u;if(u.indexOf(P)===0)return u;if(u.charAt(0)==="/"&&u.charAt(1)!=="/")return P.replace(/\\/$/,"")+u;if(/^(wss?|https?):\\/\\//i.test(u)){var a=document.createElement("a");a.href=u;if(a.host!==location.host)return P.replace(/\\/$/,"")+a.pathname+a.search;}return u;}catch(e){return u;}}var of=window.fetch;if(of)window.fetch=function(i,o){if(typeof i==="string")i=fix(i);else if(i&&i.url)i=new Request(fix(i.url),i);return of.call(this,i,o);};var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(u);return ox.apply(this,arguments);};var OW=window.WebSocket;if(OW){var NW=function(u,pr){u=fix(u);if(/^\\//.test(u))u=(location.protocol==="https:"?"wss://":"ws://")+location.host+u;return pr?new OW(u,pr):new OW(u);};NW.prototype=OW.prototype;["CONNECTING","OPEN","CLOSING","CLOSED"].forEach(function(k){NW[k]=OW[k];});window.WebSocket=NW;}})();</script>`;

export function reecrireHtml(body, prefix) {
  const p = prefix.replace(/\/$/, '');
  let s = body.toString('utf8').replace(RE_ABS, (_m, a, q) => `${a}=${q}${p}/`);
  const tete = `<base href="${prefix}">` + SHIM(prefix);
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
// requis pour une cible https.
export function mandaterHttp(req, res, { base, prefix, pin, corps }) {
  const cible = new URL(cibleAmont(base, req.params.reste || '', new URL(req.url, 'http://x').search.slice(1)));
  const secure = cible.protocol === 'https:';
  const entetes = {};
  for (const [k, v] of Object.entries(req.headers)) if (!STRIP_REQUEST.has(k.toLowerCase())) entetes[k] = v;
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
    const cookies = [];
    for (const [k, v] of Object.entries(ru.headers)) {
      const low = k.toLowerCase();
      if (STRIP_RESPONSE.has(low)) {
        if (low === 'set-cookie') for (const c of [].concat(v)) cookies.push(reecrireSetCookie(c, prefix));
        if (low === 'location') sortie.Location = reecrireLocation([].concat(v)[0], amontBase, prefix);
        continue;
      }
      sortie[k] = v;
    }
    sortie['X-Frame-Options'] = 'SAMEORIGIN';
    sortie['Content-Security-Policy'] = "frame-ancestors 'self'";
    sortie['Referrer-Policy'] = 'no-referrer';
    const ctype = String(ru.headers['content-type'] || '');
    if (/text\/html/i.test(ctype)) {
      const morceaux = []; let taille = 0;
      ru.on('data', c => { taille += c.length; if (taille > 8 * 1024 * 1024) up.destroy(new Error('page trop volumineuse')); else morceaux.push(c); });
      ru.on('end', () => {
        const html = reecrireHtml(Buffer.concat(morceaux), prefix);
        sortie['Content-Length'] = Buffer.byteLength(html);
        if (cookies.length) sortie['Set-Cookie'] = cookies;
        res.writeHead(ru.statusCode, sortie);
        res.end(req.method === 'HEAD' ? undefined : html);
      });
    } else {
      if (cookies.length) sortie['Set-Cookie'] = cookies;
      res.writeHead(ru.statusCode, sortie);
      ru.pipe(res);
    }
  });
  up.on('error', () => { if (!res.headersSent) { res.writeHead(502, { 'Content-Type': 'application/json' }); res.end('{"error":"Console injoignable."}'); } });
  if (corps && corps.length) up.end(corps); else up.end();
}

export { STRIP_REQUEST, STRIP_RESPONSE };
