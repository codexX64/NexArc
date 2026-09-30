// Chargé par l'origine des consoles dans la page d'une carte de gestion, jamais
// par Sentinel. La carte croit parler à la racine de son serveur : ses appels
// construits à l'exécution (fetch, XMLHttpRequest, WebSocket) sont réancrés
// sous le préfixe de la passe, que le mandataire a posé dans data-prefixe.
(() => {
  const prefixe = String(document.currentScript?.dataset.prefixe || '').replace(/\/$/, '');
  if (!prefixe) return;
  const reancrer = u => {
    if (typeof u !== 'string' || u.startsWith(prefixe)) return u;
    if (u.startsWith('/') && !u.startsWith('//')) return prefixe + u;
    // Une adresse absolue vers la carte elle-même (son nom réel) revient ici.
    if (/^(wss?|https?):\/\//i.test(u)) {
      try {
        const a = new URL(u, location.href);
        if (a.host !== location.host) return prefixe + a.pathname + a.search;
      } catch { return u; } // adresse illisible : la carte la verra telle quelle
    }
    return u;
  };
  const fetchCarte = window.fetch;
  if (fetchCarte) {
    window.fetch = function (entree, options) {
      if (typeof entree === 'string') entree = reancrer(entree);
      else if (entree && entree.url) entree = new Request(reancrer(entree.url), entree);
      return fetchCarte.call(this, entree, options);
    };
  }
  const ouvrir = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (methode, adresse, ...reste) {
    return ouvrir.call(this, methode, reancrer(adresse), ...reste);
  };
  const WebSocketCarte = window.WebSocket;
  if (WebSocketCarte) {
    const Reancre = function (adresse, protocoles) {
      let u = reancrer(adresse);
      if (u.startsWith('/')) u = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + u;
      return protocoles ? new WebSocketCarte(u, protocoles) : new WebSocketCarte(u);
    };
    Reancre.prototype = WebSocketCarte.prototype;
    for (const k of ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED']) Reancre[k] = WebSocketCarte[k];
    window.WebSocket = Reancre;
  }
})();
