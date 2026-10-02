// Interface de Sentinel : parc, fiche d'une machine, tâches, automatisations,
// consoles, inscription, réglages. La porte du socle gère la connexion ; tout ce
// qui suit suppose une session complète, et le serveur revérifie chaque droit.
//
// Rien n'est injecté comme balisage : tout passe par h(), qui écrit du texte.
import {
  Api, porte, pageSecurite, pageComptes, h, icone, basculeTheme, appliquerTheme,
  toast, confirmer, dialogue, feuille, ajouterPictos,
} from '/socle/compte.js';

appliquerTheme();
const SERVICE = 'Sentinel';
const api = new Api({ surDeconnexion: () => location.reload() });
const etat = await porte({ api, service: SERVICE, sousTitre: 'supervision du parc' });
const moi = etat.session.compte;
const admin = moi.role === 'admin';
const peutAgir = moi.role !== 'lecture';

ajouterPictos({
  parc: '<rect x="3.5" y="4" width="17" height="6" rx="2"/><rect x="3.5" y="14" width="17" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  alerte2: '<path d="M6.5 10a5.5 5.5 0 0 1 11 0c0 4 1.6 5.6 1.6 5.6H4.9S6.5 14 6.5 10z"/><path d="M10.2 18.6a2 2 0 0 0 3.6 0"/>',
  correctif: '<path d="M20 11.4a8.2 8.2 0 1 0-1.9 6.2"/><path d="M20.5 5v5h-5"/>',
  eclair: '<path d="M13 3 5.5 13.5H11L10 21l7.5-10.5H12z"/>',
  reglages: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2.2"/><circle cx="7.5" cy="17" r="2.2"/>',
  jauge: '<circle cx="12" cy="12" r="8.4"/><path d="M12 7.4V12l3 1.8"/>',
  reveil: '<path d="M12 3v9M8 6a7 7 0 1 0 8 0"/>',
  ecran2: '<rect x="3" y="5" width="18" height="11" rx="2"/><path d="M7 20h10M12 16v4"/>',
  puce: '<rect x="6" y="6" width="12" height="12" rx="2.4"/><rect x="9.5" y="9.5" width="5" height="5" rx="1.2"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/>',
  disque: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="2.4"/>',
  memoire: '<rect x="3.5" y="7" width="17" height="10" rx="2"/><path d="M7 7V5M12 7V5M17 7V5"/>',
  terminal: '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M7 9l3 3-3 3M12.5 15h4"/>',
  reseau: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M12 11 6 17M12 11l6 6"/>',
  serveur: '<rect x="3.5" y="4" width="17" height="6" rx="1.8"/><rect x="3.5" y="14" width="17" height="6" rx="1.8"/><path d="M7 7h.01M7 17h.01"/>',
  play: '<path d="M7 5v14l11-7z"/>',
  retour: '<path d="M15 6l-6 6 6 6"/>',
});

const stage = h('div', { class: 'stage' });
const navs = {};
const PAGES = {
  over: { titre: 'Tableau de bord', ic: 'parc', groupe: 'Supervision', rendre: pageOverview },
  machines: { titre: 'Postes', ic: 'parc', groupe: 'Supervision', rendre: pageMachines },
  alertes: { titre: 'Alertes', ic: 'alerte2', groupe: 'Supervision', rendre: pageAlertes },
  correctifs: { titre: 'Correctifs', ic: 'correctif', groupe: 'Sécurité', rendre: pageCorrectifs },
  autos: { titre: 'Automatisations', ic: 'eclair', groupe: 'Sécurité', rendre: pageAutos },
  reglages: { titre: 'Réglages', ic: 'reglages', groupe: 'Système', rendre: pageReglages },
  securite: { titre: 'Sécurité', ic: 'cadenas', groupe: 'Système', rendre: () => pageSecurite(api, { service: SERVICE, confidentialite: '/confidentialite.txt' }) },
  ...(admin ? { comptes: { titre: 'Comptes', ic: 'utilisateurs', groupe: 'Système', rendre: () => pageComptes(api, { service: SERVICE }) } } : {}),
};

const E = { machines: [], alertes: [], patches: [], autos: [], feed: [], interval: 30, mesh: false, courante: null, filtre: 'all' };

function lien(k) {
  const p = PAGES[k];
  // aria-label stable : le badge de compteur ne doit pas polluer le nom du bouton.
  return (navs[k] = h('button', { class: 'nav', type: 'button', 'aria-label': p.titre, onclick: () => aller(k) }, icone(p.ic), h('span', { text: p.titre })));
}
function groupe(nom, cles) {
  const items = cles.filter(k => PAGES[k]);
  return items.length ? h('div', { class: 'grp' }, h('span', { text: nom }), items.map(lien)) : null;
}
const railOnline = h('b', { text: '—' });
const railBar = h('i');
const app = h('div', { class: 'app' },
  h('nav', { class: 'rail', 'aria-label': 'Navigation' },
    h('div', { class: 'mark' }, h('div', { class: 'g' }, icone('bouclier', 15)), h('b', { text: SERVICE }), h('i', { class: 'pulse' })),
    groupe('Supervision', ['over', 'machines', 'alertes']),
    groupe('Sécurité', ['correctifs', 'autos']),
    groupe('Système', ['reglages', 'securite', 'comptes']),
    h('div', { class: 'railcard' },
      h('div', { class: 'row' }, icone('jauge', 14), 'Postes joignables', railOnline),
      h('div', { class: 'bar' }, railBar),
      h('div', { class: 'row mt11' }, icone('utilisateurs', 14), h('span', { class: 'tronque', text: moi.identifiant })),
      h('button', { class: 'btn sm flat plein', type: 'button', onclick: async () => { await api.post('/api/compte/deconnexion'); location.reload(); } }, icone('sortie', 14), 'Se déconnecter'))),
  h('div', { class: 'voile-rail', onclick: () => app.classList.remove('menu-ouvert') }),
  h('main', { class: 'main' },
    h('header', { class: 'top' },
      h('button', { class: 'ghost menu', type: 'button', 'aria-label': 'Menu', onclick: () => app.classList.toggle('menu-ouvert') }, icone('menu')),
      h('div', { class: 'topright' }, basculeTheme(), h('div', { class: 'who', title: moi.identifiant, text: moi.identifiant.slice(0, 2).toUpperCase() }))),
    stage));
document.body.append(app);

async function aller(k, { ref } = {}) {
  // « detail » (la fiche d'une machine) n'est pas une page du rail : il ne
  // retombe pas sur le tableau de bord.
  if (k !== 'detail' && !PAGES[k]) k = 'over';
  for (const [n, b] of Object.entries(navs)) b.classList.toggle('on', n === (k === 'detail' ? 'machines' : k));
  app.classList.remove('menu-ouvert');
  if (k === 'detail') E.courante = ref;
  history.replaceState(null, '', '#' + k + (k === 'detail' && ref ? '/' + ref : ''));
  stage.replaceChildren(k === 'detail' ? await pageDetail(ref) : await PAGES[k].rendre());
  stage.scrollTop = 0;
}

async function rafraichir() {
  try { appliquerEtat(await api.get('/api/state')); } catch { /* 401 → porte */ }
}
function appliquerEtat(st) {
  if (!st) return;
  E.machines = st.machines; E.alertes = st.alertes; E.patches = st.patches; E.autos = st.autos; E.feed = st.feed;
  E.mesh = !!st.mesh_enabled; if (st.intervalle) E.interval = st.intervalle;
  const online = E.machines.filter(m => m.online).length, total = E.machines.filter(m => m.source === 'agent').length || 1;
  railOnline.textContent = `${online} / ${E.machines.filter(m => m.source === 'agent').length}`;
  railBar.style.width = Math.round(online / total * 100) + '%';
  for (const k of ['over', 'machines', 'alertes', 'correctifs']) if (navs[k]) majCompteur(k);
  // Re-rendu automatique seulement des vues sans saisie en cours (la liste des
  // postes garde son filtre et sa recherche ; la fiche, son onglet).
  const p = location.hash.slice(1).split('/')[0];
  if (['over', 'alertes', 'correctifs', 'autos'].includes(p)) aller(p, { ref: E.courante });
}
const alertesOuvertes = () => E.alertes.filter(a => a.etat !== 'resolue');
function majCompteur(k) {
  const n = { machines: E.machines.length, alertes: alertesOuvertes().length, correctifs: E.patches.length }[k];
  const b = navs[k]?.querySelector('.cnt');
  if (n === undefined) return;
  if (b) b.textContent = n; else navs[k].append(h('span', { class: 'cnt', text: String(n) }));
}

function osIcone(k) { return { srv: 'serveur', lin: 'terminal', mac: 'ecran2', hw: 'serveur' }[k] || 'ecran2'; }
function classeRisque(r) { return r >= 75 ? 'held' : r >= 45 ? 'warn' : ''; }
function tagEtat(m) {
  if (m.source === 'kvm') return h('span', { class: 'tag held' }, h('i', { class: 'd' }), 'matériel');
  if (!m.online) return h('span', { class: 'tag idle' }, h('i', { class: 'd' }), 'hors ligne');
  if (m.risk >= 75) return h('span', { class: 'tag warn' }, h('i', { class: 'd' }), 'en alerte');
  return h('span', { class: 'tag' }, h('i', { class: 'd' }), 'en ligne');
}
function ligneMachine(m, avecOs) {
  // La largeur de la barre est une donnée : posée en CSSOM (jamais en attribut
  // de style, que la politique de contenu interdirait).
  const jauge = h('i');
  jauge.style.width = `${m.risk}%`;
  const tr = h('tr', {},
    h('td', { class: 'principal' }, h('div', { class: 'who-cell' }, h('span', { class: 'itile ' + (m.risk >= 75 ? 'hot' : '') }, icone(osIcone(m.oskind))), h('div', {}, h('b', { text: m.host }), h('small', { text: m.ip })))),
    h('td', { class: 'cache-m dim', text: m.site }),
    avecOs ? h('td', { class: 'cache-l dim', text: m.os }) : null,
    avecOs ? h('td', { class: 'mono cache-l', text: m.online ? m.cpu + '%' : '—' }) : null,
    h('td', { class: 'cache-s' }, h('div', { class: 'risk ' + classeRisque(m.risk) }, h('div', { class: 'rail2' }, jauge), h('b', { text: String(m.risk) }))),
    h('td', {}, tagEtat(m)));
  tr.addEventListener('click', () => aller('detail', { ref: m.id }));
  return tr;
}

async function pageOverview() {
  const online = E.machines.filter(m => m.online);
  const agents = E.machines.filter(m => m.source === 'agent');
  const cpuMoy = online.length ? Math.round(online.reduce((s, m) => s + m.cpu, 0) / online.length) : 0;
  const critVuln = E.patches.filter(p => p.crit === 'Critique');
  const fig = (ic, tuile, lbl, val, delta) => h('div', { class: 'fig' }, h('div', { class: 'tile ' + tuile }, icone(ic)), h('span', { text: lbl }), h('strong', { text: val }), h('div', { class: 'delta', text: delta }));
  const watch = online.slice().sort((a, b) => b.risk - a.risk).slice(0, 5);
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Tableau de bord' }), h('p', { class: 'lede', text: `Parc de ${agents.length} poste${agents.length > 1 ? 's' : ''} supervisé${agents.length > 1 ? 's' : ''}. Collecte toutes les ${E.interval} s.` })),
      h('div', { class: 'actions' }, peutAgir ? h('button', { class: 'btn', type: 'button', onclick: async () => { try { appliquerEtat(await api.post('/api/collect')); toast('Collecte lancée.'); } catch (e) { toast(e.message, true); } } }, icone('correctif', 15), 'Lancer une collecte') : null,
        peutAgir ? h('button', { class: 'btn solid', type: 'button', onclick: () => dialogueInscription(false) }, icone('plus', 15), 'Ajouter un poste') : null)),
    h('div', { class: 'figs' },
      fig('jauge', '', 'Postes en ligne', `${online.length}`, `sur ${agents.length}`),
      fig('alerte2', 'warn', 'Alertes ouvertes', String(alertesOuvertes().length), alertesOuvertes().filter(a => a.sev === 'crit').length + ' critiques'),
      fig('bouclier', 'warn', 'Correctifs critiques', String(critVuln.length), critVuln.reduce((s, p) => s + p.c, 0) + ' postes'),
      fig('puce', '', 'Charge CPU moyenne', cpuMoy + ' %', 'postes en ligne')),
    h('div', { class: 'split' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'À surveiller' }), h('button', { class: 'btn sm flat', type: 'button', onclick: () => aller('machines') }, 'Tous les postes', icone('fleche', 14))),
        h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Poste' }), h('th', { class: 'cache-m', text: 'Site' }), h('th', { class: 'cache-s', text: 'Risque' }), h('th', { text: 'État' }))),
          h('tbody', {}, watch.length ? watch.map(m => ligneMachine(m, false)) : h('tr', {}, h('td', { colspan: 4, class: 'vide', text: 'Aucun poste en ligne.' })))))),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Activité récente' }), h('span', { class: 'note', text: 'flux temps réel' })), carteFeed())));
}

const feedBox = h('div', {});
function carteFeed() {
  peindreFeed();
  return feedBox;
}
function peindreFeed() {
  feedBox.replaceChildren(...(E.feed.length ? E.feed.map(ligneFeed) : [h('p', { class: 'vide', text: 'Rien pour l\'instant.' })]));
}
function ligneFeed(f) {
  // Texte simple, jamais d'innerHTML : le DOM se construit avec h().
  return h('div', { class: 'notice' }, h('span', { class: 'itile key' }, icone('jauge', 15)), h('div', {}, h('p', { text: f.html }), h('span', { class: 'when', text: `${f.ip || ''} · ${ageDe(f.cree)}` })));
}

async function pageMachines() {
  const filtres = [['all', 'Tous'], ['online', 'En ligne'], ['offline', 'Hors ligne'], ['warn', 'En alerte']];
  const chips = h('div', { class: 'views' });
  const corps = h('tbody', {});
  const compte = h('span', { class: 'grow dim' });
  const q = h('input', { class: 'field fld-sm', type: 'search', placeholder: 'Chercher un poste, une IP, un site' });
  const peindre = () => {
    let list = E.machines.slice();
    if (E.filtre === 'online') list = list.filter(m => m.online);
    else if (E.filtre === 'offline') list = list.filter(m => !m.online);
    else if (E.filtre === 'warn') list = list.filter(m => m.risk >= 75);
    const t = q.value.toLowerCase().trim();
    if (t) list = list.filter(m => m.host.toLowerCase().includes(t) || (m.ip || '').includes(t) || m.site.toLowerCase().includes(t));
    list.sort((a, b) => b.risk - a.risk);
    corps.replaceChildren(...(list.length ? list.map(m => ligneMachine(m, true)) : [h('tr', {}, h('td', { colspan: 6, class: 'vide', text: 'Aucun poste.' }))]));
    compte.textContent = `${list.length} poste${list.length > 1 ? 's' : ''}`;
  };
  chips.replaceChildren(...filtres.map(([k, l]) => h('button', { class: 'view' + (E.filtre === k ? ' on' : ''), type: 'button', text: l, onclick: () => { E.filtre = k; [...chips.children].forEach(c => c.classList.toggle('on', c.textContent === l)); peindre(); } })));
  q.addEventListener('input', peindre);
  peindre();
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Postes' }), h('p', { class: 'lede', text: 'Chaque poste exécute l\'agent Sentinel et remonte son état.' })),
      h('div', { class: 'actions' }, peutAgir ? h('button', { class: 'btn solid', type: 'button', onclick: () => dialogueInscription(false) }, icone('plus', 15), 'Ajouter un poste') : null)),
    h('div', { class: 'card' }, h('div', { class: 'pad rowline' }, chips, q, compte),
      h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Poste' }), h('th', { class: 'cache-m', text: 'Site' }), h('th', { class: 'cache-l', text: 'Système' }), h('th', { class: 'cache-l', text: 'CPU' }), h('th', { class: 'cache-s', text: 'Risque' }), h('th', { text: 'État' }))), corps))));
}

const LIBELLES_REGLES = {
  'hors-ligne': 'Hors ligne', antivirus: 'Antivirus', 'pare-feu': 'Pare-feu', chiffrement: 'Chiffrement',
  correctifs: 'Correctifs de sécurité', disque: 'Disque', risque: 'Score de risque',
};
function tagGravite(sev) {
  return h('span', { class: 'tag ' + (sev === 'crit' ? 'held' : sev === 'warn' ? 'warn' : '') }, h('i', { class: 'd' }), sev === 'crit' ? 'Critique' : sev === 'warn' ? 'Élevée' : 'Info');
}
function cellulePoste(a) {
  return a.machine ? h('div', { class: 'who-cell' }, h('span', { class: 'itile' }, icone(osIcone(a.machine.oskind))), h('div', {}, h('b', { text: a.machine.host }), h('small', { text: a.machine.ip }))) : h('span', { class: 'dim', text: 'parc' });
}
function dureeDe(s) {
  const m = Math.max(0, Math.round(s / 60));
  return m < 60 ? `${m} min` : m < 1440 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} j`;
}
async function pageAlertes() {
  const ouvertes = alertesOuvertes(), resolues = E.alertes.filter(a => a.etat === 'resolue');
  const acquitter = a => async () => { try { appliquerEtat(await api.post(`/api/alerts/${a.id}/ack`)); toast('Alerte prise en charge.'); } catch (e) { toast(e.message, true); } };
  const etatAck = a => a.acquittee
    ? h('span', { class: 'tag idle' }, h('i', { class: 'd' }), `prise en charge · ${a.acquitte_par || '—'}`)
    : (peutAgir ? h('button', { class: 'btn sm flat', type: 'button', onclick: acquitter(a) }, 'Acquitter') : h('span', { class: 'dim', text: '—' }));
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Alertes' }), h('p', { class: 'lede', text: 'Ouvertes par ce que les agents remontent ; résolues d\'elles-mêmes quand la cause disparaît. Acquitter signale qu\'un opérateur s\'en occupe.' }))),
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Ouvertes' }), h('span', { class: 'note', text: String(ouvertes.length) })),
      h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Gravité' }), h('th', { text: 'Alerte' }), h('th', { class: 'cache-m', text: 'Poste' }), h('th', { class: 'cache-s', text: 'Depuis' }), h('th', { class: 'fin', text: 'Suivi' }))),
        h('tbody', {}, ouvertes.length ? ouvertes.map(a => h('tr', {},
          h('td', {}, tagGravite(a.sev)),
          h('td', {}, h('div', {}, h('b', { class: 'fw5', text: LIBELLES_REGLES[a.regle] || 'Alerte' }), h('small', { class: 'dim bloc', text: a.txt }))),
          h('td', { class: 'cache-m' }, cellulePoste(a)),
          h('td', { class: 'mono cache-s', text: ageDe(a.cree) }),
          h('td', { class: 'fin' }, etatAck(a))))
          : h('tr', {}, h('td', { colspan: 5, class: 'vide', text: 'Aucune alerte ouverte.' })))))),
    h('div', { class: 'card mt14' }, h('header', {}, h('h2', { text: 'Résolues cette semaine' }), h('span', { class: 'note', text: String(resolues.length) })),
      h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Alerte' }), h('th', { class: 'cache-m', text: 'Poste' }), h('th', { text: 'Résolue' }), h('th', { class: 'cache-s', text: 'Durée' }))),
        h('tbody', {}, resolues.length ? resolues.map(a => h('tr', {},
          h('td', {}, h('div', {}, h('b', { class: 'fw5', text: LIBELLES_REGLES[a.regle] || 'Alerte' }), h('small', { class: 'dim bloc', text: a.txt }))),
          h('td', { class: 'cache-m' }, cellulePoste(a)),
          h('td', { class: 'mono', text: ageDe(a.resolue) }),
          h('td', { class: 'mono cache-s', text: dureeDe(a.resolue - a.cree) })))
          : h('tr', {}, h('td', { colspan: 4, class: 'vide', text: 'Rien de résolu ces sept derniers jours.' })))))));
}

async function pageCorrectifs() {
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Correctifs' }), h('p', { class: 'lede', text: 'Mises à jour système et applicatives en attente, agrégées sur le parc.' }))),
    h('div', { class: 'card' }, h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Mise à jour' }), h('th', { class: 'cache-m', text: 'Type' }), h('th', { text: 'Postes' }), h('th', { text: 'Criticité' }), peutAgir ? h('th', { class: 'fin' }) : null)),
      h('tbody', {}, E.patches.length ? E.patches.map(p => h('tr', {},
        h('td', {}, h('b', { class: 'fw5', text: p.n }), p.ver ? h('small', { class: 'mono', text: '→ ' + p.ver }) : null),
        h('td', { class: 'cache-m dim', text: p.t }),
        h('td', { class: 'mono', text: `${p.c} poste${p.c > 1 ? 's' : ''}` }),
        h('td', {}, h('span', { class: 'tag ' + (p.crit === 'Critique' ? 'held' : p.crit === 'Important' ? 'warn' : '') }, h('i', { class: 'd' }), p.crit)),
        peutAgir ? h('td', { class: 'fin' }, h('button', { class: 'btn sm', type: 'button', onclick: () => appliquerCorrectif(p.n) }, 'Appliquer')) : null))
        : h('tr', {}, h('td', { colspan: 5, class: 'vide', text: 'Aucun correctif en attente — les agents n\'ont encore rien remonté.' })))))));
}
async function appliquerCorrectif(pkg) {
  const cibles = E.machines.filter(m => m.source === 'agent' && m.updates_n > 0);
  if (!cibles.length) return toast('Aucun poste avec agent à mettre à jour.');
  if (!await confirmer(`Appliquer « ${pkg} » ?`, 'La mise à jour part sur les postes concernés.', { oui: 'Appliquer' })) return;
  let n = 0;
  for (const m of cibles) { try { await api.post(`/api/machines/${m.id}/jobs`, { kind: 'update', payload: pkg }); n++; } catch { /* on continue */ } }
  toast(n ? `Mise à jour envoyée sur ${n} poste(s).` : 'Envoi impossible.');
}

const AU_KIND = { update: 'Mises à jour', cmd: 'Commande', install: 'Installation', uninstall: 'Désinstallation', inventory: 'Inventaire' };
async function pageAutos() {
  const liste = h('div', {});
  const peindre = () => {
    liste.replaceChildren(...(E.autos.length ? E.autos.map(ligneAuto) : [h('p', { class: 'vide', text: 'Aucune automatisation.' })]));
  };
  peindre();
  const form = admin || peutAgir ? boutonNouvelleAuto(peindre) : null;
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Automatisations' }), h('p', { class: 'lede', text: 'Tâches récurrentes exécutées par les agents : mises à jour, inventaire, commandes.' })),
      h('div', { class: 'actions' }, form)),
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Automatisations actives' }), h('span', { class: 'note', text: `${E.autos.filter(a => a.actif).length} / ${E.autos.length}` })), liste));
}
function ligneAuto(a) {
  // Une commande libre répétée, comme toute suppression, reste à l'administrateur.
  const pilotable = admin || a.kind !== 'cmd';
  const acts = [
    ...(pilotable ? [
      { texte: 'Lancer', agir: async () => { const r = await api.post(`/api/automations/${a.id}/run`); toast(`${r.queued} tâche(s) envoyée(s).`); } },
      { texte: a.actif ? 'Suspendre' : 'Activer', agir: async () => { E.autos = (await api.put(`/api/automations/${a.id}?enabled=${a.actif ? 'false' : 'true'}`)).automations; aller('autos'); } },
    ] : []),
    ...(admin ? [{ texte: 'Supprimer', danger: true, agir: async () => { if (await confirmer('Supprimer ?', 'Cette automatisation ne s\'exécutera plus.', { danger: true, oui: 'Supprimer' })) { E.autos = (await api.del(`/api/automations/${a.id}`)).automations; aller('autos'); } } }] : []),
  ];
  const sur = fn => async () => { try { await fn(); } catch (e) { toast(e.message, true); } };
  return h('div', { class: 'flowrow' },
    h('span', { class: 'itile ' + (a.actif ? 'key' : '') }, icone('eclair')),
    h('div', {}, h('strong', { text: a.nom }), h('small', { text: `${AU_KIND[a.kind] || a.kind}${a.payload ? ' · ' + a.payload.slice(0, 40) : ''} · ${cibleTexte(a)} · ${rythmeTexte(a)}` })),
    h('div', { class: 'fin' },
      peutAgir && acts.length ? acts.map(x => h('button', { class: 'btn sm flat cache-s' + (x.danger ? ' danger' : ''), type: 'button', onclick: sur(x.agir), text: x.texte })) : h('span', { class: 'mono dim', text: a.runs ? `${a.dernier_statut} · ${a.runs}×` : 'jamais' }),
      peutAgir && acts.length ? h('button', { class: 'btn sm flat seul-s', type: 'button', 'aria-label': 'Actions', onclick: sur(() => feuille(a.nom, acts)) }, icone('actions', 16)) : null));
}
function cibleTexte(a) { return { tous: 'tous les postes', site: 'site ' + a.cible_val, oskind: 'systèmes ' + a.cible_val, host: 'poste ' + a.cible_val }[a.cible] || a.cible; }
function rythmeTexte(a) { const h2 = a.toutes_h; const base = h2 < 24 ? (h2 === 1 ? 'toutes les heures' : `toutes les ${h2} h`) : h2 === 24 ? 'chaque jour' : h2 === 168 ? 'chaque semaine' : `toutes les ${Math.round(h2 / 24)} j`; return base + (h2 >= 24 ? ` à ${String(a.heure).padStart(2, '0')}h` : ''); }
function boutonNouvelleAuto(peindre) {
  return h('button', { class: 'btn solid', type: 'button', onclick: async () => {
    const nom = h('input', { class: 'field', maxlength: 60, placeholder: 'Nom (ex. Mises à jour de sécurité)' });
    const kind = h('select', { class: 'field' }, Object.entries(AU_KIND).filter(([v]) => admin || v !== 'cmd').map(([v, t]) => h('option', { value: v, text: t })));
    const payload = h('input', { class: 'field', placeholder: 'Commande ou paquet (vide = toutes les mises à jour)' });
    const cible = h('select', { class: 'field' }, [['tous', 'Tous les postes'], ['site', 'Un site'], ['oskind', 'Un système'], ['host', 'Un poste']].map(([v, t]) => h('option', { value: v, text: t })));
    const cibleVal = h('input', { class: 'field hide', placeholder: 'Valeur (site / lin / nom du poste)' });
    cible.addEventListener('change', () => { cibleVal.style.display = cible.value === 'tous' ? 'none' : 'block'; });
    const toutes = h('select', { class: 'field' }, [[1, 'Toutes les heures'], [6, 'Toutes les 6 h'], [24, 'Chaque jour'], [168, 'Chaque semaine']].map(([v, t]) => h('option', { value: v, text: t, selected: v === 24 })));
    const heure = h('select', { class: 'field' }, Array.from({ length: 24 }, (_, i) => h('option', { value: i, text: `à ${String(i).padStart(2, '0')}h`, selected: i === 2 })));
    const err = h('p', { class: 'erreur', role: 'alert' });
    const ok = await dialogue({ titre: 'Nouvelle automatisation', large: true,
      contenu: [nom, h('div', { class: 'row2 mt9' }, kind, payload), h('div', { class: 'row2 mt9' }, cible, cibleVal), h('div', { class: 'row2 mt9' }, toutes, heure), err],
      boutons: [{ texte: 'Annuler', classe: 'flat', valeur: false }, { texte: 'Créer', classe: 'solid', agir: async () => {
        const corps = { nom: nom.value.trim(), kind: kind.value, payload: payload.value.trim(), cible: cible.value, cible_val: cibleVal.value.trim(), toutes_h: Number(toutes.value), heure: Number(heure.value) };
        if (!corps.nom) { err.textContent = 'Donne un nom.'; return false; }
        try { E.autos = (await api.post('/api/automations', corps)).automations; return true; } catch (e) { err.textContent = e.message; return false; }
      } }] });
    if (ok) { peindre(); toast('Automatisation créée.'); }
  } }, icone('plus', 15), 'Nouvelle automatisation');
}

async function pageReglages() {
  let s, cov;
  try { s = await api.get('/api/settings'); } catch (e) { return h('div', { class: 'page' }, h('p', { class: 'erreur', text: e.message })); }
  try { cov = (await api.get('/api/relays')).coverage; } catch { cov = []; }
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', { text: k }), h('b', { text: v }));
  const couverture = h('div', { class: 'cardbody' });
  if (!cov.length) couverture.append(h('p', { class: 'hint', text: 'Aucun agent : la couverture apparaîtra dès qu\'un poste remonte.' }));
  else {
    couverture.append(h('p', { class: 'hint mb12', text: 'Un réveil n\'atteint que les machines du même sous-réseau qu\'un émetteur en ligne. Un nœud relais dédié garantit la couverture d\'un VLAN.' }));
    for (const c of cov) {
      const relais = c.relays.filter(r => r.online).map(r => r.host);
      const dispo = relais.length ? `relais ${relais.join(', ')}` : (c.covered ? `${c.online_emitters} postes en ligne` : '—');
      couverture.append(h('div', { class: 'kv' }, h('span', { text: c.subnet + '.x' }), h('b', {}, h('span', { class: 'tag ' + (c.covered ? '' : 'held') }, h('i', { class: 'd' }), c.covered ? 'couvert' : 'non couvert'), h('span', { class: 'mldim', text: dispo }))));
    }
    if (peutAgir) couverture.append(h('div', { class: 'pad pt12' }, h('button', { class: 'btn plein', type: 'button', onclick: () => dialogueInscription(true) }, icone('reveil', 15), 'Ajouter un nœud relais')));
  }
  return h('div', { class: 'page' },
    h('div', { class: 'headrow' }, h('div', {}, h('h1', { class: 'title', text: 'Réglages' }), h('p', { class: 'lede', text: 'Configuration de cette instance. Le compte et la sécurité sont dans la page Sécurité.' }))),
    h('div', { class: 'grille' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Supervision' })), h('div', { class: 'cardbody' }, kv('Intervalle de collecte', s.collect_interval + ' s'), kv('Hors ligne après', s.offline_after + ' s'), kv('Agents réels enrôlés', String(s.real_agents)), kv('Commande libre', s.exec ? 'activée' : 'désactivée'))),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Seuils des alertes' }), h('span', { class: 'note', text: 'SENTINEL_ALERT_*' })), h('div', { class: 'cardbody' },
        kv('Hors ligne au-delà de', s.alertes.hors_ligne_min + ' min'), kv('Correctifs de sécurité en attente', 'plus de ' + s.alertes.correctifs_jours + ' j'),
        kv('Disque rempli à', s.alertes.disque_pct + ' %'), kv('Score de risque', s.alertes.risque + ' / 100'))),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Réveil réseau (Wake-on-LAN)' }), h('span', { class: 'note', text: 'couverture par sous-réseau' })), couverture),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Prise en main à distance' })), h('div', { class: 'cardbody' }, kv('MeshCentral', s.mesh.enabled ? 'activé' : 'désactivé'), kv('Serveur', s.mesh.url || '—'), kv('Ouverture', s.mesh.enabled ? (s.mesh.embed ? 'intégrée' : 'nouvel onglet') : '—'), kv('Auto-login', s.mesh.autologin ? 'configuré' : 'non configuré'))),
      peutAgir ? h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Enrôler un poste' })), h('div', { class: 'cardbody' }, h('p', { class: 'hint mt0', text: 'Un code d\'inscription à usage unique génère la commande d\'installation.' }), h('button', { class: 'btn solid', type: 'button', onclick: () => dialogueInscription(false) }, icone('plus', 15), 'Générer une commande'))) : null));
}

async function pageDetail(ref) {
  const m = E.machines.find(x => x.id === ref);
  if (!m) { setTimeout(() => aller('machines'), 0); return h('div', { class: 'page' }, h('p', { class: 'vide', text: 'Poste introuvable.' })); }
  const spark = id => h('svg', { class: 'spark', id, viewBox: '0 0 260 38', preserveAspectRatio: 'none' });
  const cpuS = spark('s-cpu'), ramS = spark('s-ram'), diskS = spark('s-disk');
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', { class: 'k', text: k }), h('span', { class: 'v', text: v }));
  const isAgent = m.source === 'agent';
  const onglets = ['info', ...(m.inventory ? ['comp'] : []), ...(isAgent ? ['soft', 'term'] : [])];
  const paneInfo = h('div', { class: 'dtpane' },
    h('div', { class: 'grille' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Informations système' })), h('div', { class: 'cardbody' }, kv('Nom d\'hôte', m.host), kv('Adresse IP', m.ip || '—'), kv('Système', m.os || '—'), kv('Site', m.site), kv('Dernier contact', m.seen ? ageDe(m.seen) : '—'))),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Posture de sécurité' })), h('div', { class: 'cardbody' }, kv('Antivirus', m.av || '—'), kv('Pare-feu', m.fw || '—'), kv('Chiffrement disque', m.enc || '—'), kv('Correctifs en attente', m.patch + ' en attente'), kv('Score de risque', m.risk + ' / 100'))),
      m.redfish && peutAgir ? carteAlimentation(m) : null));
  const paneComp = h('div', { class: 'dtpane hide' }, carteComposants(m));
  const paneSoft = h('div', { class: 'dtpane hide' });
  const paneTerm = h('div', { class: 'dtpane hide' });
  const panes = { info: paneInfo, comp: paneComp, soft: paneSoft, term: paneTerm };
  const tabs = h('div', { class: 'dtabs' }, onglets.map(t => h('button', { class: 'dtab' + (t === 'info' ? ' on' : ''), type: 'button', text: { info: 'Vue d\'ensemble', comp: 'Composants', soft: 'Logiciels', term: 'Commandes' }[t], onclick: e => {
    onglets.forEach(x => { panes[x].style.display = x === t ? 'block' : 'none'; });
    [...tabs.children].forEach(b => b.classList.toggle('on', b === e.currentTarget));
    if (t === 'soft') chargerLogiciels(m, paneSoft);
    if (t === 'term') chargerTaches(m, paneTerm);
  } })));

  const page = h('div', { class: 'page' },
    h('button', { class: 'btn flat mb12', type: 'button', onclick: () => aller('machines') }, icone('retour', 15), 'Retour aux postes'),
    h('div', { class: 'detailhead' },
      h('div', { class: 'big ' + (m.risk >= 75 ? 'hot' : '') }, icone(osIcone(m.oskind), 22)),
      h('div', { class: 'grow1' }, h('h1', { class: 'tronque', text: m.host }), h('div', { class: 'sub dim', text: `${m.ip || '—'} · ${m.site}` })),
      h('div', { class: 'actions' }, actionsDetail(m))),
    h('div', { class: 'metricgrid' },
      h('div', { class: 'mcard' }, h('div', { class: 'lbl' }, icone('puce', 15), 'Processeur'), h('div', { class: 'val' }, h('span', { text: m.online ? String(m.cpu) : '—' }), h('em', { text: '%' })), cpuS),
      h('div', { class: 'mcard' }, h('div', { class: 'lbl' }, icone('memoire', 15), 'Mémoire'), h('div', { class: 'val' }, h('span', { text: m.online ? String(m.ram) : '—' }), h('em', { text: '%' })), ramS),
      h('div', { class: 'mcard' }, h('div', { class: 'lbl' }, icone('disque', 15), 'Disque'), h('div', { class: 'val' }, h('span', { text: String(m.disk) }), h('em', { text: '%' })), diskS)),
    tabs, paneInfo, paneComp, paneSoft, paneTerm);
  requestAnimationFrame(() => { dessinerSpark(cpuS, m.hist, 'var(--accent)'); dessinerSpark(ramS, m.hist.map(v => Math.min(95, v + 20)), 'var(--warn)'); dessinerSpark(diskS, m.hist.map(() => m.disk), 'var(--muted)'); });
  return page;
}

// État d'alimentation lu sur la carte à l'ouverture de la fiche.
function carteAlimentation(m) {
  const corps = h('div', { class: 'cardbody' }, h('p', { class: 'hint', text: 'Lecture de la carte…' }));
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', { class: 'k', text: k }), h('span', { class: 'v', text: v }));
  api.get(`/api/machines/${m.id}/power`).then(p => corps.replaceChildren(
    kv('État', (p.power || '').toLowerCase() === 'on' ? 'sous tension' : (p.power || '—')),
    kv('Modèle', [p.manufacturer, p.model].filter(Boolean).join(' ') || '—'),
    kv('BIOS', p.bios || '—'), kv('Santé', p.health || '—')))
    .catch(e => corps.replaceChildren(h('p', { class: 'hint', text: e.message })));
  return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Alimentation (Redfish)' }), h('span', { class: 'note', text: m.rf_pin ? 'certificat épinglé' : '' })), corps);
}

function actionsDetail(m) {
  const out = [];
  // Allumer : membre. Arrêter, redémarrer : administrateur (le serveur l'exige,
  // avec un renfort récent) — inutile de montrer un bouton qui sera refusé.
  if (m.redfish && peutAgir) {
    const actions = [['on', 'Allumer'], ...(admin ? [['arret', 'Arrêter'], ['redemarrer', 'Redémarrer']] : [])];
    out.push(h('span', { class: 'powerbox' }, ...actions.map(([a, l]) => h('button', { class: 'btn sm', type: 'button', text: l, onclick: () => alimentation(m, a) }))));
  }
  if (m.source === 'agent' && m.wol && !m.online) out.push(h('button', { class: 'btn', type: 'button', onclick: () => reveiller(m) }, icone('reveil', 15), 'Réveiller'));
  const items = m.consoles || [];
  if (items.length) out.push(h('button', { class: 'btn solid', type: 'button', onclick: () => ouvrirConsole(m, 0) }, icone('ecran2', 15), items[0].label));
  // Déclarer un accès distant (où le serveur se connecte) : administrateur.
  if (admin) out.push(h('button', { class: 'ghost', type: 'button', title: 'Accès distants', 'aria-label': 'Accès distants', onclick: () => gererConsoles(m) }, icone('reglages', 16)));
  return out;
}

function carteComposants(m) {
  const inv = m.inventory;
  if (!inv) return h('p', { class: 'hint', text: 'Inventaire pas encore remonté.' });
  const kv = (k, v) => v ? h('div', { class: 'kv' }, h('span', { text: k }), h('b', { text: String(v) })) : null;
  const go = gb => gb >= 1024 ? (gb / 1024).toFixed(1) + ' To' : gb + ' Go';
  return h('div', { class: 'grille' },
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Matériel' })), h('div', { class: 'cardbody' },
      kv('Modèle', [inv.vendor, inv.model].filter(Boolean).join(' ')), kv('Numéro de série', inv.serial), kv('Processeur', inv.cpu_model),
      kv('Cœurs / threads', `${inv.cpu_cores || '?'} / ${inv.cpu_threads || '?'}`), kv('Mémoire', inv.ram_total_gb ? inv.ram_total_gb + ' Go' : ''), kv('Architecture', inv.arch), kv('Noyau', inv.kernel))),
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Stockage' })), h('div', { class: 'cardbody' }, (inv.disks || []).map(d => h('div', { class: 'kv' }, h('span', { text: `${d.device} · ${d.mount}` }), h('b', { text: `${go(d.total_gb)} · ${d.used_pct}%` }))))),
    h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Réseau' })), h('div', { class: 'cardbody' }, (inv.nics || []).map(n => h('div', { class: 'kv' }, h('span', { text: n.name }), h('b', { text: `${n.ip} · ${n.mac || ''}` }))))));
}

async function chargerLogiciels(m, pane) {
  pane.replaceChildren(h('p', { class: 'hint', text: 'Chargement…' }));
  let sw = [];
  try { sw = (await api.get(`/api/machines/${m.id}/software`)).software; } catch { sw = []; }
  const q = h('input', { class: 'field fld-sm', type: 'search', placeholder: 'Filtrer les logiciels' });
  const corps = h('tbody', {});
  const peindre = () => {
    const t = q.value.toLowerCase();
    const list = sw.filter(a => !t || (a.name || '').toLowerCase().includes(t)).slice(0, 600);
    corps.replaceChildren(...(list.length ? list.map(a => h('tr', {},
      h('td', {}, h('b', { text: a.name })), h('td', { class: 'mono', text: a.version || '—' }), h('td', { class: 'cache-m dim', text: (a.publisher || '—').slice(0, 40) }), h('td', { class: 'cache-l dim', text: a.source || '' }),
      peutAgir ? h('td', { class: 'fin' }, h('button', { class: 'btn sm flat danger', type: 'button', text: 'Désinstaller', onclick: () => envoyerTache(m, 'uninstall', a.name, `Désinstaller ${a.name} ?`) })) : null))
      : [h('tr', {}, h('td', { colspan: 5, class: 'vide', text: 'Aucun logiciel.' }))]));
  };
  q.addEventListener('input', peindre); peindre();
  pane.replaceChildren(h('div', { class: 'card' }, h('div', { class: 'pad rowline' }, q,
    peutAgir ? h('button', { class: 'btn sm', type: 'button', onclick: async () => { const p = prompt('Paquet à installer (id winget / nom apt / formule brew) :'); if (p && p.trim()) envoyerTache(m, 'install', p.trim()); } }, icone('plus', 14), 'Installer un paquet') : null),
    h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', { text: 'Nom' }), h('th', { text: 'Version' }), h('th', { class: 'cache-m', text: 'Éditeur' }), h('th', { class: 'cache-l', text: 'Source' }), peutAgir ? h('th', { class: 'fin' }) : null)), corps))));
}

let termTimer = null;
async function chargerTaches(m, pane) {
  const err = h('p', { class: 'erreur' });
  const cmd = h('input', { class: 'field', spellcheck: 'false', placeholder: 'ex. systemctl status ssh' });
  const liste = h('div', {});
  const peindre = jobs => {
    const st = { attente: ['idle', 'en attente'], cours: ['warn', 'en cours'], fait: ['', 'terminé'], echec: ['held', 'échec'] };
    liste.replaceChildren(...(jobs.length ? jobs.map(j => {
      const t = st[j.status] || ['', ''];
      const pre = j.output ? h('pre', { class: 'jobout hide', text: j.output.slice(0, 20000) }) : null;
      const tete = h('div', { class: 'jobhead' }, h('span', { class: 'tag ' + t[0] }, h('i', { class: 'd' }), t[1]), h('code', { text: j.kind === 'cmd' ? j.payload : `${j.kind} ${j.payload}` }), (j.rc !== null && j.status !== 'attente' && j.status !== 'cours') ? h('span', { class: 'mono fs11', text: 'rc=' + j.rc }) : null);
      if (pre) tete.addEventListener('click', () => { pre.style.display = pre.style.display === 'none' ? 'block' : 'none'; });
      return h('div', { class: 'joblog' }, tete, pre);
    }) : [h('p', { class: 'hint', text: 'Aucune tâche pour cette machine.' })]));
  };
  const charger = async () => { try { const jobs = (await api.get(`/api/machines/${m.id}/jobs`)).jobs; peindre(jobs); if (!jobs.some(j => j.status === 'attente' || j.status === 'cours')) clearInterval(termTimer); } catch { /* silencieux */ } };
  const lancer = async () => {
    const v = cmd.value.trim(); if (!v) { err.textContent = 'Entre une commande.'; return; }
    err.textContent = ''; cmd.value = '';
    try { await api.post(`/api/machines/${m.id}/jobs`, { kind: 'cmd', payload: v }); toast('Commande envoyée.'); await charger(); clearInterval(termTimer); termTimer = setInterval(charger, 3000); }
    catch (e) { err.textContent = e.message; }
  };
  cmd.addEventListener('keydown', e => { if (e.key === 'Enter') lancer(); });
  pane.replaceChildren(h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Exécuter une commande' })),
    h('div', { class: 'cardbody' },
      admin ? h('p', { class: 'hint mt0', text: 'La commande est exécutée par l\'agent (souvent root/SYSTEM). Chaque exécution est tracée.' }) : h('div', { class: 'note warn' }, icone('alerte'), h('div', { text: 'Une commande libre demande le rôle administrateur.' })),
      admin ? h('div', { class: 'rowline9' }, cmd, h('button', { class: 'btn solid', type: 'button', onclick: lancer, text: 'Exécuter' })) : null, err, liste)));
  charger();
}
async function envoyerTache(m, kind, payload, question) {
  if (question && !await confirmer(question, 'La tâche part à l\'agent.', { danger: true, oui: 'Confirmer' })) return;
  try { await api.post(`/api/machines/${m.id}/jobs`, { kind, payload }); toast('Tâche envoyée à l\'agent.'); } catch (e) { toast(e.message, true); }
}

async function alimentation(m, action) {
  const labels = { on: 'Allumer', arret: 'Arrêter', redemarrer: 'Redémarrer' };
  if (action !== 'on' && !await confirmer(`${labels[action]} ${m.host} ?`, 'Action d\'alimentation via Redfish.', { danger: true, oui: labels[action] })) return;
  try { const r = await api.post(`/api/machines/${m.id}/power`, { action }); toast(`${labels[action]} envoyé (${r.reset_type}).`); }
  catch (e) { toast(e.message, true); }
}
async function reveiller(m) {
  try { const r = await api.post(`/api/machines/${m.id}/wake`); toast('Réveil envoyé — ' + r.methods.join(', ') + '.'); } catch (e) { toast(e.message, true); }
}

let TYPES = null;
async function chargerTypes() { if (!TYPES) { try { TYPES = (await api.get('/api/console-types')).types; } catch { TYPES = []; } } return TYPES; }

async function ouvrirConsole(m, idx) {
  const con = (m.consoles || [])[idx];
  if (con && con.type === 'vnc') return ouvrirVnc(m, idx, con.label);
  try {
    const r = await api.post(`/api/machines/${m.id}/remote`, { idx });
    if (r.embed) ouvrirCadre(r.url, `${r.label} · ${m.host}`);
    else window.open(r.url, '_blank', 'noopener');
  } catch (e) {
    if (e.status === 409 && /épingl/i.test(e.message || '') && admin) return epinglerConsole(m, idx);
    if (e.status === 409 && admin) gererConsoles(m);
    else if (e.status !== 401) toast(e.message || 'Impossible d\'ouvrir cet accès.', true);
  }
}

function ouvrirCadre(url, titre) {
  const cadre = h('iframe', { class: 'remote-frame', src: url, allow: 'fullscreen; clipboard-read; clipboard-write', referrerpolicy: 'no-referrer' });
  const scrim = h('div', { class: 'remote-scrim on' }, h('div', { class: 'remote-shell' },
    h('div', { class: 'remote-bar' }, h('span', { class: 'remote-dot' }), h('b', { text: titre }), h('span', { class: 'grow' }),
      h('a', { class: 'btn', href: url, target: '_blank', rel: 'noopener' }, 'Nouvel onglet'),
      h('button', { class: 'btn solid', type: 'button', onclick: () => scrim.remove() }, icone('croix', 15), 'Fermer')), cadre));
  document.body.append(scrim);
}

async function ouvrirVnc(m, idx, label) {
  const ecran = h('div', { class: 'remote-frame vncscreen' });
  const statut = h('span', { class: 'grow dim fs12' });
  let rfb = null;
  const scrim = h('div', { class: 'remote-scrim on' }, h('div', { class: 'remote-shell' },
    h('div', { class: 'remote-bar' }, h('span', { class: 'remote-dot' }), h('b', { text: `${label} · ${m.host}` }), statut,
      h('button', { class: 'btn', type: 'button', text: 'Ctrl+Alt+Suppr', onclick: () => { try { rfb?.sendCtrlAltDel(); } catch { /* rien */ } } }),
      h('button', { class: 'btn solid', type: 'button', onclick: () => { try { rfb?.disconnect(); } catch { /* rien */ } scrim.remove(); } }, icone('croix', 15), 'Fermer')), ecran));
  document.body.append(scrim);
  statut.textContent = 'connexion…';
  try {
    const { default: RFB } = await import('/vendor/novnc/core/rfb.js');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    rfb = new RFB(ecran, `${proto}://${location.host}/vnc/${m.id}/${idx}`, {});
    rfb.scaleViewport = true; rfb.clipViewport = false;
    rfb.addEventListener('connect', () => { statut.textContent = 'connecté'; });
    rfb.addEventListener('disconnect', e => { statut.textContent = e.detail?.clean ? 'déconnecté' : 'connexion perdue'; });
    rfb.addEventListener('securityfailure', () => { statut.textContent = 'échec d\'authentification'; });
  } catch { statut.textContent = 'noVNC indisponible'; }
}

async function epinglerConsole(m, idx) {
  try {
    const vu = await api.get(`/api/machines/${m.id}/pin?idx=${idx}`);
    const ok = await confirmer('Épingler le certificat de la carte ?',
      `Empreinte : ${vu.fp}\nSujet : ${vu.sujet || '—'}\nConfirme si elle correspond à la carte. Toute connexion future exigera exactement ce certificat.`, { oui: 'Épingler' });
    if (!ok) return;
    await api.post(`/api/machines/${m.id}/pin`, { idx, fp: vu.fp });
    toast('Certificat épinglé.'); ouvrirConsole(m, idx);
  } catch (e) { toast(e.message, true); }
}

async function epinglerRedfish(m) {
  try {
    const vu = await api.get(`/api/machines/${m.id}/pin?redfish=1`);
    const ok = await confirmer('Épingler le certificat de la carte Redfish ?',
      `Empreinte : ${vu.fp}\nSujet : ${vu.sujet || '—'}\nConfirme si elle correspond à la carte. L'alimentation n'acceptera plus que ce certificat.`, { oui: 'Épingler' });
    if (!ok) return false;
    await api.post(`/api/machines/${m.id}/pin`, { redfish: true, fp: vu.fp });
    await rafraichir();
    toast('Certificat épinglé.');
    return true;
  } catch (e) { toast(e.message, true); return false; }
}

// Identifiants Redfish d'une carte : secret d'appareil, donc administrateur.
// Le mot de passe part au serveur, qui le scelle ; il ne revient jamais.
function blocRedfish(m) {
  if (!admin) return h('div', { class: 'cons-add' }, h('b', { class: 'fs12', text: 'Contrôle d\'alimentation (Redfish)' }), h('p', { class: 'hint', text: 'Les identifiants d\'une carte sont réservés à un administrateur.' }));
  const user = h('input', { class: 'field', placeholder: 'Utilisateur (ex. root)', autocomplete: 'off', value: m.rf_user || '' });
  const mdp = h('input', { class: 'field', type: 'password', placeholder: m.redfish ? 'Mot de passe (en place)' : 'Mot de passe', autocomplete: 'new-password' });
  const url = h('input', { class: 'field', spellcheck: 'false', placeholder: 'URL de la carte (vide = celle de la console iDRAC/iLO)', value: m.rf_url || '' });
  const etat = h('p', { class: 'hint' });
  const actions = h('div', { class: 'rowline9 mt9' });
  const peindre = () => {
    const frais = E.machines.find(x => x.id === m.id) || m;
    etat.textContent = frais.redfish ? `Configuré${frais.rf_pin ? ' · certificat épinglé' : ''} — les boutons d'alimentation sont sur la fiche.` : 'Non configuré.';
    const https = /^https:/i.test(frais.rf_url || '') || (!frais.rf_url && (frais.consoles || []).some(c => ['idrac', 'ilo', 'ipmi'].includes(c.type) && /^https:/i.test(c.target)));
    // replaceChildren écrirait « null » en texte : les absents sont filtrés.
    actions.replaceChildren(...[
      h('button', { class: 'btn solid grow1', type: 'button', text: 'Enregistrer', onclick: () => sauver(false) }),
      h('button', { class: 'btn grow1', type: 'button', text: 'Retirer', onclick: () => sauver(true) }),
      frais.redfish && https && !frais.rf_pin ? h('button', { class: 'btn grow1', type: 'button', text: 'Épingler le certificat', onclick: async () => { if (await epinglerRedfish(frais)) peindre(); } }) : null,
    ].filter(Boolean));
  };
  const sauver = async retirer => {
    const corps = retirer ? { user: '', password: '', url: '' } : { user: user.value.trim(), password: mdp.value, url: url.value.trim() };
    if (!retirer && (!corps.user || !corps.password)) { etat.textContent = 'Utilisateur et mot de passe requis.'; return; }
    try {
      appliquerEtat(await api.put(`/api/machines/${m.id}/redfish`, corps));
      mdp.value = '';
      if (retirer) { user.value = ''; url.value = ''; }
      toast(retirer ? 'Contrôle d\'alimentation retiré.' : 'Identifiants enregistrés, scellés côté serveur.');
      peindre();
    } catch (e) { etat.textContent = e.message; }
  };
  peindre();
  return h('div', { class: 'cons-add' },
    h('b', { class: 'fs12', text: 'Contrôle d\'alimentation (Redfish)' }),
    h('p', { class: 'hint mt0', text: 'Identifiants de la carte iDRAC / iLO / BMC : allumer, arrêter et redémarrer depuis Sentinel, sans licence Enterprise.' }),
    h('div', { class: 'row2' }, user, mdp), url, actions, etat);
}

async function gererConsoles(m) {
  await chargerTypes();
  let cons = (m.consoles || []).slice();
  const err = h('p', { class: 'erreur' });
  const liste = h('div', {});
  const peindreListe = () => liste.replaceChildren(...(cons.length ? cons.map((c, i) => h('div', { class: 'flowrow' },
    h('span', { class: 'itile' }, icone('ecran2', 15)),
    h('div', {}, h('strong', { text: c.label }), h('small', { text: `${typeLabel(c.type)} · ${c.target}${c.embed ? ' · intégré' : ''}${c.a_mdp ? ' · mot de passe' : ''}` })),
    h('div', { class: 'fin' }, h('button', { class: 'ghost', type: 'button', 'aria-label': 'Retirer', onclick: async () => { cons.splice(i, 1); await sauverConsoles(); } }, icone('croix', 15))))) : [h('p', { class: 'hint', text: 'Aucun accès configuré.' })]));
  const typeSel = h('select', { class: 'field' }, optionsDeTypes(TYPES));
  const cible = h('input', { class: 'field', spellcheck: 'false', placeholder: 'https://idrac.exemple.org' });
  const label = h('input', { class: 'field', maxlength: 40, placeholder: 'Libellé (optionnel)' });
  const vncpw = h('input', { class: 'field hide', type: 'password', placeholder: 'Mot de passe VNC (défini dans la carte)' });
  const embed = h('input', { type: 'checkbox', checked: true });
  const hint = h('p', { class: 'hint' });
  const syncType = () => {
    const t = TYPES.find(x => x.id === typeSel.value);
    cible.placeholder = t?.vnc ? '198.51.100.10:5900 (hôte:port)' : (!t?.url ? 'Node MeshCentral' : 'https://carte.exemple.org');
    vncpw.style.display = t?.vnc ? 'block' : 'none';
    hint.textContent = t?.note || '';
  };
  typeSel.addEventListener('change', syncType); syncType();
  const sauverConsoles = async () => {
    err.textContent = '';
    try { appliquerEtat(await api.put(`/api/machines/${m.id}/consoles`, { consoles: cons })); const frais = E.machines.find(x => x.id === m.id); cons = (frais?.consoles || []).slice(); peindreListe(); return true; }
    catch (e) { err.textContent = e.message; return false; }
  };
  peindreListe();
  await dialogue({ titre: `Accès distants — ${m.host}`, large: true,
    contenu: [liste, h('div', { class: 'cons-add' },
      h('div', { class: 'row2' }, typeSel, label), cible, vncpw, h('label', { class: 'chk mt9' }, embed, h('span', { text: 'Afficher dans Sentinel (sinon : nouvel onglet)' })), hint,
      h('div', { class: 'pad pt10' }, h('button', { class: 'btn solid plein', type: 'button', text: 'Ajouter l\'accès', onclick: async () => {
        const t = cible.value.trim(); if (!t) { err.textContent = 'Renseigne l\'URL ou le node.'; return; }
        const acces = { type: typeSel.value, target: t, label: label.value.trim(), embed: embed.checked };
        if (typeSel.value === 'vnc' && vncpw.value) acces.vncpw = vncpw.value;
        cons.push(acces);
        if (await sauverConsoles()) { cible.value = ''; label.value = ''; vncpw.value = ''; toast('Accès ajouté.'); } else cons.pop();
      } }))), blocRedfish(m), err],
    boutons: [{ texte: 'Fermer', classe: 'solid', valeur: true }] });
}
function typeLabel(t) { return (TYPES || []).find(x => x.id === t)?.label || t; }
// Les types d'accès proposés, les recommandés marqués d'une étoile.
function optionsDeTypes(types) { return types.map(t => h('option', { value: t.id, text: t.label + (t.recommande ? ' ★' : '') })); }

async function dialogueInscription(relais) {
  const site = h('input', { class: 'field', maxlength: 40, value: relais ? 'Relais' : 'Agents' });
  const nom = h('input', { class: 'field', maxlength: 60, placeholder: 'Laisser vide = nom réseau de la machine' });
  const osTabs = h('div', { class: 'views' });
  const zone = h('div', {});
  let os = detecterOs();
  let info = null;
  const rafraichirInfo = async () => {
    try { info = await api.post('/api/enroll/info', { site: site.value.trim() || 'Agents', name: nom.value.trim(), relay: relais }); }
    catch (e) { toast(e.message, true); return; }
    peindreZone();
  };
  const peindreOs = () => osTabs.replaceChildren(...[['windows', 'Windows'], ['macos', 'macOS'], ['linux', 'Linux']].map(([v, l]) => h('button', { class: 'view' + (os === v ? ' on' : ''), type: 'button', text: l, onclick: () => { os = v; peindreOs(); peindreZone(); } })));
  const copier = cmd => navigator.clipboard?.writeText(cmd).then(() => toast('Commande copiée.'), () => toast('Copie impossible.', true));
  const AIDE = {
    windows: { fichier: 'Télécharger l’installateur (.exe)', etapes: 'Double-clique sur le fichier : Windows demande l’accord d’un administrateur, puis l’agent s’installe, Python compris s’il manque. L’installateur n’est pas signé : si SmartScreen s’affiche, « Informations complémentaires » puis « Exécuter quand même ».', ligne: 'Ou colle dans PowerShell, ouvert en administrateur :' },
    macos: { fichier: 'Télécharger l’installateur (.zip)', etapes: 'Ouvre l’archive, puis clic droit sur « Installer Sentinel » et « Ouvrir » (un fichier non signé ne s’ouvre pas d’un double-clic). Le Terminal demande le mot de passe d’un administrateur. Sans Python 3 sur le Mac, lance d’abord « xcode-select --install ».', ligne: 'Ou colle dans le Terminal :' },
    linux: { fichier: 'Télécharger le script (.sh)', etapes: 'Lance-le avec « sudo bash installer-sentinel.sh ». Debian, Ubuntu, Fedora et Arch : Python est installé s’il manque.', ligne: 'Ou colle dans un terminal :' },
  };
  const peindreZone = () => {
    if (!info) { zone.replaceChildren(h('p', { class: 'hint', text: 'Génération du code…' })); return; }
    const cmd = info.commands[os];
    const telechargement = new URL(info.downloads[os]);
    const a = AIDE[os];
    let hote = '';
    try { hote = new URL(info.base_url).hostname; } catch { /* adresse déjà refusée par le serveur */ }
    const locale = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(hote);
    zone.replaceChildren(...[
      locale ? h('div', { class: 'note warn mt10' }, icone('alerte'), h('div', { text: `Les postes joindraient Sentinel à ${info.base_url}, une adresse qui ne mène qu’à ta propre machine. Renseigne « Adresse publique de Sentinel » dans ses réglages du Hub (son adresse sur le réseau, ex. http://192.0.2.10:8090), puis rouvre ce dialogue.` })) : null,
      !locale && info.base_url.startsWith('http:') ? h('p', { class: 'hint', text: 'Sentinel est joint en HTTP : le jeton de l’agent passe en clair sur le réseau. Sers-le en HTTPS dès que possible (action H1 de SECURITY.md).' }) : null,
      h('div', { class: 'installe mt10' },
        h('a', { class: 'btn solid', href: telechargement.pathname + telechargement.search, download: '' }, icone('telecharge', 15), a.fichier),
        h('p', { class: 'hint', text: a.etapes })),
      h('p', { class: 'hint mt14', text: a.ligne }),
      h('pre', { class: 'cmd', text: cmd }),
      h('div', { class: 'rowline9' },
        h('button', { class: 'btn', type: 'button', onclick: () => copier(cmd) }, icone('copie', 14), 'Copier'),
        h('button', { class: 'btn flat', type: 'button', onclick: () => { info = null; peindreZone(); rafraichirInfo(); } }, icone('correctif', 14), 'Nouveau code')),
      h('p', { class: 'hint', text: `Un code sert à un seul poste et expire dans ${Math.round(info.expire_dans / 60)} min ; installateur et commande portent le même. Pour un autre poste : « Nouveau code ».` })].filter(Boolean));
  };
  peindreOs(); rafraichirInfo();
  let t;
  const relance = () => { clearTimeout(t); t = setTimeout(rafraichirInfo, 400); };
  site.addEventListener('input', relance); nom.addEventListener('input', relance);
  const modeKvm = !relais && admin ? boutonKvm() : null;
  await dialogue({ titre: relais ? 'Ajouter un nœud relais (Wake-on-LAN)' : 'Ajouter un poste', large: true,
    contenu: [
      relais ? h('div', { class: 'note info' }, icone('reveil'), h('div', { text: 'Installe-le sur une machine toujours allumée du VLAN à couvrir (un Raspberry Pi suffit).' })) : null,
      h('label', { class: 'champ' }, h('span', { class: 'lbl', text: 'Parc / site' }), site),
      h('label', { class: 'champ mt10' }, h('span', { class: 'lbl', text: 'Nom du poste (optionnel)' }), nom),
      h('p', { class: 'lbl mt14', text: 'Système' }), osTabs, zone, modeKvm],
    boutons: [{ texte: 'Fermer', classe: 'solid', valeur: true }] });
}

function boutonKvm() {
  const b = h('button', { class: 'btn flat plein mt14 btnretour', type: 'button', onclick: () => dialogueKvm() }, icone('serveur', 15), 'Carte de gestion, sans agent…');
  return b;
}
async function dialogueKvm() {
  await chargerTypes();
  const host = h('input', { class: 'field', maxlength: 60, placeholder: 'Nom (ex. serveur-a)' });
  const ip = h('input', { class: 'field', maxlength: 45, placeholder: 'IP (optionnel)' });
  const typeSel = h('select', { class: 'field' }, optionsDeTypes(TYPES.filter(t => t.url || t.vnc)));
  const site = h('input', { class: 'field', maxlength: 40, value: 'Matériel' });
  const cible = h('input', { class: 'field', spellcheck: 'false', placeholder: 'https://idrac.exemple.org' });
  const embed = h('input', { type: 'checkbox', checked: true });
  const err = h('p', { class: 'erreur' });
  await dialogue({ titre: 'Carte de gestion (sans agent)', large: true,
    contenu: [h('p', { class: 'hint mt0', text: 'Accès écran, clavier et BIOS/UEFI sans agent, même serveur éteint.' }),
      h('div', { class: 'row2' }, host, ip), h('div', { class: 'mt9' }, typeSel),
      h('label', { class: 'champ mt9' }, h('span', { class: 'lbl', text: 'Parc / site' }), site), cible,
      h('label', { class: 'chk mt9' }, embed, h('span', { text: 'Afficher dans Sentinel' })), err],
    boutons: [{ texte: 'Annuler', classe: 'flat', valeur: false }, { texte: 'Ajouter le matériel', classe: 'solid', agir: async () => {
      if (!host.value.trim()) { err.textContent = 'Donne un nom.'; return false; }
      if (!cible.value.trim()) { err.textContent = 'Renseigne l\'adresse de la console.'; return false; }
      try {
        appliquerEtat(await api.post('/api/hosts', { host: host.value.trim(), ip: ip.value.trim(), site: site.value.trim() || 'Matériel', ctype: typeSel.value, target: cible.value.trim(), embed: embed.checked, label: typeLabel(typeSel.value) }));
        toast('Matériel ajouté.'); return true;
      } catch (e) { err.textContent = e.message; return false; }
    } }] });
}

function detecterOs() {
  const p = (navigator.platform || '') + ' ' + (navigator.userAgent || '');
  if (/mac/i.test(p) && !/iphone|ipad/i.test(p)) return 'macos';
  if (/win/i.test(p)) return 'windows';
  return 'linux';
}

function ageDe(cree) {
  if (!cree) return 'jamais';
  const d = Math.max(0, Date.now() / 1000 - cree);
  if (d < 8) return 'à l\'instant';
  if (d < 90) return `il y a ${Math.round(d)} s`;
  if (d < 5400) return `il y a ${Math.round(d / 60)} min`;
  if (d < 172800) return `il y a ${Math.round(d / 3600)} h`;
  return `il y a ${Math.round(d / 86400)} j`;
}
const SVGNS = 'http://www.w3.org/2000/svg';
function dessinerSpark(el, valeurs, couleur) {
  if (!valeurs.length) return;
  const W = 260, H = 38, max = Math.max(...valeurs, 100);
  const pts = valeurs.map((v, i) => `${i * (W / Math.max(1, valeurs.length - 1))} ${H - (v / max) * (H - 4) - 2}`).join(' L');
  const path = (d, attrs) => { const p = document.createElementNS(SVGNS, 'path'); p.setAttribute('d', d); for (const [k, v] of Object.entries(attrs)) p.setAttribute(k, v); return p; };
  el.replaceChildren(
    path(`M${pts} L${W} ${H} L0 ${H}Z`, { fill: couleur, opacity: '0.12' }),
    path(`M${pts}`, { fill: 'none', stroke: couleur, 'stroke-width': '1.6' }));
}

let relectureAlerte = null;
function brancherFlux() {
  const src = new EventSource('/api/activite');
  src.onmessage = ev => {
    try {
      const e = JSON.parse(ev.data);
      if (e.t === 'flux') { E.feed = [{ html: e.html, ip: e.ip, cree: e.cree }, ...E.feed].slice(0, 8); if (location.hash.startsWith('#over')) peindreFeed(); }
      // Une alerte ouverte ou résolue : l'état est relu (une rafale ne relit qu'une fois).
      if (e.t === 'alerte' && !relectureAlerte) relectureAlerte = setTimeout(() => { relectureAlerte = null; rafraichir(); }, 400);
    } catch { /* ligne non-JSON (ping) */ }
  };
  src.onerror = () => { /* EventSource se reconnecte seul */ };
}

await rafraichir();
brancherFlux();
setInterval(rafraichir, Math.max(10, E.interval) * 1000);
const [page, ref] = location.hash.slice(1).split('/');
aller(PAGES[page] ? page : (page === 'detail' ? 'detail' : 'over'), { ref: /^[\w-]{16}$/.test(ref || '') ? ref : null });
