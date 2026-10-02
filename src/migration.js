// Reprise d'une base Sentinel 1.1.0, l'ancien nom de NEXARC.
//
// La 1.x avait un opérateur unique (table auth, mot de passe scrypt, secret
// TOTP en clair) : il devient l'administrateur du socle. L'empreinte scrypt du
// mot de passe se relit telle quelle (le socle la reconnaît et la repasse en
// Argon2id à la première connexion) ; si elle est absente ou illisible, le
// compte est repris sans mot de passe et l'admin le réinitialise. Le secret
// TOTP, en clair en 1.x, est scellé.
//
// Le parc, les automatisations, les alertes et l'historique sont importés. Les
// agents perdent leur jeton (la 1.x en partageait un seul) : chacun se réenrôle
// une fois et se rattache à sa machine par son nom d'hôte. Les mots de passe VNC
// et identifiants Redfish, scellés en 1.x sous une clé qui n'existe plus, ne
// sont pas repris : l'URL et l'utilisateur restent, l'admin ressaisit le secret.
import { normaliseIdentifiant } from '../socle/src/comptes.js';
import { nouvelleRef, secondes, transaction } from './base.js';
import { TYPES } from './consoles.js';

const existe = (db, t) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t);
const colonnes = (db, t) => new Set(db.prepare('SELECT name FROM pragma_table_info(?)').all(t).map(c => c.name));

// Passée à demarrerSocle : importe l'opérateur unique de la 1.x, avant que le
// socle ne décide s'il attend une installation.
export function migrerComptes({ db, comptes, coffre, log = console }) {
  if (!existe(db, 'auth')) return 0;
  const row = db.prepare('SELECT * FROM auth WHERE id = 1').get();
  if (!row) return 0;
  let ident = normaliseIdentifiant(row.username || 'admin').replace(/[^\p{L}\p{N}._@+-]/gu, '-').slice(0, 60);
  if (ident.length < 3) ident = 'admin';
  comptes.transaction(() => {
    if (comptes.parIdentifiant(ident)) return;
    const c = comptes.creerCompte({ identifiant: ident, affichage: row.username || ident, role: 'admin' });
    // must_change signalait un mot de passe d'amorçage : on ne le reprend pas,
    // l'admin en pose un neuf. Sinon l'empreinte scrypt est reprise.
    const mdp = row.must_change ? null : (row.pw_hash || null);
    const totp = (row.tfa_enabled && row.totp_secret) ? coffre.scelle('totp', String(row.totp_secret).replace(/\s/g, '').toUpperCase(), c.id) : null;
    db.prepare('UPDATE socle_comptes SET mdp = ?, totp = ? WHERE id = ?').run(mdp, totp, c.id);
  });
  log.info?.(`[migration] Opérateur 1.x « ${ident} » repris comme administrateur${db.prepare('SELECT must_change FROM auth WHERE id=1').get()?.must_change ? ' (mot de passe à redéfinir)' : ''}.`);
  return 1;
}

// L'opérateur repris sans mot de passe ne peut pas se connecter, et il n'y a
// pas d'autre administrateur pour lui envoyer un lien. Tant qu'aucun
// administrateur actif ne tient un mot de passe ou une clé d'accès, chaque
// démarrage écrit au journal du conteneur un lien de réinitialisation neuf,
// comme le jeton d'installation d'une base vide.
const SECOURS_MS = 20 * 60e3;
export function lienDeSecours({ db, comptes, journal, urlPublique = '', log = console }) {
  const admins = db.prepare("SELECT * FROM socle_comptes WHERE role = 'admin' AND actif = 1 ORDER BY cree").all();
  if (!admins.length || admins.some(c => { const f = comptes.facteursDe(c); return f.motdepasse || f.cle; })) return null;
  const c = admins[0];
  db.prepare("DELETE FROM socle_jetons WHERE compte = ? AND usage = 'reinit'").run(c.id);
  const jeton = comptes.emettreJeton('reinit', c.id, SECOURS_MS);
  journal.ecrire({ acteur: 'système', action: 'compte.reinit_emis', objet: c.id, details: { par: 'démarrage, aucun administrateur ne peut se connecter' } });
  log.warn?.(`[comptes] Aucun administrateur ne peut se connecter. Lien de réinitialisation pour « ${c.identifiant} », valable vingt minutes et une seule fois : ${urlPublique || '<adresse de NEXARC>'}/#reinit=${jeton}`);
  return jeton;
}

// Appelée après demarrerSocle : importe le parc et son historique, puis retire
// les tables de la 1.x.
export function migrerParc({ db, log = console }) {
  if (!existe(db, 'agents')) return 0;
  const now = secondes();
  const cols = colonnes(db, 'agents');
  const lire = c => (cols.has(c) ? c : 'NULL');
  const anciens = db.prepare("SELECT * FROM agents WHERE source IN ('agent','kvm')").all();
  const idParAncien = new Map();
  transaction(db, () => {
    for (const a of anciens) {
      const ref = nouvelleRef();
      const consoles = nettoyerConsoles(a.consoles);
      const r = db.prepare(`INSERT INTO machines(ref, jeton_hash, host, ip, site, os, oskind, role, online, risk,
          cpu, ram, disk, av, fw, enc, patch, hist, source, mac, mesh_node, consoles, inventory, software, updates, inv_at,
          rf_url, rf_user, last_report, cree)
        VALUES(?,NULL,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        ref, a.host || 'machine', a.ip || null, a.site || 'Agents', a.os || '', a.oskind || 'win', a.role || 'poste', a.risk || 0,
        a.cpu || 0, a.ram || 0, a.disk || 0, a.av || '', a.fw || '', a.enc || '', a.patch || 0,
        a.hist || '[]', a.source === 'kvm' ? 'kvm' : 'agent', cols.has('mac') ? a.mac || null : null,
        cols.has('mesh_node') ? a.mesh_node || null : null, consoles,
        cols.has('inventory') ? a.inventory || null : null, cols.has('software') ? a.software || null : null,
        cols.has('updates') ? a.updates || null : null, cols.has('inv_at') ? a.inv_at || null : null,
        cols.has('rf_url') ? a.rf_url || null : null, cols.has('rf_user') ? a.rf_user || null : null,
        a.last_report || null, now);
      idParAncien.set(a.id, Number(r.lastInsertRowid));
    }
    if (existe(db, 'alerts')) {
      for (const al of db.prepare('SELECT * FROM alerts').all()) {
        const mid = idParAncien.get(al.host_id) ?? null;
        db.prepare('INSERT INTO alertes(ref, sev, txt, machine_id, cree) VALUES(?,?,?,?,?)')
          .run(nouvelleRef(), al.sev || 'info', al.txt || '', mid, al.created || now);
      }
    }
    if (existe(db, 'automations')) {
      const ac = colonnes(db, 'automations');
      for (const au of db.prepare('SELECT * FROM automations').all()) {
        db.prepare(`INSERT INTO automatisations(ref, nom, kind, payload, cible, cible_val, toutes_h, heure, actif, dernier_run, dernier_statut, runs)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          nouvelleRef(), au.name || 'Automatisation', au.kind || 'inventory', au.payload || '',
          au.target || 'tous', ac.has('target_val') ? au.target_val || '' : '', au.every || 24, au.at_hour || 2,
          au.enabled ? 1 : 0, au.last_run || null, au.last_status || null, au.runs || 0);
      }
    }
    if (existe(db, 'jobs')) {
      for (const j of db.prepare("SELECT * FROM jobs WHERE status IN ('done','error')").all()) {
        const mid = idParAncien.get(j.agent_id);
        if (!mid) continue;
        db.prepare(`INSERT INTO taches(ref, machine_id, kind, payload, sensible, status, output, rc, cree, fin, auteur)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(
          nouvelleRef(), mid, j.kind || 'cmd', j.kind === 'cmd' ? '' : (j.payload || ''), j.kind === 'cmd' ? 1 : 0,
          j.status, (j.output || '').slice(0, 20000), j.rc ?? null, j.created || now, j.finished || null, j.author || null);
      }
    }
    if (existe(db, 'feed')) {
      for (const f of db.prepare('SELECT * FROM feed ORDER BY created DESC LIMIT 40').all()) {
        db.prepare('INSERT INTO flux(texte, ip, cree) VALUES(?,?,?)').run(String(f.html || '').replace(/<[^>]+>/g, '').slice(0, 400), f.ip || null, f.created || now);
      }
    }
    for (const t of ['agents', 'alerts', 'automations', 'jobs', 'enroll_codes', 'feed', 'users', 'patches', 'vulns', 'autos', 'tgs', 'auth', 'meta']) {
      if (existe(db, t)) db.exec(`DROP TABLE ${t}`);
    }
  });
  log.info?.(`[migration] ${anciens.length} machine(s) de la 1.x reprises. Les agents se réenrôlent une fois ; identifiants VNC/Redfish à ressaisir.`);
  return anciens.length;
}

// Les mots de passe VNC (vncpw_enc) et scellés d'antan ne se déchiffrent pas
// sans l'ancien secret : on garde la console, sans le mot de passe. Un type de
// console de la 1.x qui n'existe plus tel quel (une console d'hyperviseur, par
// exemple) est ramené sur le type générique « hyperviseur », qui ouvre la même
// URL dans une iframe.
function nettoyerConsoles(brut) {
  if (!brut) return null;
  let lues; try { lues = JSON.parse(brut); } catch { return null; }
  if (!Array.isArray(lues)) return null;
  const reprises = lues.map(({ vncpw_enc, vncpw, ...reste }) => {
    const type = String(reste.type || '').toLowerCase();
    return { ...reste, type: TYPES[type] ? type : 'hyperviseur' };
  });
  return JSON.stringify(reprises);
}
