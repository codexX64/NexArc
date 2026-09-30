// Base de Sentinel : parc (machines avec ou sans agent), tâches distantes,
// automatisations, alertes, flux d'activité, codes et jetons d'enrôlement.
//
// Deux règles de conception valent partout :
//   1. Aucun identifiant séquentiel ne sort. Chaque objet désigné de l'extérieur
//      (machine, tâche, automatisation, alerte) porte une référence aléatoire de
//      96 bits ; l'entier interne ne dit ni combien il y en a, ni où chercher le
//      suivant (SEC-AUTHZ-006).
//   2. Aucun secret ne sort en clair. Mots de passe VNC et identifiants Redfish
//      sont scellés par le Coffre du socle ; l'API ne rend que « en place ».
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

export const REF = /^[A-Za-z0-9_-]{16}$/;
// Une automatisation vise un site, un système ou tout le parc : quelques
// dizaines suffisent à un parc réel, deux cents bornent la ronde de chaque minute.
export const MAX_AUTOMATISATIONS = 200;
export const nouvelleRef = () => crypto.randomBytes(12).toString('base64url');
const secondes = () => Date.now() / 1000;

export function ouvrirBase(dossier) {
  fs.mkdirSync(dossier, { recursive: true, mode: 0o700 });
  const fichier = path.join(dossier, 'sentinel.db');
  // La base garde des secrets scellés et des empreintes de jetons : lisible par
  // Sentinel seul. SQLite donne aux journaux WAL les droits de la base.
  fs.closeSync(fs.openSync(fichier, 'a', 0o600));
  for (const f of [fichier, fichier + '-wal', fichier + '-shm']) if (fs.existsSync(f)) fs.chmodSync(f, 0o600);
  const db = new DatabaseSync(fichier);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;');
  // Les premières bases de la 2.0 gardaient les codes d'inscription en clair ;
  // un code ne vaut qu'une heure, la table repart vide sous sa forme hachée.
  if (db.prepare("SELECT 1 FROM pragma_table_info('enrolements') WHERE name = 'code'").get()) db.exec('DROP TABLE enrolements');
  db.exec(`
    CREATE TABLE IF NOT EXISTS machines(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE,
      jeton_hash TEXT, host TEXT NOT NULL, ip TEXT, site TEXT NOT NULL DEFAULT 'Agents',
      os TEXT, oskind TEXT NOT NULL DEFAULT 'win', role TEXT NOT NULL DEFAULT 'poste',
      online INTEGER NOT NULL DEFAULT 0, risk INTEGER NOT NULL DEFAULT 0,
      cpu INTEGER NOT NULL DEFAULT 0, ram INTEGER NOT NULL DEFAULT 0, disk INTEGER NOT NULL DEFAULT 0,
      av TEXT DEFAULT '', fw TEXT DEFAULT '', enc TEXT DEFAULT '', patch INTEGER NOT NULL DEFAULT 0,
      hist TEXT NOT NULL DEFAULT '[]', source TEXT NOT NULL DEFAULT 'agent',
      mac TEXT, mesh_node TEXT, consoles TEXT, inventory TEXT, software TEXT, updates TEXT, inv_at REAL,
      rf_url TEXT, rf_user TEXT, rf_secret TEXT, rf_fp TEXT,
      sec_n INTEGER NOT NULL DEFAULT 0, sec_depuis REAL,
      last_report REAL, cree REAL NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS machines_ref ON machines(ref);
    CREATE INDEX IF NOT EXISTS machines_source ON machines(source);

    -- regle NULL : alerte reprise de la 1.x, qu'aucune mesure ne résout.
    CREATE TABLE IF NOT EXISTS alertes(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE, regle TEXT,
      sev TEXT NOT NULL, txt TEXT NOT NULL, machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
      etat TEXT NOT NULL DEFAULT 'ouverte' CHECK(etat IN ('ouverte', 'resolue')),
      cree REAL NOT NULL, maj REAL, resolue REAL, acquittee REAL, acquitte_par TEXT, acquitte_compte TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS alertes_ref ON alertes(ref);
    CREATE UNIQUE INDEX IF NOT EXISTS alertes_une_ouverte ON alertes(machine_id, regle) WHERE etat = 'ouverte' AND regle IS NOT NULL;
    CREATE INDEX IF NOT EXISTS alertes_etat ON alertes(etat, resolue);

    CREATE TABLE IF NOT EXISTS taches(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE,
      machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
      kind TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '', sensible INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'attente', output TEXT, rc INTEGER,
      cree REAL NOT NULL, debut REAL, fin REAL, auteur TEXT, auteur_compte TEXT);
    CREATE INDEX IF NOT EXISTS taches_auteur ON taches(auteur_compte);
    CREATE UNIQUE INDEX IF NOT EXISTS taches_ref ON taches(ref);
    CREATE INDEX IF NOT EXISTS taches_machine ON taches(machine_id, status);

    CREATE TABLE IF NOT EXISTS automatisations(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE,
      nom TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '',
      cible TEXT NOT NULL DEFAULT 'tous', cible_val TEXT DEFAULT '',
      toutes_h INTEGER NOT NULL DEFAULT 24, heure INTEGER NOT NULL DEFAULT 2,
      actif INTEGER NOT NULL DEFAULT 1, dernier_run REAL, dernier_statut TEXT, runs INTEGER NOT NULL DEFAULT 0);
    CREATE UNIQUE INDEX IF NOT EXISTS autos_ref ON automatisations(ref);

    CREATE TABLE IF NOT EXISTS enrolements(
      empreinte TEXT PRIMARY KEY, expire REAL NOT NULL, site TEXT NOT NULL DEFAULT 'Agents',
      nom TEXT DEFAULT '', relais INTEGER NOT NULL DEFAULT 0, cree REAL NOT NULL);

    -- Jeton d'un agent minté à l'échange d'un code, en attente de sa première
    -- remontée : la machine naît à cet instant, avec ce jeton haché.
    CREATE TABLE IF NOT EXISTS jetons_attente(
      jeton_hash TEXT PRIMARY KEY, site TEXT NOT NULL DEFAULT 'Agents', nom TEXT DEFAULT '',
      relais INTEGER NOT NULL DEFAULT 0, expire REAL NOT NULL, cree REAL NOT NULL);

    CREATE TABLE IF NOT EXISTS flux(
      id INTEGER PRIMARY KEY AUTOINCREMENT, texte TEXT NOT NULL, ip TEXT, cree REAL NOT NULL);
  `);
  return db;
}

const echappeLike = s => s.replace(/[\\%_]/g, c => '\\' + c);

// Plusieurs écritures qui vont ensemble : toutes ou aucune. Appelée au sein
// d'une transaction déjà ouverte, elle en fait partie.
export function transaction(db, fn) {
  if (db.isTransaction) return fn();
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export class Parc {
  constructor(db, { coffre, horsLigneApres = 120 }) {
    this.db = db; this.coffre = coffre; this.horsLigneApres = horsLigneApres;
  }

  enLigne(lastReport) { return (secondes() - (lastReport || 0)) < this.horsLigneApres; }

  // Entier interne d'une machine à partir de sa référence publique ; null pour
  // une référence inconnue. Toute route qui désigne une machine passe par là.
  idDe(ref) { return REF.test(String(ref)) ? this.db.prepare('SELECT id FROM machines WHERE ref = ?').get(ref)?.id ?? null : null; }
  machine(id) { return this.db.prepare('SELECT * FROM machines WHERE id = ?').get(id) || null; }
  machineParRef(ref) { const id = this.idDe(ref); return id ? this.machine(id) : null; }

  // ---- consoles : liste publique sans aucun secret ----
  consolesPubliques(items) {
    return (items || []).map(it => {
      const { vncpw_scelle, ...pub } = it;
      if (it.type === 'vnc') pub.a_mdp = !!vncpw_scelle;
      return pub;
    });
  }

  consolesEffectives(m) {
    let items = [];
    try { items = m.consoles ? JSON.parse(m.consoles) : []; } catch { items = []; }
    return items;
  }

  machinePublique(m) {
    const consoles = this.consolesEffectives(m);
    let inv = null, softN = 0, majN = 0;
    try { inv = m.inventory ? JSON.parse(m.inventory) : null; } catch { inv = null; }
    try { softN = m.software ? JSON.parse(m.software).length : 0; } catch { softN = 0; }
    try { majN = m.updates ? JSON.parse(m.updates).length : 0; } catch { majN = 0; }
    const online = m.source === 'agent' ? this.enLigne(m.last_report) : false;
    return {
      id: m.ref, host: m.host, ip: m.ip || '', site: m.site, os: m.os || '', oskind: m.oskind,
      role: m.role, online, risk: m.risk, cpu: m.cpu, ram: m.ram, disk: m.disk,
      av: m.av, fw: m.fw, enc: m.enc, patch: m.patch, seen: m.last_report || null,
      hist: (() => { try { return JSON.parse(m.hist); } catch { return []; } })(),
      source: m.source, mesh_node: m.mesh_node || null,
      consoles: this.consolesPubliques(consoles),
      inventory: inv, software_n: softN, updates_n: majN, inv_at: m.inv_at || null,
      mac: m.mac || '', wol: !!m.mac,
      redfish: !!(m.rf_user && m.rf_secret), rf_user: m.rf_user || '', rf_url: m.rf_url || '',
      rf_pin: !!m.rf_fp,
    };
  }

  etat() {
    const rows = this.db.prepare('SELECT * FROM machines ORDER BY id').all();
    const parId = new Map(rows.map(r => [r.id, r]));
    const machines = rows.map(r => this.machinePublique(r));
    // Toutes les alertes ouvertes, et les résolues de la semaine : de quoi voir
    // ce qui vient de rentrer dans l'ordre sans que la liste grossisse sans fin.
    const alertes = this.db.prepare(`SELECT * FROM alertes WHERE etat = 'ouverte'
        OR (etat = 'resolue' AND resolue > ?) ORDER BY etat = 'resolue', cree DESC LIMIT 500`).all(secondes() - 7 * 86400).map(a => {
      const h = parId.get(a.machine_id);
      return {
        id: a.ref, regle: a.regle || null, sev: a.sev, txt: a.txt, etat: a.etat, cree: a.cree, resolue: a.resolue || null,
        acquittee: a.acquittee || null, acquitte_par: a.acquitte_par || '',
        machine: h ? { id: h.ref, host: h.host, ip: h.ip, oskind: h.oskind } : null,
      };
    });
    const feed = this.db.prepare('SELECT texte, ip, cree FROM flux ORDER BY cree DESC LIMIT 8').all()
      .map(f => ({ html: f.texte, ip: f.ip || '', cree: f.cree }));
    const patches = this.correctifs(rows);
    return { machines, alertes, patches, autos: this.automatisations(), feed, intervalle: null };
  }

  // Résumé léger pour les sondes du Hub : des comptes, jamais l'état complet.
  resume() {
    const machines = this.db.prepare("SELECT COUNT(*) n FROM machines WHERE source = 'agent'").get().n;
    const now = secondes();
    const enLigne = this.db.prepare("SELECT COUNT(*) n FROM machines WHERE source = 'agent' AND last_report > ?").get(now - this.horsLigneApres).n;
    const alertes = this.db.prepare("SELECT COUNT(*) n FROM alertes WHERE etat = 'ouverte'").get().n;
    const enAttente = this.db.prepare("SELECT COUNT(*) n FROM taches WHERE status = 'attente'").get().n;
    return { machines, en_ligne: enLigne, hors_ligne: machines - enLigne, alertes, taches_en_attente: enAttente };
  }

  // Correctifs et vulnérabilités dérivés de ce que les agents rapportent
  // vraiment (winget / Windows Update / apt / softwareupdate) : rien d'inventé.
  correctifs(rows) {
    const agg = new Map();
    for (const r of rows) {
      if (r.source !== 'agent' || !r.updates) continue;
      let items; try { items = JSON.parse(r.updates); } catch { continue; }
      for (const u of items) {
        const cle = (u.name || '').slice(0, 120) + '|' + (u.kind || 'Système');
        const e = agg.get(cle) || { name: (u.name || '').slice(0, 120), kind: u.kind || 'Système', n: 0, sec: false, vers: new Set() };
        e.n++; e.sec = e.sec || !!u.security;
        if (u.available) e.vers.add(String(u.available).slice(0, 32));
        agg.set(cle, e);
      }
    }
    return [...agg.values()].map(v => ({
      n: v.name, t: v.kind, c: v.n,
      crit: v.sec ? 'Critique' : (v.kind === 'Système' ? 'Important' : 'Moyen'),
      ver: [...v.vers].slice(0, 2).join(', '),
    })).sort((a, b) => (a.crit !== 'Critique') - (b.crit !== 'Critique') || b.c - a.c || a.n.localeCompare(b.n)).slice(0, 400);
  }

  // ---- flux d'activité ----
  pousser(texte, ip = '') {
    this.db.prepare('INSERT INTO flux(texte, ip, cree) VALUES(?,?,?)').run(String(texte).slice(0, 400), ip || null, secondes());
    this.db.prepare('DELETE FROM flux WHERE id NOT IN (SELECT id FROM flux ORDER BY cree DESC LIMIT 60)').run();
    return { html: String(texte).slice(0, 400), ip: ip || '', cree: secondes() };
  }

  // ---- tâches ----
  // La création en refuse au-delà de MAX_AUTOMATISATIONS : la liste reste bornée.
  automatisations() {
    return this.db.prepare('SELECT * FROM automatisations ORDER BY id LIMIT ?').all(MAX_AUTOMATISATIONS).map(a => this.autoPublique(a));
  }
  autoPublique(a) {
    return {
      id: a.ref, nom: a.nom, kind: a.kind, payload: a.payload || '', cible: a.cible, cible_val: a.cible_val || '',
      toutes_h: a.toutes_h, heure: a.heure, actif: !!a.actif, dernier_run: a.dernier_run || null,
      dernier_statut: a.dernier_statut || '', runs: a.runs || 0,
    };
  }
  // Une commande libre n'est rendue à personne ; ce qu'elle a affiché, à un
  // administrateur seulement, comme la commande elle-même ne part que de lui.
  tachePublique(t, { admin = false } = {}) {
    return { id: t.ref, kind: t.kind, payload: t.sensible ? '' : t.payload, status: t.status, output: t.sensible && !admin ? '' : t.output || '', rc: t.rc, cree: t.cree, fin: t.fin, auteur: t.auteur || '' };
  }

  // ---- écriture des consoles, avec scellage des mots de passe VNC ----
  // Scelle tout mot de passe VNC (clé « vncpw » en clair → « vncpw_scelle »),
  // et préserve un mot de passe déjà scellé quand le client ré-enregistre sans
  // le retaper (l'UI ne renvoie jamais le secret). Le pin épinglé est préservé.
  enregistrerConsoles(machineId, items) {
    const m = this.machine(machineId);
    if (!m) return false;
    const anciens = this.consolesEffectives(m);
    const parCle = new Map(anciens.map(o => [`${o.type}|${o.target}|${o.label}`, o]));
    const out = items.map(it => {
      const cle = `${it.type}|${it.target}|${it.label}`;
      const avant = parCle.get(cle);
      const e = { type: it.type, target: it.target, label: it.label, embed: it.embed };
      if (avant?.pin) e.pin = avant.pin;                 // pin épinglé conservé
      if (it.type === 'vnc') {
        if (it.vncpw) e.vncpw_scelle = this.coffre.scelle('console-vnc', it.vncpw, m.ref + '|' + it.target);
        else if (avant?.vncpw_scelle) e.vncpw_scelle = avant.vncpw_scelle;
      }
      return e;
    });
    this.db.prepare('UPDATE machines SET consoles = ? WHERE id = ?').run(JSON.stringify(out), machineId);
    return true;
  }

  entreeConsole(machineId, idx) {
    const m = this.machine(machineId);
    if (!m) return null;
    const items = this.consolesEffectives(m);
    return (idx >= 0 && idx < items.length) ? items[idx] : null;
  }

  ouvrirVncPw(item, ref) {
    if (!item?.vncpw_scelle) return '';
    try { return this.coffre.ouvre('console-vnc', item.vncpw_scelle, ref + '|' + item.target); } catch { return ''; }
  }

  poserPinConsole(machineId, idx, pin) {
    const m = this.machine(machineId);
    const items = this.consolesEffectives(m);
    if (!items[idx]) return false;
    items[idx] = { ...items[idx], pin };
    this.db.prepare('UPDATE machines SET consoles = ? WHERE id = ?').run(JSON.stringify(items), machineId);
    return true;
  }

  // ---- Redfish : identifiants scellés, empreinte du certificat épinglée ----
  poserRedfish(machineId, { url, user, password }) {
    const m = this.machine(machineId);
    if (!m) return false;
    if (!user && !password) {
      this.db.prepare('UPDATE machines SET rf_url=NULL, rf_user=NULL, rf_secret=NULL, rf_fp=NULL WHERE id=?').run(machineId);
      return true;
    }
    const secret = this.coffre.scelle('redfish', password, m.ref);
    this.db.prepare('UPDATE machines SET rf_url=?, rf_user=?, rf_secret=? WHERE id=?').run(url || null, user, secret, machineId);
    return true;
  }
  poserPinRedfish(machineId, pin) {
    this.db.prepare('UPDATE machines SET rf_fp=? WHERE id=?').run(JSON.stringify(pin), machineId);
  }
  // L'adresse Redfish posée, sinon celle de la console iDRAC, iLO ou IPMI.
  redfishBase(m) {
    return m.rf_url || this.consolesEffectives(m).find(c => ['idrac', 'ilo', 'ipmi'].includes(c.type))?.target || null;
  }
  // (base, user, password, pin) pour joindre la carte, ou null si non configuré.
  redfishConf(m) {
    if (!m.rf_user || !m.rf_secret) return null;
    const base = this.redfishBase(m);
    if (!base) return null;
    let password; try { password = this.coffre.ouvre('redfish', m.rf_secret, m.ref); } catch { return null; }
    let pin = null; try { pin = m.rf_fp ? JSON.parse(m.rf_fp) : null; } catch { pin = null; }
    return { base, user: m.rf_user, password, pin };
  }

  supprimer(machineId) {
    this.db.prepare('DELETE FROM machines WHERE id = ?').run(machineId);
  }

  // Rotation de SOCLE_CLE : le socle rescelle les secrets TOTP, Sentinel les
  // siens (mots de passe VNC, identifiants Redfish), au même démarrage. Un secret
  // qui s'ouvre sous la clé actuelle est laissé tel quel ; sous l'ancienne, il
  // est rescellé. Illisible sous l'une comme l'autre :
  //   - sans SOCLE_CLE_ANCIENNE posée, le démarrage s'arrête (un arrêt entre la
  //     rotation du socle et celle-ci, puis l'ancienne clé retirée trop tôt :
  //     la reposer suffit, rien n'est perdu) ;
  //   - avec elle, le secret est corrompu : il est retiré, et le journal le dit,
  //     plutôt que de bloquer le service pour un mot de passe qui se ressaisit.
  // Tout ou rien, en une transaction.
  resceller() {
    const avant = this.coffre.precedente;
    const bilan = { vnc: 0, redfish: 0, retires: 0 };
    const rouvrir = (usage, scelle, aad) => {
      try { this.coffre.ouvre(usage, scelle, aad); return { etat: 'actuel' }; } catch { /* scellé sous une autre clé */ }
      try { if (avant) return { etat: 'ancien', clair: avant.ouvre(usage, scelle, aad) }; } catch { /* illisible aussi sous l'ancienne */ }
      if (!avant) throw new Error('Un secret d\'appareil (VNC ou Redfish) est illisible sous SOCLE_CLE : repose la clé remplacée dans SOCLE_CLE_ANCIENNE le temps d\'un démarrage.');
      return { etat: 'illisible' };
    };
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const m of this.db.prepare('SELECT id, ref, consoles, rf_secret FROM machines WHERE consoles IS NOT NULL OR rf_secret IS NOT NULL').all()) {
        const items = this.consolesEffectives(m);
        let change = false;
        for (const it of items) {
          if (!it.vncpw_scelle) continue;
          const aad = m.ref + '|' + it.target;
          const r = rouvrir('console-vnc', it.vncpw_scelle, aad);
          if (r.etat === 'ancien') { it.vncpw_scelle = this.coffre.scelle('console-vnc', r.clair, aad); bilan.vnc++; change = true; }
          if (r.etat === 'illisible') { delete it.vncpw_scelle; bilan.retires++; change = true; }
        }
        if (change) this.db.prepare('UPDATE machines SET consoles = ? WHERE id = ?').run(JSON.stringify(items), m.id);
        if (m.rf_secret) {
          const r = rouvrir('redfish', m.rf_secret, m.ref);
          if (r.etat === 'ancien') { this.db.prepare('UPDATE machines SET rf_secret = ? WHERE id = ?').run(this.coffre.scelle('redfish', r.clair, m.ref), m.id); bilan.redfish++; }
          if (r.etat === 'illisible') { this.db.prepare('UPDATE machines SET rf_secret = NULL WHERE id = ?').run(m.id); bilan.retires++; }
        }
      }
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    return bilan;
  }

  // Ce que le parc garde d'un compte : les tâches qu'il a lancées et les
  // alertes qu'il a acquittées (le parc lui-même est partagé, il n'est à
  // personne). Exporté à sa demande, neutralisé à sa suppression : la trace
  // d'audit, elle, reste au journal de sécurité du socle.
  donneesDe(compteId) {
    return {
      taches_lancees: this.db.prepare(`SELECT t.ref, t.kind, t.payload, t.sensible, t.status, t.cree, t.fin, m.host FROM taches t
          LEFT JOIN machines m ON m.id = t.machine_id WHERE t.auteur_compte = ? ORDER BY t.id`).all(compteId)
        .map(t => ({ id: t.ref, machine: t.host || null, kind: t.kind, payload: t.sensible ? '' : t.payload, status: t.status, cree: t.cree, fin: t.fin })),
      alertes_acquittees: this.db.prepare(`SELECT a.ref, a.regle, a.txt, a.acquittee, m.host FROM alertes a
          LEFT JOIN machines m ON m.id = a.machine_id WHERE a.acquitte_compte = ? ORDER BY a.id`).all(compteId)
        .map(a => ({ id: a.ref, machine: a.host || null, regle: a.regle, txt: a.txt, acquittee: a.acquittee })),
    };
  }
  oublier(compteId) {
    this.db.prepare("UPDATE taches SET auteur = 'compte supprimé', auteur_compte = NULL WHERE auteur_compte = ?").run(compteId);
    this.db.prepare("UPDATE alertes SET acquitte_par = 'compte supprimé', acquitte_compte = NULL WHERE acquitte_compte = ?").run(compteId);
  }
}

export { secondes, echappeLike };
