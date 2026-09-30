// Tâches à distance et automatisations.
//
// Types autorisés en liste fermée. Une commande libre (« cmd ») exige le rôle
// admin et un renfort récent (contrôlé dans l'API) ; les autres restent à la
// portée d'un membre. Chaque tâche créée et chaque résultat sont journalisés,
// sans jamais le contenu sensible (la charge d'une commande libre n'est pas
// écrite en clair). Un agent ne relève et ne répond qu'à SES tâches : l'agent
// est identifié par son jeton, jamais par un nom qu'il choisit.
import { nouvelleRef, secondes } from './base.js';

export const KINDS = new Set(['cmd', 'install', 'uninstall', 'inventory', 'update', 'wol']);
export const CIBLES = new Set(['tous', 'site', 'host', 'oskind']);
// Ce qu'un opérateur, une automatisation ou le Hub peut demander. « wol » n'en
// fait pas partie : seule la route de réveil en crée, avec l'adresse MAC et la
// diffusion qu'elle calcule elle-même.
export const DEMANDES = ['cmd', 'install', 'uninstall', 'inventory', 'update'];
// Le motif de l'agent (PAQUET dans sentinel-agent.py) : un nom de paquet ne
// commence jamais par un tiret, il ne peut pas devenir une option.
export const PAQUET = /^[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,120}$/;

// Message d'erreur si la charge ne convient pas à son type, sinon null.
export function chargeRefusee(kind, payload) {
  if (kind === 'inventory') return payload ? 'L\'inventaire ne prend aucune charge.' : null;
  if (kind === 'update') return payload && !PAQUET.test(payload) ? 'Nom de paquet invalide.' : null;
  if (kind === 'install' || kind === 'uninstall') return PAQUET.test(payload) ? null : 'Nom de paquet invalide.';
  if (kind === 'cmd') return payload ? null : 'Commande manquante.';
  return 'Type de tâche non admis.';
}

export class Taches {
  constructor(db, { parc, synapse, journal, flux, commandeLibre = false }) {
    this.db = db; this.parc = parc; this.synapse = synapse; this.journal = journal; this.flux = flux; this.commandeLibre = commandeLibre;
  }

  // auteur : ce qui s'affiche (identifiant, « hub »), auteurCompte : le compte
  // du socle, qui permet d'exporter et d'effacer ce qui se rattache à lui.
  creer(machineId, { kind, payload = '', auteur, auteurCompte = null, sensible = false }) {
    const ref = nouvelleRef();
    const t = secondes();
    this.db.prepare(`INSERT INTO taches(ref, machine_id, kind, payload, sensible, status, cree, auteur, auteur_compte)
      VALUES(?,?,?,?,?,'attente',?,?,?)`).run(ref, machineId, kind, payload, sensible ? 1 : 0, t, auteur || null, auteurCompte);
    // Trace d'exécution : toujours traçable, jamais le contenu d'une commande libre.
    this.journal?.ecrire({ acteur: auteurCompte || auteur || null, action: 'tache.creee', objet: this.parc.machine(machineId)?.host || null, details: { kind, ...(sensible ? {} : { apercu: String(payload).slice(0, 80) }) } });
    return this.db.prepare('SELECT * FROM taches WHERE ref = ?').get(ref);
  }

  liste(machineId, limite = 25) {
    return this.db.prepare('SELECT * FROM taches WHERE machine_id = ? ORDER BY id DESC LIMIT ?').all(machineId, Math.max(1, Math.min(limite, 100)));
  }
  enAttente(machineId) {
    return this.db.prepare("SELECT COUNT(*) n FROM taches WHERE machine_id = ? AND status = 'attente'").get(machineId).n;
  }

  // Relève par l'agent : uniquement les tâches de SA machine.
  relever(machineId, delaiTache) {
    const rows = this.db.prepare("SELECT * FROM taches WHERE machine_id = ? AND status = 'attente' ORDER BY id LIMIT 5").all(machineId);
    const now = secondes();
    for (const r of rows) this.db.prepare("UPDATE taches SET status='cours', debut=? WHERE id=?").run(now, r.id);
    // Clé « jobs » : le contrat que l'agent (et l'UI) attendent.
    return { jobs: rows.map(r => ({ id: r.ref, kind: r.kind, payload: r.payload })), timeout: delaiTache };
  }

  resultat(ref, machineId, output, rc) {
    const r = this.db.prepare('SELECT * FROM taches WHERE ref = ? AND machine_id = ?').get(ref, machineId);
    if (!r) return false;
    const now = secondes();
    this.db.prepare("UPDATE taches SET status=?, output=?, rc=?, fin=? WHERE id=?")
      .run(rc === 0 ? 'fait' : 'echec', String(output || '').slice(0, 200000), rc, now, r.id);
    const m = this.parc.machine(machineId);
    this.journal?.ecrire({ action: 'tache.resultat', objet: m?.host || null, resultat: rc === 0 ? 'ok' : 'erreur', details: { kind: r.kind, rc } });
    // À SYNAPSE, l'origine seulement, jamais l'identifiant d'un opérateur.
    const origine = r.auteur === 'hub' ? 'le Hub' : String(r.auteur || '').startsWith('auto:') ? `l'automatisation ${r.auteur.slice(5)}` : 'un opérateur';
    if (m) this.synapse?.tacheFinie(m.host, r.kind, rc, origine);
    return true;
  }

  // ---- automatisations ----
  ciblesDe(row) {
    let q = "SELECT id FROM machines WHERE source = 'agent'";
    const args = [];
    if (row.cible === 'site') { q += ' AND site = ?'; args.push(row.cible_val); }
    else if (row.cible === 'host') { q += ' AND host = ?'; args.push(row.cible_val); }
    else if (row.cible === 'oskind') { q += ' AND oskind = ?'; args.push(row.cible_val); }
    return this.db.prepare(q).all(...args).map(r => r.id);
  }

  lancer(row, { acteur = null, now = secondes() } = {}) {
    const ids = this.ciblesDe(row);
    const sensible = row.kind === 'cmd';
    for (const mid of ids) {
      const ref = nouvelleRef();
      this.db.prepare("INSERT INTO taches(ref, machine_id, kind, payload, sensible, status, cree, auteur) VALUES(?,?,?,?,?,'attente',?,?)")
        .run(ref, mid, row.kind, row.payload || '', sensible ? 1 : 0, now, `auto:${row.nom}`);
    }
    this.db.prepare('UPDATE automatisations SET dernier_run=?, runs=runs+1, dernier_statut=? WHERE id=?')
      .run(now, ids.length ? `${ids.length} poste(s)` : 'aucun poste', row.id);
    this.journal?.ecrire({ acteur, action: 'automatisation.lancee', objet: row.nom, details: { kind: row.kind, postes: ids.length } });
    if (ids.length) this.synapse?.automatisation(row.nom, row.kind, ids.length);
    return ids.length;
  }

  // Toutes les minutes : les automatisations dues sont lancées. Une commande
  // libre ne part que si SENTINEL_ALLOW_EXEC l'autorise encore : une
  // automatisation créée avant qu'on la désactive (ou reprise de la 1.x) attend.
  tour() {
    const now = secondes();
    const heure = new Date().getHours();
    for (const row of this.db.prepare("SELECT * FROM automatisations WHERE actif = 1 AND (kind <> 'cmd' OR ?)").all(this.commandeLibre ? 1 : 0)) {
      const due = (now - (row.dernier_run || 0)) >= row.toutes_h * 3600;
      if (row.toutes_h >= 24 && heure !== (row.heure || 0)) continue;
      if (due) this.lancer(row, { now });
    }
  }
}
