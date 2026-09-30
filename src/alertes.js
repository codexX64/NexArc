// Alertes dérivées de ce que les agents remontent et de la collecte.
//
// Une alerte naît d'une règle appliquée à une machine : au plus UNE alerte
// ouverte par (machine, règle) — l'index unique partiel de la table le garantit
// même si deux évaluations se croisaient. Tant que la condition dure, l'alerte
// reste ouverte (son texte suit la valeur mesurée) ; quand la condition
// disparaît, elle se résout d'elle-même, horodatée. L'acquittement dit « vu,
// pris en charge » : il ne ferme pas une alerte dont la cause est toujours là,
// sauf une alerte sans règle (reprise de la 1.x), qu'aucune mesure ne résoudra.
//
// Une valeur que l'agent n'a pas su lire (« inconnu », vide) ne change rien :
// ni ouverture sur une supposition, ni résolution sur un silence.
import { nouvelleRef, secondes, transaction } from './base.js';

const GARDE_RESOLUES_J = 30;

// Seuils : lus dans la configuration (SENTINEL_ALERT_*), voir config.js.
const REGLES = {
  'hors-ligne': { sev: 'crit', libelle: 'Machine hors ligne' },
  antivirus: { sev: 'crit', libelle: 'Antivirus absent ou inactif' },
  'pare-feu': { sev: 'warn', libelle: 'Pare-feu inactif' },
  chiffrement: { sev: 'warn', libelle: 'Disque non chiffré' },
  correctifs: { sev: 'warn', libelle: 'Correctifs de sécurité en attente' },
  disque: { sev: 'warn', libelle: 'Disque presque plein' },
  risque: { sev: 'warn', libelle: 'Score de risque élevé' },
};

const AV_EN_DEFAUT = new Set(['absent', 'inactif']);

export class Alertes {
  constructor(db, { seuils, parc, flux = null, synapse = null }) {
    this.db = db; this.seuils = seuils; this.parc = parc; this.flux = flux; this.synapse = synapse;
  }

  // Règles de posture : { règle → texte } pour celles dont la condition est
  // vraie, null pour celles qui sont évaluables et fausses. Une règle absente
  // de la réponse n'est pas évaluable avec ce que l'agent a remonté.
  posture(m, now = secondes()) {
    const s = this.seuils, etat = {};
    const av = String(m.av || '').trim();
    if (av && av !== 'inconnu') etat.antivirus = AV_EN_DEFAUT.has(av) ? `Antivirus ${av}.` : null;
    const fw = String(m.fw || '').trim();
    if (fw && fw !== 'inconnu') etat['pare-feu'] = fw === 'inactif' ? 'Pare-feu inactif.' : null;
    const enc = String(m.enc || '').trim();
    if (enc && enc !== 'inconnu') etat.chiffrement = enc === 'non chiffré' ? 'Disque système non chiffré.' : null;
    etat.correctifs = (m.sec_depuis && now - m.sec_depuis > s.correctifsJours * 86400)
      ? `${m.sec_n || 0} correctif(s) de sécurité en attente depuis plus de ${s.correctifsJours} jour(s).` : null;
    etat.disque = m.disk >= s.disquePct ? `Disque rempli à ${m.disk} % (seuil ${s.disquePct} %).` : null;
    etat.risque = m.risk >= s.risque ? `Score de risque ${m.risk} (seuil ${s.risque}).` : null;
    return etat;
  }

  horsLigne(m, now = secondes()) {
    const silence = now - (m.last_report || 0);
    return silence > this.seuils.horsLigneMin * 60 ? `Aucune remontée depuis ${Math.floor(silence / 60)} min.` : null;
  }

  // Après une remontée : posture et présence.
  evaluer(machineId, now = secondes()) {
    const m = this.parc.machine(machineId);
    if (!m || m.source !== 'agent') return;
    this.appliquer(m, { ...this.posture(m, now), 'hors-ligne': this.horsLigne(m, now) }, now);
  }

  // Tour de collecte : seule la présence change sans remontée.
  evaluerPresence(now = secondes()) {
    for (const m of this.db.prepare("SELECT * FROM machines WHERE source = 'agent'").all()) {
      this.appliquer(m, { 'hors-ligne': this.horsLigne(m, now) }, now);
    }
  }

  appliquer(m, etat, now) {
    for (const [regle, texte] of Object.entries(etat)) {
      const ouverte = this.db.prepare("SELECT * FROM alertes WHERE machine_id = ? AND regle = ? AND etat = 'ouverte'").get(m.id, regle);
      if (texte && !ouverte) this.ouvrir(m, regle, texte, now);
      else if (texte && ouverte.txt !== texte) this.db.prepare('UPDATE alertes SET txt = ?, maj = ? WHERE id = ?').run(texte, now, ouverte.id);
      else if (!texte && ouverte) this.resoudre(m, ouverte, now);
    }
  }

  ouvrir(m, regle, texte, now) {
    const ref = nouvelleRef(), sev = REGLES[regle].sev;
    const r = this.db.prepare(`INSERT INTO alertes(ref, regle, sev, txt, machine_id, etat, cree, maj)
      VALUES(?,?,?,?,?,'ouverte',?,?) ON CONFLICT DO NOTHING`).run(ref, regle, sev, texte, m.id, now, now);
    if (!r.changes) return;
    this.annoncer('ouverte', { ref, regle, sev, txt: texte, cree: now }, m, `Alerte ouverte sur ${m.host} : ${texte}`);
    this.synapse?.alerteOuverte(m.host, regle, texte, sev);
  }

  resoudre(m, a, now) {
    this.db.prepare("UPDATE alertes SET etat = 'resolue', resolue = ?, maj = ? WHERE id = ? AND etat = 'ouverte'").run(now, now, a.id);
    this.annoncer('resolue', { ...a, resolue: now }, m, `Alerte résolue sur ${m.host} : ${REGLES[a.regle]?.libelle || a.txt}.`);
    this.synapse?.alerteResolue(m.host, a.regle, a.txt, Math.round(now - a.cree));
  }

  annoncer(etat, a, m, ligne) {
    if (!this.flux) return;
    this.flux.pousser({ t: 'alerte', etat, alerte: { id: a.ref, regle: a.regle, sev: a.sev, txt: a.txt, cree: a.cree, resolue: a.resolue || null, machine: { id: m.ref, host: m.host } } });
    this.flux.pousser({ t: 'flux', ...this.parc.pousser(ligne, m.ip || '') });
  }

  // Acquittement par un opérateur. Renvoie false pour une référence inconnue.
  acquitter(ref, { identifiant, compte }, now = secondes()) {
    const a = this.db.prepare('SELECT * FROM alertes WHERE ref = ?').get(ref);
    if (!a) return false;
    if (a.acquittee) return true;
    transaction(this.db, () => {
      this.db.prepare('UPDATE alertes SET acquittee = ?, acquitte_par = ?, acquitte_compte = ?, maj = ? WHERE id = ?').run(now, identifiant, compte, now, a.id);
      if (!a.regle && a.etat === 'ouverte') this.db.prepare("UPDATE alertes SET etat = 'resolue', resolue = ? WHERE id = ?").run(now, a.id);
    });
    return true;
  }

  purger(now = secondes()) {
    this.db.prepare("DELETE FROM alertes WHERE etat = 'resolue' AND resolue < ?").run(now - GARDE_RESOLUES_J * 86400);
  }
}

// Correctifs de sécurité en attente d'après la liste remontée : combien, et
// depuis quand sans interruption (la date du premier constat est gardée tant
// que la liste en contient au moins un).
export function suiviCorrectifs(updates, avant, now = secondes()) {
  const n = updates.filter(u => u && typeof u === 'object' && u.security === true).length;
  return { sec_n: n, sec_depuis: n ? (avant || now) : null };
}
