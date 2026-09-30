// Ce que Sentinel raconte à SYNAPSE, tout seul : une machine réelle enrôlée,
// perdue de vue ou revenue ; une alerte ouverte ou résolue ; le résultat d'une
// tâche (jamais sa sortie) ; chaque passage d'une automatisation ; un réveil ou
// une action d'alimentation demandés par un opérateur.
//
// Le Hub pose SYNAPSE_URL et un jeton de cerveau quand SYNAPSE est installé.
// Sans eux, rien ne part et rien ne casse. Les envois passent par une file
// bornée vidée en arrière-plan : SYNAPSE lent ou absent ne ralentit jamais une
// remontée d'agent.
const FILE_MAX = 300, LOT = 50;

export class Synapse {
  constructor({ url, jeton, log = console }) {
    this.url = url; this.jeton = jeton; this.log = log;
    this.file = []; this.attente = 5000; this.minuterie = null; this.pannes = new Map();
    this.etat = { envoyes: 0, echecs: 0, perdus: 0, dernierEnvoi: null, erreur: null };
  }
  get pret() { return !!(this.url && this.jeton); }

  raconter(kind, titre, { corps = '', tags = [], meta = null } = {}) {
    if (!this.pret) return;
    const e = { kind, title: String(titre).slice(0, 300), tags: [...new Set(['sentinel', ...tags])].sort(), occurred_at: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z') };
    if (corps) e.body = String(corps).slice(0, 2000);
    if (meta) e.meta = meta;
    this.file.push(e);
    while (this.file.length > FILE_MAX) { this.file.shift(); this.etat.perdus++; }
    if (!this.minuterie) this.minuterie = setTimeout(() => this.vider(), 2000).unref();
  }

  async vider() {
    const lot = this.file.slice(0, LOT);
    try {
      // Aucune redirection suivie : le jeton ne part qu'à l'adresse configurée.
      const r = await fetch(`${this.url}/v1/ingest/batch`, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json', authorization: `Bearer ${this.jeton}` }, body: JSON.stringify({ events: lot }), signal: AbortSignal.timeout(15000) });
      if (!r.ok) throw new Error(`SYNAPSE ${r.status}`);
      this.file.splice(0, lot.length);
      Object.assign(this.etat, { envoyes: this.etat.envoyes + lot.length, dernierEnvoi: new Date().toISOString(), erreur: null });
      this.attente = 5000;
      this.minuterie = this.file.length ? setTimeout(() => this.vider(), 2000).unref() : null;
    } catch (e) {
      this.etat.echecs++; this.etat.erreur = String(e.message).slice(0, 160);
      this.minuterie = setTimeout(() => this.vider(), this.attente).unref();
      this.attente = Math.min(300000, this.attente * 2);
    }
  }

  _uneFois(cle, fenetre = 600000) {
    const t = Date.now();
    if (t - (this.pannes.get(cle) || 0) < fenetre) return false;
    this.pannes.set(cle, t); return true;
  }

  machineEnrolee(host, os, site, ip) {
    this.raconter('machine.enrolled', `Nouvelle machine enrôlée : ${host}`, { corps: `${os || 'OS inconnu'} · site ${site || '—'} · ${ip}`, tags: ['machine', 'enrolement'], meta: { host, site: site || '' } });
  }
  machinePerdue(host, site) {
    if (!this._uneFois('perdue:' + host)) return;
    this.raconter('machine.offline', `${host} ne répond plus`, { corps: `Plus aucun rapport d'agent. Site ${site || '—'}.`, tags: ['machine', 'panne'], meta: { host } });
  }
  machineRevenue(host, site) {
    this.raconter('machine.recovered', `${host} répond de nouveau`, { corps: `L'agent a repris ses rapports. Site ${site || '—'}.`, tags: ['machine', 'retabli'], meta: { host } });
  }
  tacheFinie(host, kind, rc, origine) {
    const ok = rc === 0;
    this.raconter(ok ? 'job.done' : 'job.failed', `Tâche ${kind} ${ok ? 'terminée' : 'en échec'} sur ${host}${ok ? '' : ` (code ${rc})`}`, { corps: `Lancée par ${origine}.`, tags: ['tache', ok ? 'ok' : 'echec'], meta: { host, kind, rc } });
  }
  automatisation(nom, kind, postes) {
    this.raconter('automation.run', `Automatisation « ${nom} » lancée sur ${postes} poste(s)`, { corps: `Action : ${kind}.`, tags: ['automatisation'], meta: { nom, kind, postes } });
  }
  reveil(host, methodes) {
    this.raconter('machine.wake', `Réveil envoyé à ${host}`, { corps: 'Par ' + methodes.join(', ') + '.', tags: ['reveil'], meta: { host } });
  }
  alimentation(host, action) {
    this.raconter('machine.power', `Alimentation : ${action} demandé sur ${host}`, { tags: ['alimentation'], meta: { host, action } });
  }
  alerteOuverte(host, regle, texte, sev) {
    this.raconter('alert.opened', `Alerte sur ${host} : ${texte}`, { tags: ['alerte', regle, sev], meta: { host, regle, sev } });
  }
  alerteResolue(host, regle, texte, dureeS) {
    this.raconter('alert.resolved', `Alerte résolue sur ${host} (${regle})`, { corps: `${texte} Durée : ${Math.round(dureeS / 60)} min.`, tags: ['alerte', regle, 'retabli'], meta: { host, regle, duree_s: dureeS } });
  }
}
