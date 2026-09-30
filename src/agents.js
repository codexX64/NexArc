// Enrôlement des agents et remontées.
//
// Chaque agent a SON jeton, jamais un secret partagé (défaut corrigé de la
// 1.x) : un code d'inscription court, à usage unique et lié à un site, s'échange
// contre un jeton propre à l'agent. Ce jeton n'est gardé que haché ; il désigne
// la machine, si bien qu'un agent ne relève et ne répond qu'à SES tâches.
//
// L'inventaire remonté est borné par schéma (voir S.ingest dans api.js) : ni liste
// démesurée, ni texte sans fin.
import crypto from 'node:crypto';
import { sha256hex } from '../socle/src/index.js';
import { nouvelleRef, secondes, transaction } from './base.js';
import { normaliserMac } from './wol.js';
import { suiviCorrectifs } from './alertes.js';

const CODE_TTL_MS = 60 * 60e3;       // un code d'inscription vaut une heure
const JETON_TTL_MS = 24 * 3600e3;    // un jeton minté attend une remontée un jour

const hashJeton = t => sha256hex('agent:' + t);
// Un code d'inscription n'est gardé que par son empreinte : une lecture de la
// base ne donne rien à échanger.
const hashCode = c => sha256hex('inscription:' + c);

export class Agents {
  constructor(db, { parc, maxMachines, synapse, flux, alertes = null }) {
    this.db = db; this.parc = parc; this.maxMachines = maxMachines; this.synapse = synapse; this.flux = flux; this.alertes = alertes;
  }

  purger() {
    const t = secondes();
    this.db.prepare('DELETE FROM enrolements WHERE expire < ?').run(t);
    this.db.prepare('DELETE FROM jetons_attente WHERE expire < ?').run(t);
  }

  nouveauCode({ site = 'Agents', nom = '', relais = false }) {
    this.purger();
    const code = crypto.randomBytes(16).toString('base64url');
    const t = secondes();
    this.db.prepare('INSERT INTO enrolements(empreinte, expire, site, nom, relais, cree) VALUES(?,?,?,?,?,?)')
      .run(hashCode(code), t + CODE_TTL_MS / 1000, site.slice(0, 40) || 'Agents', nom.slice(0, 60), relais ? 1 : 0, t);
    return { code, expire_dans: CODE_TTL_MS / 1000 };
  }

  // Échange un code (usage unique) contre un jeton d'agent. Le jeton n'apparaît
  // qu'ici ; seule son empreinte est gardée. La machine naît à la remontée.
  echanger(code) {
    if (typeof code !== 'string' || code.length > 40) return null;
    const t = secondes();
    const h = hashCode(code);
    // Le code consommé et le jeton tiré, ensemble : jamais l'un sans l'autre.
    return transaction(this.db, () => {
      const l = this.db.prepare('SELECT * FROM enrolements WHERE empreinte = ?').get(h);
      if (l) this.db.prepare('DELETE FROM enrolements WHERE empreinte = ?').run(h);
      if (!l || l.expire < t) return null;
      const jeton = 'sag_' + crypto.randomBytes(24).toString('base64url');
      this.db.prepare('INSERT INTO jetons_attente(jeton_hash, site, nom, relais, expire, cree) VALUES(?,?,?,?,?,?)')
        .run(hashJeton(jeton), l.site, l.nom, l.relais, t + JETON_TTL_MS / 1000, t);
      return { jeton, site: l.site, nom: l.nom, relais: !!l.relais };
    });
  }

  codeValide(code) {
    if (typeof code !== 'string' || code.length > 40) return false;
    const l = this.db.prepare('SELECT expire FROM enrolements WHERE empreinte = ?').get(hashCode(code));
    return !!(l && l.expire >= secondes());
  }

  // La machine d'un jeton d'agent ; pour un jeton sans machine, { attente },
  // sa ligne d'attente (absente si personne ne l'a tiré) : la machine naît à
  // la première remontée. null pour un jeton mal formé.
  resoudre(jeton) {
    if (typeof jeton !== 'string' || jeton.length < 8 || jeton.length > 200) return null;
    const h = hashJeton(jeton);
    const m = this.db.prepare('SELECT * FROM machines WHERE jeton_hash = ?').get(h);
    if (m) return m;
    const attente = this.db.prepare('SELECT * FROM jetons_attente WHERE jeton_hash = ?').get(h);
    // Un jeton en attente expiré est effacé ; l'appelant le refuse sur sa date.
    if (attente && attente.expire < secondes()) this.db.prepare('DELETE FROM jetons_attente WHERE jeton_hash = ?').run(h);
    return { attente };
  }

  // Révocation (ligne de commande, runbook d'incident) : le jeton d'un poste,
  // ou de tout le parc, cesse aussitôt. La machine garde son historique et ses
  // accès ; l'agent se réinscrit avec un nouveau code et la retrouve par son
  // nom d'hôte. Ses tâches encore dues sont abandonnées : elles ne partiront
  // pas vers le prochain détenteur d'un code qui porterait ce nom.
  revoquer({ hote = null, tous = false } = {}) {
    return transaction(this.db, () => {
      const machines = tous
        ? this.db.prepare("SELECT id, host FROM machines WHERE source = 'agent' AND jeton_hash IS NOT NULL ORDER BY host").all()
        : this.db.prepare("SELECT id, host FROM machines WHERE source = 'agent' AND jeton_hash IS NOT NULL AND host = ?").all(hote);
      const t = secondes();
      const bilan = machines.map(m => {
        this.db.prepare('UPDATE machines SET jeton_hash = NULL WHERE id = ?').run(m.id);
        const taches = this.db.prepare("UPDATE taches SET status = 'echec', output = 'Jeton de l''agent révoqué : tâche abandonnée.', fin = ? WHERE machine_id = ? AND status IN ('attente', 'cours')").run(t, m.id).changes;
        return { host: m.host, taches: Number(taches) };
      });
      // Un jeton tiré mais pas encore présenté n'a pas de machine : tout le parc
      // révoqué, il tombe aussi.
      const attente = tous ? Number(this.db.prepare('DELETE FROM jetons_attente').run().changes) : 0;
      return { machines: bilan, attente };
    });
  }

  // Vrai pour le jeton d'une machine, ou d'une machine à naître encore valable.
  jetonConnu(jeton) {
    const r = this.resoudre(jeton);
    return !!(r?.id || r?.attente?.expire >= secondes());
  }

  // Une remontée écrit la machine, son inventaire et ses alertes : tout ou rien.
  ingest(jeton, body) {
    return transaction(this.db, () => this.remonter(jeton, body));
  }

  remonter(jeton, body) {
    const r = this.resoudre(jeton);
    if (!r) return { erreur: 401 };
    const now = secondes();
    if (r.id) return this.majMachine(r, body, now);
    // Première remontée : créer la machine si le jeton en attente est valide.
    const a = r.attente;
    if (!a || a.expire < now) return { erreur: 401 };
    const host = (a.nom || body.hostname).slice(0, 80);
    // Reprise 1.1.0 : une machine importée sans jeton (jeton_hash NULL) qui
    // porte ce nom d'hôte est réadoptée par ce nouveau jeton, gardant son
    // historique et ses consoles. Sinon on en crée une (dans la limite du parc).
    const legacy = this.db.prepare("SELECT * FROM machines WHERE host = ? AND source = 'agent' AND jeton_hash IS NULL").get(host);
    if (legacy) {
      this.db.prepare("UPDATE machines SET jeton_hash = ?, role = CASE WHEN ? THEN 'relais' ELSE role END WHERE id = ?").run(hashJeton(jeton), a.relais, legacy.id);
      this.db.prepare('DELETE FROM jetons_attente WHERE jeton_hash = ?').run(hashJeton(jeton));
      return this.majMachine(this.parc.machine(legacy.id), body, now);
    }
    const n = this.db.prepare("SELECT COUNT(*) n FROM machines WHERE source = 'agent'").get().n;
    if (n >= this.maxMachines) return { erreur: 429 };
    const ref = nouvelleRef();
    // Le rôle vient du code d'inscription, jamais de l'agent : un relais reçoit
    // les réveils des autres machines de son segment.
    const role = a.relais ? 'relais' : 'poste';
    const suivi = Array.isArray(body.updates) ? suiviCorrectifs(body.updates, null, now) : { sec_n: 0, sec_depuis: null };
    this.db.prepare(`INSERT INTO machines(ref, jeton_hash, host, ip, site, os, oskind, role, online, risk,
        cpu, ram, disk, av, fw, enc, patch, sec_n, sec_depuis, hist, source, mesh_node, last_report, cree)
      VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,'agent',?,?,?)`).run(
      ref, hashJeton(jeton), host, body.ip || null, a.site, body.os || '', body.oskind, role, this.risque(body, suivi.sec_n),
      body.cpu, body.ram, body.disk, body.av, body.fw, body.enc, body.patch, suivi.sec_n, suivi.sec_depuis,
      JSON.stringify([body.cpu]), body.mesh_node || null, now, now);
    this.db.prepare('DELETE FROM jetons_attente WHERE jeton_hash = ?').run(hashJeton(jeton));
    const m = this.db.prepare('SELECT * FROM machines WHERE ref = ?').get(ref);
    this.appliquerInventaire(m, body, now);
    this.synapse?.machineEnrolee(m.host, m.os, m.site, m.ip || '');
    this.flux?.(this.parc.pousser(`Nouvel agent enrôlé : ${m.host}.`, body.ip || ''));
    this.alertes?.evaluer(m.id, now);
    return { ok: true };
  }

  majMachine(m, body, now) {
    const revenu = !this.parc.enLigne(m.last_report);
    let hist; try { hist = JSON.parse(m.hist); } catch { hist = []; }
    hist.push(body.cpu); hist = hist.slice(-24);
    const host = m.host && m.host.trim() ? m.host : body.hostname.slice(0, 80);
    // La liste des mises à jour n'arrive qu'un rapport sur douze : entre deux,
    // le suivi des correctifs de sécurité reste celui du dernier constat.
    const suivi = Array.isArray(body.updates) ? suiviCorrectifs(body.updates, m.sec_depuis, now) : { sec_n: m.sec_n || 0, sec_depuis: m.sec_depuis || null };
    this.db.prepare(`UPDATE machines SET host=?, ip=?, os=?, oskind=?,
        cpu=?, ram=?, disk=?, av=?, fw=?, enc=?, patch=?, sec_n=?, sec_depuis=?, risk=?, online=1, hist=?, mesh_node=COALESCE(?, mesh_node), last_report=? WHERE id=?`).run(
      host, body.ip || null, body.os || '', body.oskind,
      body.cpu, body.ram, body.disk, body.av, body.fw, body.enc, body.patch, suivi.sec_n, suivi.sec_depuis, this.risque(body, suivi.sec_n),
      JSON.stringify(hist), body.mesh_node || null, now, m.id);
    this.appliquerInventaire(this.parc.machine(m.id), body, now);
    if (revenu) this.synapse?.machineRevenue(m.host, m.site);
    this.alertes?.evaluer(m.id, now);
    return { ok: true };
  }

  // L'inventaire arrive périodiquement ; chaque champ est déjà borné par le
  // schéma, on borne encore la taille sérialisée avant de l'écrire.
  appliquerInventaire(m, body, now) {
    if (body.inventory !== undefined && body.inventory !== null) {
      this.db.prepare('UPDATE machines SET inventory=?, inv_at=? WHERE id=?')
        .run(JSON.stringify(body.inventory).slice(0, 60000), now, m.id);
      let mac = '';
      for (const nic of (body.inventory.nics || [])) {
        const x = normaliserMac(nic.mac || '');
        if (x && x !== '00:00:00:00:00:00') { mac = x; break; }
      }
      if (mac) this.db.prepare('UPDATE machines SET mac=? WHERE id=?').run(mac, m.id);
    }
    if (body.software !== undefined && body.software !== null) {
      this.db.prepare('UPDATE machines SET software=? WHERE id=?').run(JSON.stringify(body.software).slice(0, 400000), m.id);
    }
    if (body.updates !== undefined && body.updates !== null) {
      this.db.prepare('UPDATE machines SET updates=? WHERE id=?').run(JSON.stringify(body.updates).slice(0, 200000), m.id);
    }
  }

  // Score de risque : seuls les défauts CONSTATÉS comptent. Un état que
  // l'agent n'a pas su lire (« inconnu ») ne pèse rien : le score ne doit pas
  // monter sur une supposition, sans quoi l'alerte de risque en naîtrait.
  risque(body, secN = 0) {
    let r = 10;
    if (body.av === 'absent' || body.av === 'inactif') r += 30;
    else if (body.av === 'obsolète') r += 15;
    if (body.fw === 'inactif') r += 20;
    if (body.enc === 'non chiffré') r += 15;
    r += Math.min(25, secN * 5);
    return Math.min(99, r);
  }

  // Boucle de fond : marque hors ligne ce qui a cessé de remonter, sans jamais
  // inventer de métrique. Renvoie la liste des lignes de flux à diffuser.
  collecter() {
    const now = secondes();
    const lignes = [];
    for (const m of this.db.prepare("SELECT id, host, site, online, last_report FROM machines WHERE source = 'agent'").all()) {
      const online = this.parc.enLigne(m.last_report) ? 1 : 0;
      if (online !== m.online) {
        this.db.prepare('UPDATE machines SET online=? WHERE id=?').run(online, m.id);
        if (online) this.synapse?.machineRevenue(m.host, m.site);
        else { this.synapse?.machinePerdue(m.host, m.site); lignes.push(this.parc.pousser(`${m.host} ne répond plus.`, '')); }
      }
    }
    this.alertes?.evaluerPresence(now);
    return lignes;
  }
}
