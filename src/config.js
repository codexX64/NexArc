// Configuration de NEXARC, lue et validée une fois au démarrage. Les
// variables SOCLE_* (comptes, relais, clé maîtresse) sont lues par le socle.
// Une valeur invalide arrête le processus avec la liste complète des erreurs.
import fs from 'node:fs';
import { lireConfig } from '../socle/src/index.js';

export const VERSION = '2.0.0';

export function lireConfigNexarc(env = process.env) {
  // SOCLE_CLE_FILE posée dit « la clé vient d'un secret » : un fichier vide ne
  // doit pas laisser le socle la tirer dans le volume, à côté de ce qu'elle scelle.
  if (env.SOCLE_CLE_FILE && fs.existsSync(env.SOCLE_CLE_FILE) && !fs.readFileSync(env.SOCLE_CLE_FILE, 'utf8').trim()) {
    throw Object.assign(new Error(`Configuration invalide :\n  - SOCLE_CLE_FILE (${env.SOCLE_CLE_FILE}) est vide : pose la clé maîtresse dans ce secret (README, « Installation seule »).`), { erreurs: ['SOCLE_CLE_FILE vide'] });
  }
  const cfg = lireConfig({
    port: { env: 'PORT', type: 'entier', min: 0, max: 65535, defaut: 8090 },
    hote: { env: 'HOTE', type: 'chaine', defaut: '0.0.0.0' },
    donnees: { env: 'DATA_DIR', type: 'chaine', defaut: '/app/data' },
    // Jeton de service du Hub : ouvre l'API (lecture, tâches, réveils), jamais
    // les comptes ni les réglages de sécurité. Un agent, lui, ne présente jamais
    // ce jeton : chacun a le sien, minté à l'échange d'un code d'inscription.
    jetonHub: { env: 'NEXARC_HUB_TOKEN', type: 'secret', min: 24 },
    // Cadence de la boucle de collecte (marquage hors ligne) et silence toléré.
    intervalle: { env: 'NEXARC_COLLECT_INTERVAL', type: 'entier', min: 10, max: 3600, defaut: 30 },
    horsLigneApres: { env: 'NEXARC_OFFLINE_AFTER', type: 'entier', min: 30, max: 86400, defaut: 120 },
    // Plafonds : nombre de machines, remontées d'agent par minute et par IP.
    maxMachines: { env: 'NEXARC_MAX_MACHINES', type: 'entier', min: 1, max: 100000, defaut: 5000 },
    ingestMinute: { env: 'NEXARC_INGEST_MINUTE', type: 'entier', min: 1, max: 100000, defaut: 240 },
    // Adresse publique annoncée aux agents (vide : celle de la requête d'enrôlement).
    urlEnrolement: { env: 'NEXARC_PUBLIC_URL', type: 'url' },
    // Le conteneur est-il sur le réseau de l'hôte ? Seulement alors le serveur
    // émet lui-même un paquet magique ; sinon il passe par un agent relais.
    reseauHote: { env: 'NEXARC_HOST_NET', type: 'booleen', defaut: false },
    // Commande libre (tâche « cmd ») : autorisée globalement ? Même à 1, elle
    // reste réservée au rôle admin sous renfort récent.
    commandeLibre: { env: 'NEXARC_ALLOW_EXEC', type: 'booleen', defaut: false },
    // Délai d'exécution d'une tâche par l'agent, borné.
    delaiTache: { env: 'NEXARC_JOB_TIMEOUT', type: 'entier', min: 10, max: 1800, defaut: 120 },
    // Seuils des alertes. Hors ligne : au-delà du simple marquage (qui suit
    // NEXARC_OFFLINE_AFTER), pour qu'un redémarrage ne sonne pas. Correctifs :
    // une semaine laisse passer un cycle de mise à jour ordinaire. Disque : 90 %
    // prévient avant l'arrêt d'un service. Risque : 70 n'est franchi qu'en
    // cumulant des défauts constatés — antivirus, pare-feu et chiffrement à la
    // fois, par exemple (voir Agents.risque) — pas sur un seul.
    alerteHorsLigneMin: { env: 'NEXARC_ALERT_OFFLINE_MINUTES', type: 'entier', min: 1, max: 10080, defaut: 15 },
    alerteCorrectifsJours: { env: 'NEXARC_ALERT_PATCH_DAYS', type: 'entier', min: 0, max: 365, defaut: 7 },
    alerteDisquePct: { env: 'NEXARC_ALERT_DISK_PERCENT', type: 'entier', min: 50, max: 100, defaut: 90 },
    alerteRisque: { env: 'NEXARC_ALERT_RISK', type: 'entier', min: 1, max: 100, defaut: 70 },
    // Prise en main à distance MeshCentral (facultatif). URL vide : désactivé.
    meshUrl: { env: 'NEXARC_MESH_URL', type: 'url' },
    meshUser: { env: 'NEXARC_MESH_USER', type: 'chaine' },
    // Clé de « meshcentral --logintokenkey » : 80 octets en hexadécimal, dont les
    // 32 premiers chiffrent le jeton ; plus courte, elle échouerait au premier bureau ouvert.
    meshCle: { env: 'NEXARC_MESH_LOGIN_KEY', type: 'chaine', motif: /^(?:[0-9a-fA-F]{2}){32,80}$/ },
    meshViewmode: { env: 'NEXARC_MESH_VIEWMODE', type: 'chaine', motif: /^\d{1,3}$/, defaut: '11' },
    meshHide: { env: 'NEXARC_MESH_HIDE', type: 'chaine', motif: /^\d{0,3}$/, defaut: '' },
    meshEmbed: { env: 'NEXARC_MESH_EMBED', type: 'booleen', defaut: false },
    // Intégration SYNAPSE : la mémoire du parc. Sans URL ni jeton, rien ne part.
    synapseUrl: { env: 'SYNAPSE_URL', type: 'url' },
    synapseJeton: { env: 'SYNAPSE_JETON', type: 'secret', min: 24 },
    // Origine des consoles web (origine-consoles.js) : l'adresse que les
    // navigateurs joignent, et le port où elle écoute. Sans adresse, l'interface
    // d'une carte s'ouvre dans un nouvel onglet, directement sur la carte.
    consoleUrl: { env: 'NEXARC_CONSOLE_URL', type: 'url' },
    consolePort: { env: 'NEXARC_CONSOLE_PORT', type: 'entier', min: 0, max: 65535, defaut: 8091 },
  }, env);
  if (cfg.consoleUrl) {
    const u = new URL(cfg.consoleUrl);
    if (u.pathname !== '/' || u.search || u.hash || u.username || u.password) {
      throw Object.assign(new Error('Configuration invalide :\n  - NEXARC_CONSOLE_URL : une origine seule est attendue (schéma, hôte et port, sans chemin).'), { erreurs: ['NEXARC_CONSOLE_URL'] });
    }
  }
  return cfg;
}
