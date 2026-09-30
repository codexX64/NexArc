// Configuration de Sentinel, lue et validée une fois au démarrage. Les
// variables SOCLE_* (comptes, relais, clé maîtresse) sont lues par le socle.
// Une valeur invalide arrête le processus avec la liste complète des erreurs.
import { lireConfig } from '../socle/src/index.js';

export const VERSION = '2.0.0';

export function lireConfigSentinel(env = process.env) {
  return lireConfig({
    port: { env: 'PORT', type: 'entier', min: 0, max: 65535, defaut: 8090 },
    hote: { env: 'HOTE', type: 'chaine', defaut: '0.0.0.0' },
    donnees: { env: 'DATA_DIR', type: 'chaine', defaut: '/app/data' },
    // Jeton de service du Hub : ouvre l'API (lecture, tâches, réveils), jamais
    // les comptes ni les réglages de sécurité. Un agent, lui, ne présente jamais
    // ce jeton : chacun a le sien, minté à l'échange d'un code d'inscription.
    jetonHub: { env: 'SENTINEL_HUB_TOKEN', type: 'secret', min: 24 },
    // Cadence de la boucle de collecte (marquage hors ligne) et silence toléré.
    intervalle: { env: 'SENTINEL_COLLECT_INTERVAL', type: 'entier', min: 10, max: 3600, defaut: 30 },
    horsLigneApres: { env: 'SENTINEL_OFFLINE_AFTER', type: 'entier', min: 30, max: 86400, defaut: 120 },
    // Plafonds : nombre de machines, remontées d'agent par minute et par IP.
    maxMachines: { env: 'SENTINEL_MAX_MACHINES', type: 'entier', min: 1, max: 100000, defaut: 5000 },
    ingestMinute: { env: 'SENTINEL_INGEST_MINUTE', type: 'entier', min: 1, max: 100000, defaut: 240 },
    // Adresse publique annoncée aux agents (vide : celle de la requête d'enrôlement).
    urlEnrolement: { env: 'SENTINEL_PUBLIC_URL', type: 'url' },
    // Le conteneur est-il sur le réseau de l'hôte ? Seulement alors le serveur
    // émet lui-même un paquet magique ; sinon il passe par un agent relais.
    reseauHote: { env: 'SENTINEL_HOST_NET', type: 'booleen', defaut: false },
    // Commande libre (tâche « cmd ») : autorisée globalement ? Même à 1, elle
    // reste réservée au rôle admin sous renfort récent.
    commandeLibre: { env: 'SENTINEL_ALLOW_EXEC', type: 'booleen', defaut: false },
    // Délai d'exécution d'une tâche par l'agent, borné.
    delaiTache: { env: 'SENTINEL_JOB_TIMEOUT', type: 'entier', min: 10, max: 1800, defaut: 120 },
    // Seuils des alertes. Hors ligne : au-delà du simple marquage (qui suit
    // SENTINEL_OFFLINE_AFTER), pour qu'un redémarrage ne sonne pas. Correctifs :
    // une semaine laisse passer un cycle de mise à jour ordinaire. Disque : 90 %
    // prévient avant l'arrêt d'un service. Risque : 70 n'est franchi qu'en
    // cumulant des défauts constatés — antivirus, pare-feu et chiffrement à la
    // fois, par exemple (voir Agents.risque) — pas sur un seul.
    alerteHorsLigneMin: { env: 'SENTINEL_ALERT_OFFLINE_MINUTES', type: 'entier', min: 1, max: 10080, defaut: 15 },
    alerteCorrectifsJours: { env: 'SENTINEL_ALERT_PATCH_DAYS', type: 'entier', min: 0, max: 365, defaut: 7 },
    alerteDisquePct: { env: 'SENTINEL_ALERT_DISK_PERCENT', type: 'entier', min: 50, max: 100, defaut: 90 },
    alerteRisque: { env: 'SENTINEL_ALERT_RISK', type: 'entier', min: 1, max: 100, defaut: 70 },
    // Prise en main à distance MeshCentral (facultatif). URL vide : désactivé.
    meshUrl: { env: 'SENTINEL_MESH_URL', type: 'url' },
    meshUser: { env: 'SENTINEL_MESH_USER', type: 'chaine' },
    meshCle: { env: 'SENTINEL_MESH_LOGIN_KEY', type: 'chaine', motif: /^[0-9a-fA-F]{0,128}$/ },
    meshViewmode: { env: 'SENTINEL_MESH_VIEWMODE', type: 'chaine', motif: /^\d{1,3}$/, defaut: '11' },
    meshHide: { env: 'SENTINEL_MESH_HIDE', type: 'chaine', motif: /^\d{0,3}$/, defaut: '' },
    meshEmbed: { env: 'SENTINEL_MESH_EMBED', type: 'booleen', defaut: false },
    // Intégration SYNAPSE : la mémoire du parc. Sans URL ni jeton, rien ne part.
    synapseUrl: { env: 'SYNAPSE_URL', type: 'url' },
    synapseJeton: { env: 'SYNAPSE_JETON', type: 'chaine' },
  }, env);
}
