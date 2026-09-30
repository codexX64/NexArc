# Sentinel

Le parc sous les yeux : des agents d'inventaire, des tâches distantes, le suivi
des correctifs, des consoles intégrées et le réveil des machines — auto-hébergé,
sur le socle commun des services.

Projet [CodexX64](https://github.com/CodexX64). Licence MIT.

## Ce que fait Sentinel

- **Parc** : chaque machine remonte, par son agent, son système, ses métriques
  (CPU, RAM, disque), sa posture (antivirus, pare-feu, chiffrement, correctifs),
  son inventaire matériel, ses logiciels et ses mises à jour en attente. Un
  tableau de bord, une fiche par machine, un fil d'activité en direct.
- **Tâches distantes** : inventaire à la demande, installation, désinstallation,
  mise à jour, réveil, et — réservée aux administrateurs, sous confirmation
  récente — la commande libre. L'agent ne relève et ne rend que **ses** tâches.
- **Automatisations** : une tâche répétée sur un groupe (tout le parc, un site,
  un système, un hôte), à intervalle ou à heure fixe. Une commande libre
  répétée suit les mêmes règles que la commande libre ; supprimer une
  automatisation revient à un administrateur.
- **Alertes** dérivées de ce que les agents remontent : machine hors ligne,
  antivirus absent ou inactif, pare-feu inactif, disque non chiffré, correctifs
  de sécurité en attente, disque plein, score de risque. Une alerte par machine
  et par règle, résolue d'elle-même quand la cause disparaît ; un fil
  d'activité poussé en direct (SSE).
- **Consoles intégrées** : console VNC plein écran (le mot de passe VNC ne quitte
  jamais le serveur), interfaces d'administration hors bande (iDRAC, iLO, IPMI,
  JetKVM, hyperviseurs…) servies par un proxy inverse qui filtre en-têtes et
  cookies, sous une origine à part, bureau distant MeshCentral.
- **Alimentation Redfish** : lecture de l'état, allumage (membre), arrêt,
  extinction forcée, redémarrage et cycle (administrateur, confirmation
  récente), sur une carte de gestion au certificat épinglé.
- **Réveil réseau** (Wake-on-LAN) par un agent relais du même segment, ou en
  émission directe si le conteneur est sur le réseau de l'hôte.
- **Hôtes sans agent** : une carte de gestion supervisée seule, sans rien à
  installer sur la machine.
- **SYNAPSE**, s'il est installé, reçoit les faits du parc — machines enrôlées,
  perdues, revenues, tâches, automatisations, réveils — jamais le contenu d'une
  commande, jamais un secret.

## Comptes et sécurité

Sentinel repose sur le socle commun : comptes nominatifs, rôles (`admin`,
`membre`, `lecture`), et au moins deux facteurs pour se connecter.

- **Clé d'accès** (Touch ID, Face ID, Windows Hello, clé USB) — exigée pour un
  administrateur quand Sentinel est servi en HTTPS.
- **Application d'authentification** (TOTP), configurée par un QR code généré
  localement dans le navigateur : le secret ne quitte jamais Sentinel.
- **Mot de passe** (Argon2id), selon la politique choisie.
- **Dix codes de secours** à usage unique.

Chaque connexion d'un nouvel appareil et chaque changement de facteur est
signalé dans la page Sécurité et, si un relais SMTP est configuré, à l'adresse
d'alerte vérifiée du compte, avec un lien qui ferme toutes les sessions.

Sessions côté serveur, cookies `HttpOnly` et `SameSite=Strict`, en-tête CSRF,
politique de contenu stricte avec nonce (aucun script en ligne, aucune
bibliothèque tierce), limitation des tentatives, journal de sécurité. Toute
route exige une session (ou un jeton de service ou d'agent comparé en temps
constant), un rôle et l'autorisation sur l'objet visé ; `/api/health` ne rend
que `{ ok: true }`.

**Secrets d'appareils.** Les mots de passe des consoles VNC et les identifiants
Redfish sont scellés au repos (AES-256-GCM, sous-clé par usage) et ne
ressortent jamais de l'API après enregistrement — l'interface affiche seulement
« en place ». La cible d'une console (hôte VNC, URL amont) est toujours résolue
côté serveur, jamais dictée par le navigateur.

**Certificats des cartes de gestion.** Le trafic vers une carte n'est jamais
envoyé sans vérification TLS. Une carte à certificat auto-signé est épinglée :
l'empreinte SHA-256 vue à l'enregistrement est montrée à l'administrateur, qui
la confirme (confiance au premier usage), puis exigée à chaque connexion. Une
empreinte différente est refusée. La lecture initiale du certificat, seule
connexion sans autorité, est bornée par trois garanties, vérifiées par les
essais : elle n'est atteignable que par un administrateur sous confirmation
récente ; elle n'envoie aucune donnée applicative et ferme la connexion dès la
poignée TLS finie ; elle ne rend que l'empreinte et le sujet du certificat.

**Adresses joignables.** Les consoles et cartes jointes par Sentinel ne
peuvent viser ni les métadonnées d'un nuage, ni un lien local, ni une plage
réservée : contrôlé à la saisie pour une adresse littérale, et à chaque
connexion pour un nom d'hôte (la résolution DNS est vérifiée).

**Jetons d'agents.** Un jeton par agent, gardé seulement sous forme d'empreinte
et comparé en temps constant. Le jeton en clair n'apparaît qu'une fois, à
l'inscription. Il n'existe pas de jeton d'agent global. Un jeton se révoque
sans perdre la machine (voir « Agents »). Chaque code d'inscription, jeton
d'agent ou jeton de service refusé compte pour l'adresse qui l'a présenté :
dix échecs la bloquent une minute, puis par paliers jusqu'à une heure, à part
du compteur des connexions humaines. Un agent dont le jeton est refusé se tait
plus d'une heure avant de réessayer.

Les clés d'accès n'existent que sur une page HTTPS. Sans HTTPS, `SOCLE_HTTP=1`
ouvre un mode dégradé, affiché comme tel partout : réservé à un réseau de
confiance, le temps de servir Sentinel en HTTPS.

**Tourner la clé maîtresse.** Dans le Hub (réglages avancés de Sentinel) ou dans
`.env` : la clé actuelle dans `SOCLE_CLE_ANCIENNE`, une neuve
(`openssl rand -base64 32`) dans `SOCLE_CLE`, puis redémarrer. Sentinel rescelle
chaque secret TOTP et chaque secret d'appareil (mots de passe VNC, identifiants
Redfish), chacun en une transaction, et l'écrit dans ses journaux. Vider ensuite
`SOCLE_CLE_ANCIENNE` et redémarrer. Une clé que la base ne connaît pas arrête le
démarrage au lieu de perdre les secrets ; de même, un secret d'appareil encore
scellé sous l'ancienne clé (arrêt au milieu d'une rotation) arrête le démarrage
tant que `SOCLE_CLE_ANCIENNE` n'est pas reposée. Les jetons d'agents, gardés
sous forme d'empreinte, ne dépendent pas de la clé. `node outils/exercice-rotation.mjs`
rejoue toute la rotation sur une instance lancée comme en production.

## Installation par le Hub

Dans le Hub : Extensions → Sentinel → Installer. Le Hub génère la clé maîtresse
et le jeton de service, les garde dans son coffre, et branche, si elle est
installée, la mémoire SYNAPSE.

Au premier démarrage, Sentinel écrit son **jeton d'installation** dans ses
journaux (bouton Journaux du service). Il ne sert qu'une fois : à créer le
premier compte administrateur.

## Installation seule

La clé maîtresse vit dans un secret Docker, hors du volume de données, lisible
par l'utilisateur du conteneur (10001) seul : une copie du volume ne suffit pas
à ouvrir ce qu'elle scelle. Garder une copie hors ligne de `secrets/socle_cle` :
sans elle, une sauvegarde de la base ne rouvre ni les secrets TOTP ni les
secrets d'appareils.

```bash
cp .env.example .env
# renseigner SENTINEL_HUB_TOKEN (openssl rand -hex 24)
mkdir -p secrets && openssl rand -base64 32 > secrets/socle_cle && : > secrets/socle_cle_ancienne
sudo chown 10001:10001 secrets/socle_cle secrets/socle_cle_ancienne && sudo chmod 400 secrets/socle_cle secrets/socle_cle_ancienne
docker compose up -d --build
docker compose logs sentinel | grep "Jeton d'installation"
```

Ouvrir ensuite `http://<hôte>:8090`, coller le jeton, créer le compte et son
second facteur. Un secret `socle_cle` vide arrête le démarrage : la clé n'est
jamais tirée dans le volume quand `SOCLE_CLE_FILE` est posée.

Sans Docker : Node 24.7 ou plus récent, puis `npm start` (aucune dépendance à
installer) ; sans `SOCLE_CLE` ni `SOCLE_CLE_FILE`, la clé est créée dans
`DATA_DIR/cles`, ce qui ne convient qu'au développement.

Vérifications : `npm test` (serveur, vrais serveurs HTTP, TLS, WebSocket et
UDP simulés), `python3 -m unittest agent/test_agent.py` (agent : vérification
TLS sur les deux chemins, lecture de la posture ; demande `psutil`, `requests`
et Node), `node outils/exercice-rotation.mjs` (rotation de la clé maîtresse de
bout en bout), `node outils/parcours-navigateur.mjs <url> <jeton> [dossier]`
(parcours dans Chromium, sept largeurs, avec Playwright).

## Mise à jour depuis la version 1.1.0

Sentinel 2.0 reprend une base `sentinel.db` de la 1.1.0 au premier démarrage,
puis retire les tables de l'ancienne version.

- **Le compte.** La 1.x avait un opérateur unique ; il devient l'administrateur
  du socle. L'empreinte scrypt de son mot de passe est relue telle quelle (le
  socle la reconnaît et la repasse en Argon2id à la connexion suivante). **Si
  cette empreinte est absente ou illisible — ou si la 1.x attendait un mot de
  passe d'amorçage — le compte est repris sans mot de passe, et un administrateur
  lui envoie un lien de réinitialisation depuis la page Comptes.** Le secret
  TOTP, gardé en clair par la 1.x, est scellé à la reprise.
- **Le parc, les alertes, les automatisations et l'historique** sont importés.
  Le contenu des commandes libres passées n'est pas conservé. Une alerte de la
  1.x n'a pas de règle de 2.0 qui la résoudrait : elle se ferme à
  l'acquittement.
- **Les agents** perdaient et partageaient un seul jeton en 1.x : chacun se
  **réenrôle une fois** (nouveau code d'inscription) et se rattache à sa machine
  par son nom d'hôte.
- **Les secrets d'appareils** (mots de passe VNC, identifiants Redfish), scellés
  en 1.x sous une clé qui n'existe plus, ne sont pas repris : l'URL et
  l'utilisateur restent, l'administrateur ressaisit le secret, et réépingle le
  certificat de la carte. Une adresse Redfish en `http://` n'est plus jointe :
  la déclarer en `https://`.

Le conteneur ne tourne plus en `root`. Un volume créé par la version 1 doit
donc changer de propriétaire une fois, avant le premier démarrage de la 2 :

```bash
docker run --rm -v <volume>:/data busybox cp /data/sentinel.db /data/sentinel.db.v1
docker run --rm -v <volume>:/data busybox chown -R 10001:10001 /data
```

## Agents

Un agent s'installe par un **code d'inscription** à usage unique, lié à un site
et à une durée courte, créé depuis la page Postes (« Ajouter un poste »). Le
script proposé installe Python dans un environnement virtuel, télécharge
l'agent et l'enrôle : l'agent échange le code contre **son** jeton, l'écrit
avec sa configuration en `0600`, et se pose en service.

- **Linux** (systemd) et **macOS** (launchd) : `curl -fsSL '<commande>' | sudo bash`.
- **Windows** (tâche planifiée SYSTEM au démarrage), PowerShell en
  administrateur : `powershell -ExecutionPolicy Bypass -Command "irm '<commande>' | iex"`,
  ou le fichier `installer-sentinel.ps1` téléchargé depuis la même fenêtre. Le
  script cherche Python 3 (en écartant le raccourci du Microsoft Store), l'installe
  par winget s'il manque, crée `%ProgramData%\SentinelAgent\venv`, y installe
  `psutil` et `requests`, puis enrôle l'agent. C'est le chemin de la 1.1.0 ; le
  binaire autonome PyInstaller n'existe plus.

Le site et le nom saisis sont contrôlés (lettres, chiffres, espace, point,
tiret, parenthèses) avant d'entrer dans un script exécuté en root ou SYSTEM.

L'agent (`agent/sentinel-agent.py`, Python 3, `psutil` et `requests`) :

- vérifie **toujours** le certificat de Sentinel — autorité système ou fichier
  `SENTINEL_CA`, ou empreinte SHA-256 épinglée (`SENTINEL_PIN`) pour un
  certificat auto-signé ; la vérification par autorité ne cède la place qu'à
  une empreinte bien formée ;
- **constate** la posture qu'il remonte : antivirus (centre de sécurité Windows
  ou Defender, XProtect sur macOS, ClamAV sur Linux), pare-feu (profils
  Windows, pare-feu applicatif macOS, firewalld, ufw, nftables ou iptables),
  chiffrement (BitLocker, FileVault, LUKS). Ce qu'il ne peut pas lire part
  « inconnu » et n'ouvre aucune alerte. Sur Linux, seul ClamAV est reconnu
  comme antivirus : un serveur sans lui est déclaré « absent » ;
- n'exécute qu'une liste fermée de types de tâches, identique à celle du serveur,
  sans shell interpolé, avec des délais et une sortie bornés ;
- ne relève et ne rend que les tâches de sa propre machine.

Révoquer un jeton — poste perdu, jeton exposé, incident :

```bash
docker exec <sentinel> node src/cli.js agents lister
docker exec <sentinel> node src/cli.js agents revoquer <hôte>    # ou --tous
```

Le jeton cesse aussitôt ; les tâches encore dues de ce poste sont abandonnées ;
la machine garde son historique et ses accès. L'agent se réinscrit avec un
nouveau code et retrouve sa machine par son nom d'hôte. Chaque révocation est
inscrite au journal de sécurité.

## Consoles et cartes de gestion

Jusqu'à huit accès par machine, déclarés par un administrateur sous
confirmation récente (un accès dit où Sentinel se connecte sur le réseau
interne), chaque déclaration inscrite au journal de sécurité. Types : console VNC intégrée (hôte:port, écran
plein dans Sentinel, mot de passe scellé côté serveur), iDRAC, iLO, IPMI/BMC,
JetKVM, hyperviseur (console noVNC des VM), interface web, MeshCentral. Une URL
amont est jointe par un proxy inverse qui n'accepte que http(s), refuse les
métadonnées de nuage et les plages réservées, et filtre en-têtes et cookies.

L'interface web d'une carte est du code qui n'est pas le nôtre : elle ne
s'exécute jamais sous l'origine de Sentinel, où elle lirait l'API avec la
session de l'opérateur. Pour l'afficher dans Sentinel, poser
`SENTINEL_CONSOLE_URL` : un second écouteur (`SENTINEL_CONSOLE_PORT`, 8091 par
défaut) sert alors les consoles sous cette adresse, où ne vivent ni page, ni
API, ni session de Sentinel. Chaque ouverture tire une passe de 256 bits, liée
à la session qui l'a demandée, à la machine et à l'accès, qui meurt avec cette
session (huit heures au plus) ; seule la page de Sentinel qui l'a tirée peut
encadrer la console. Donner à cette adresse **son propre nom d'hôte**, en HTTPS
de préférence : un autre port du même hôte sépare les scripts, pas les cookies,
que les navigateurs ne distinguent pas par port. Sans `SENTINEL_CONSOLE_URL`,
l'interface d'une carte s'ouvre dans un nouvel onglet, directement sur la carte.
L'alimentation passe par Redfish sur les cartes qui le supportent (identifiants
posés par un administrateur dans « Accès distants »). Redfish s'authentifie en
Basic : la carte n'est jointe qu'à une adresse `https://`, sur son certificat
épinglé, pour que ses identifiants ne circulent jamais en clair. Allumer est ouvert au rôle membre, comme le réveil par le
réseau ; arrêter, forcer l'extinction, redémarrer ou faire un cycle
interrompent un système en marche et exigent un administrateur sous
confirmation récente.

## Alertes

Chaque remontée d'agent, et chaque tour de collecte, évalue ces règles :

| Règle | Ouverte quand | Gravité |
|---|---|---|
| Hors ligne | aucune remontée depuis `SENTINEL_ALERT_OFFLINE_MINUTES` | critique |
| Antivirus | absent ou inactif | critique |
| Pare-feu | inactif | élevée |
| Chiffrement | disque système non chiffré | élevée |
| Correctifs de sécurité | en attente depuis plus de `SENTINEL_ALERT_PATCH_DAYS` jours | élevée |
| Disque | rempli à `SENTINEL_ALERT_DISK_PERCENT` % ou plus | élevée |
| Score de risque | à `SENTINEL_ALERT_RISK` ou plus | élevée |

Une alerte par machine et par règle, jamais deux : tant que la condition dure,
l'alerte ouverte suit la mesure. Quand la condition disparaît, elle se résout
d'elle-même, datée. Acquitter dit qu'un opérateur s'en occupe, sans la fermer.
Ouverture et résolution arrivent en direct dans l'interface, au fil
d'activité, et à SYNAPSE s'il est branché. Les alertes résolues sont gardées
trente jours.

Le score de risque ne compte que des défauts constatés : antivirus absent ou
inactif (30), périmé (15), pare-feu inactif (20), disque non chiffré (15),
correctifs de sécurité en attente (5 chacun, 25 au plus), sur une base de 10.

## Réveil réseau

Sentinel réveille une machine hors ligne en confiant un paquet magique à un
agent relais **en ligne du même sous-réseau** (diffusion dirigée calculée et
validée). Si le conteneur est sur le réseau de l'hôte (`SENTINEL_HOST_NET=1`),
le serveur émet lui-même. Sans relais disponible ni réseau de l'hôte, l'action
est refusée (409) plutôt que d'échouer en silence.

## Configuration

Chaque variable secrète peut aussi être lue d'un fichier : `NOM_FILE=/chemin`
(convention des secrets Docker). Une valeur invalide arrête Sentinel au
démarrage avec la liste des erreurs. Les variables `SOCLE_*` sont lues par le
socle.

| Variable | Rôle | Défaut |
|---|---|---|
| `SENTINEL_HUB_TOKEN` | jeton du Hub : état, tâches, réveils — jamais les comptes ni les réglages | — |
| `SENTINEL_ALLOW_EXEC` | `1` autorise la commande libre, en tâche comme en automatisation (toujours admin + confirmation récente) ; à `0`, une automatisation « commande libre » existante ne s'exécute plus | `0` |
| `SENTINEL_MAX_MACHINES` | plafond de machines | `5000` |
| `SENTINEL_INGEST_MINUTE` | remontées d'agent par minute et par IP | `240` |
| `SENTINEL_COLLECT_INTERVAL` | cadence de la boucle de collecte (s) | `30` |
| `SENTINEL_OFFLINE_AFTER` | silence toléré avant « hors ligne » (s) | `120` |
| `SENTINEL_JOB_TIMEOUT` | délai d'exécution d'une tâche par l'agent (s) | `120` |
| `SENTINEL_ALERT_OFFLINE_MINUTES` | alerte : minutes sans remontée | `15` |
| `SENTINEL_ALERT_PATCH_DAYS` | alerte : jours d'attente d'un correctif de sécurité | `7` |
| `SENTINEL_ALERT_DISK_PERCENT` | alerte : disque rempli à (%) | `90` |
| `SENTINEL_ALERT_RISK` | alerte : score de risque à partir de | `70` |
| `SENTINEL_HOST_NET` | `1` : conteneur sur le réseau de l'hôte (réveil direct) | `0` |
| `SENTINEL_PUBLIC_URL` | adresse annoncée aux agents ; vide : celle de l'enrôlement | — |
| `SENTINEL_MESH_URL` | serveur MeshCentral ; vide : prise en main désactivée | — |
| `SENTINEL_MESH_USER` | compte de service Mesh (sans `user//`), pour l'auto-login | — |
| `SENTINEL_MESH_LOGIN_KEY` | clé hex de `meshcentral --logintokenkey` | — |
| `SENTINEL_MESH_VIEWMODE` / `_HIDE` / `_EMBED` | affichage du bureau Mesh | `11` / — / `0` |
| `SYNAPSE_URL` / `SYNAPSE_JETON` | mémoire du parc ; jamais le contenu d'une commande | — |
| `SENTINEL_CONSOLE_URL` | origine des consoles web intégrées (schéma, hôte, port), sur son propre nom d'hôte ; vide : une carte s'ouvre dans un nouvel onglet | — |
| `SENTINEL_CONSOLE_PORT` | écoute de cette origine | `8091` |
| `DATA_DIR` | dossier de `sentinel.db` | `/app/data` |
| `PORT` / `HOTE` | écoute | `8090` / `0.0.0.0` |
| `SOCLE_CLE` | clé maîtresse, 32 octets en base64 (en conteneur : `SOCLE_CLE_FILE`, secret Docker) ; sans l'une ni l'autre : créée dans `DATA_DIR/cles` (développement) | — |
| `SOCLE_CLE_ANCIENNE` | pendant une rotation seulement : la clé remplacée | — |
| `SOCLE_HTTP` | `1` : mode dégradé sans HTTPS | `0` |
| `SOCLE_PROXYS` | relais inverses de confiance (CIDR) | — |
| `SOCLE_ORIGINES` | origines acceptées en plus de celle de la page | — |
| `SOCLE_JETON_INSTALLATION` | jeton du premier compte ; vide : tiré au démarrage | — |
| `SOCLE_URL_PUBLIQUE` | adresse publique (`https://…`), d'où partent les liens des courriels | — |
| `SOCLE_SMTP_HOTE` / `_PORT` / `_SECURITE` | relais des alertes : `tls` (465) ou `starttls` (587) | — / 465 / `tls` |
| `SOCLE_SMTP_UTILISATEUR` / `_MOTDEPASSE` / `_DE` | identifiants du relais et adresse d'expédition | — |

Le socle accepte d'autres réglages (politique des facteurs, paramètres
Argon2id, durée de session, poivre HMAC) ; leurs valeurs par défaut conviennent
à une installation courante.

## Derrière un relais inverse

Déclarer l'adresse du relais dans `SOCLE_PROXYS` ; sans cela, Sentinel ignore
`X-Forwarded-For` et `X-Forwarded-Proto`, et compte les tentatives par l'adresse
du relais. Le relais doit transmettre :

```
X-Forwarded-For, X-Forwarded-Proto, Host
```

Les consoles intégrées ouvrent des WebSockets (`/vnc/…` sur Sentinel, `/c/…`
sur l'origine des consoles) : le relais doit laisser passer la mise à niveau
`Upgrade`. L'origine des consoles est une seconde route du relais, vers le port
`SENTINEL_CONSOLE_PORT`, sous son propre nom d'hôte.

## Sécurité

Les données conservées et leur finalité sont décrites dans
`web/confidentialite.txt`, servi à `/confidentialite.txt`.

En cas d'incident : révoquer les sessions et forcer une réinitialisation depuis
la page Sécurité, tourner la clé maîtresse et réémettre les jetons de service et
d'agents, restaurer depuis une sauvegarde. L'exploitant notifie une violation de
données dans les 72 heures si le droit applicable l'exige.

Une faille se signale en privé, par un avis de sécurité GitHub sur le dépôt
(`Security → Advisories → Report a vulnerability`), jamais dans une issue
publique.
