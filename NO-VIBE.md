# Code quality record — Sentinel RMM

Method: Project Baseline Requirements & Security Manual, Part III (chapters 37-49)
Reviewed: 2026-09-30   ·   Owner: Codex64

## Behaviour freeze
Point de départ de la passe : `694d771`, dernier commit de code de la phase de sécurité (les deux commits suivants ne touchent que SECURITY.md). Ensemble de référence relevé avant la passe : 109 essais — 33 du service (`test/sentinel.test.js`, vrais serveurs HTTP, TLS, WebSocket et UDP), 18 de l’agent Python (`agent/test_agent.py`, contre un vrai serveur HTTPS local), 58 du socle embarqué — tous verts. Relancés à la génération de ce fichier : les mêmes, un à un, tous verts, et 11 de plus : « épinglage TLS : un certificat signé par le certificat épinglé n'est pas pour autant la carte épinglée » (`4a8e159`), ajouté par la passe après une cassure volontaire que rien ne détectait ; « migration 1.1.0 : l'opérateur resté au mot de passe d'amorçage reçoit au journal un lien qui lui rend l'accès » (`1048ff3`), ajouté après la passe avec la correction d’un constat de reprise de la 1.x (relevé en préparant la mise à jour) ; « thème : la page porte la gamme posée par la page Thème du Hub ; SOMA hors Hub » (`aa6baa0`), ajouté avec le thème choisi depuis le Hub ; « comptes depuis le Hub : manifeste et Compose relient le jeton d’administration ; ni le jeton de service ni lui n’ouvrent l’autre côté » (`3858149`), ajouté avec la gestion des comptes depuis le Hub ; « inscription : installateurs à télécharger (exécutable Windows, archive macOS, script Linux), même script que la commande » (`ab11e56`), ajouté avec les installateurs à télécharger. Aucun essai de caractérisation n’a été nécessaire : l’essai « autorisation » balaie déjà chaque route sans session, en lecture seule et en membre, et chaque route a son parcours.

Diff de l’API publique sur la passe : vide. L’inventaire de la surface publique (`sentinel/surface.mjs`, hors dépôt) est identique ligne à ligne entre `694d771` et l’arbre final, et identique à celui relevé avant la passe : 36 routes avec leurs options et leurs schémas de requête, 17 schémas de corps, les types de tâches, de cibles et d’accès distants, le chemin WebSocket du pont VNC et celui de l’origine des consoles, 26 variables de configuration, 27 réglages du manifeste du Hub, 5 commandes de la ligne de commande, et le contrat de l’agent (arguments, routes appelées, corps envoyés) — 134 lignes. Après la passe, les fonctions ajoutées n'ont rien retiré ni changé : 2 lignes en plus, `hub HUB_ADMIN_TOKEN secret null` (3858149, réglage du manifeste qui porte le jeton d’administration des comptes depuis le Hub) ; `route GET ^\/api\/enroll\/installateur$` (ab11e56, installateur à télécharger, mêmes contrôles que le script).

Démarrage et parcours de bout en bout, sur l’arbre final, le 2026-09-30 : `outils/exercice-rotation.mjs` → 24 vérifications réussies ; `outils/exercice-incident.mjs` → 23 vérifications réussies ; `outils/parcours-navigateur.mjs` (installation par clé d’accès virtuelle, tableau de bord, postes, fiche et composants, accès distants, alertes, correctifs, automatisations, réglages, sécurité, comptes, inscription ; douze écrans à sept largeurs, de 360 à 1920 pixels) → 84 écrans×largeurs, 0 défaut de mise en page, 0 erreur de console ; sondage exploratoire de SECURITY.md → 40 cas conformes, rejoués sur une instance neuve à chaque génération de ce relevé-là.

Changements de comportement voulus pendant la phase de sécurité, chacun étant le correctif (détail dans SECURITY.md, « Findings ») :

| Avant | Après | Contrôle |
|---|---|---|
| le HTML d’une carte servi sous l’origine de Sentinel, par `/console/…` | une origine à part (SENTINEL_CONSOLE_URL), ouverte par une passe liée à la session ; `/console/…` répond 404 | REQ-WEB-002 |
| un membre déclarait consoles, cartes et nœuds Mesh | administrateur sous renfort, geste journalisé | SEC-CSRF-004 |
| `GET /api/enroll/info`, `GET /api/enroll/config`, `GET /api/agent/jobs` | les mêmes en POST ; un GET répond 405 | SEC-CSRF-003 |
| codes et jetons de machine devinés sans limite | dix échecs par adresse, puis 429 par paliers | REQ-AUTH-010 |
| code d’inscription de 72 bits gardé en clair | 128 bits, gardé par son empreinte | REQ-CRYPT-005, -006 |
| une automatisation « commande libre » réactivée par un membre et lancée avec SENTINEL_ALLOW_EXEC coupé | réglage, administrateur et renfort à chaque geste ; 403 sinon | SEC-AUTHZ-007, -008 |
| charge d’une tâche libre, réveil dicté dans une tâche | charge validée selon le type (422) ; « wol » réservé à la route de réveil (400) | REQ-WEB-006 |
| paramètre de requête non déclaré ignoré | 400 | REQ-WEB-006 |
| sortie d’une commande libre rendue à tout lecteur | à un administrateur seulement | SEC-API-004 |
| rôle de relais pris dans la remontée de l’agent | fixé par le code d’inscription | SEC-AUTHZ-003 |
| texte d’erreur d’une carte rendu au client (ou masqué en 500) | 502, une cause courte et une référence ; le détail au journal du serveur | SEC-XSS-006 |
| Redfish en HTTP accepté | 422 : HTTPS et certificat épinglé exigés | REQ-DATA-002 |
| dépendances de l’agent en plages, installées sans empreinte | versions exactes, `--require-hashes` | SEC-DEP-001 |
| aucune révocation des jetons d’agents, aucune sauvegarde | `node src/cli.js agents revoquer`, `sauvegarde`, `restaurer` | REQ-CFG-005, REQ-DATA-003 |

## Layer status
| Chapter | Subject | Status | What changed |
|---|---|---|---|
| 39 | Comment layer | DONE | 38 lignes de bannières et de marqueurs de section retirées (`src/api.js`, `web/app.js`, l’agent, `src/base.js`, `src/agents.js`, `src/taches.js`, `src/main.js`), un titre gardé en phrase quand il disait ce que le code ne dit pas ; la règle des rôles déclarés recollée à `creerApi` ; le commentaire de `Agents.resoudre` corrigé (il annonçait une création et un null que la fonction ne fait pas) ; densité moyenne 12.6 %, les fichiers au-dessus de 25 % relus un à un (`src/tls.js`, `src/config.js`, `src/mesh.js`) : les trois garanties de la sonde TLS, les seuils justifiés de la configuration, le format du jeton MeshCentral — des invariants et des raisons, aucune narration |
| 40 | Naming and vocabulary | DONE | noms génériques remplacés par ce qu’ils désignent : `item`, `items`, `it` → `entree`, `entrees` (accès distants, dans l’API, le parc, le démarrage et l’origine des consoles), `res` → `remontee`, `machineAgent`, `verdict` ; `up`, `ru`, `mod`, `low` → `amont`, `reponse`, `transport`, `nom` ; `STRIP_REQUEST`/`STRIP_RESPONSE` → `RETIRES_DE_LA_REQUETE`/`RETIRES_DE_LA_REPONSE` ; `data`, `tmp`, `clean`, `out` → `lot`, `provisoire`, `normalisee`, `morceau`, `reprises` ; `accept` → `acceptation` ; l’alias `q` et `base$` retirés ; restent `res` (réponse HTTP de Node, nom de tout le socle) et `output` (colonne des tâches) |
| 41 | Formatting, layout and whitespace | DONE | aucun formateur dans le dépôt, aucun introduit ; 2 espaces, apostrophes simples, points-virgules en JavaScript ; l’agent garde la forme de la 1.x (4 espaces, apostrophes simples, deux lignes entre les fonctions) ; `git diff --check` depuis l’arbre vide : propre ; aucun caractère invisible ; un alignement de commentaire resserré |
| 42 | Gratuitous abstraction | DONE | aucune interface à une seule implémentation, aucune fabrique ; duplications repliées : la lecture des accès distants d’une machine (une copie dans l’API), la vérification de l’identité d’une carte épinglée (une copie dans le WebSocket client, `identiteEpinglee` dans `src/tls.js`), l’état rendu après chaque geste (huit copies, `etatParc`), deux transactions écrites à la main (`resceller`, reprise de la 1.x) ramenées à `transaction`, la liste des types d’accès de l’interface (deux copies, et un libellé relu dans le texte de l’option) |
| 43 | Defensive noise | DONE | 154 `catch` rangés ci-dessous selon ce que fait leur bloc, aucun hors classe (98 dans le code de Sentinel, les autres dans le socle, relus dans son propre dépôt) ; les huit que la règle générale ne rangeait pas (`src/api.js`, `src/main.js`, `src/websocket.js`) relus et rangés sous leur raison propre (carte en échec, connexion rompue) ; 32 `except` Python (agent et essais) relus, trois `pass` sans raison ont reçu la leur, un `chmod` du fichier du jeton n’est plus tu en cas d’échec ; un rappel d’envoi UDP sans effet réécrit ; deux `catch` d’essais disent pourquoi ils se taisent ; aucun message vague, aucune journalisation d’entrée ou de sortie de fonction |
| 44 | Control flow and idiom | DONE | retours anticipés ; une branche en double retirée de `Agents.resoudre` ; boucles indexées réservées au démasquage des trames WebSocket, au DES du RFB et au paquet magique |
| 45 | Types, signatures and data shapes | DONE | JavaScript sans TypeScript ; un contrat d’erreur : `ErreurHttp` du socle, `Refus` (sa sous-classe journalisée) et `CarteEnEchec` (502 avec une référence), levées au plus près, formatées une seule fois ; schémas de corps et de requête déclaratifs, champ inconnu refusé ; l’agent parle le même vocabulaire que le serveur (types de tâches et motif de paquet vérifiés par ses essais) |
| 46 | Dependencies, configuration, fitting the repository | DONE | aucune dépendance npm, deux pour l’agent (versions et empreintes fixées) ; chacune des 30 variables de `.env.example` a un lecteur ; code mort retiré (`echappeLike`, `LIBELLES` de Redfish, un contrôle d’upgrade sans effet) ; exports sans lecteur ramenés à leur module (26 noms) ; aucun import inutilisé (liaisons de 68 fichiers JavaScript et 2 Python analysées ; deux retirés) |
| 47 | Tests | DONE | les essais nettoient sans `try` muet ; 13 cassures volontaires, chacune détectée (ci-dessous) ; deux passaient d’abord inaperçues et ont chacune leur essai : un cookie de Sentinel seul, sans cookie de la carte, n’était pas essayé (assertion ajoutée à l’essai de l’origine des consoles), et la comparaison d’empreinte n’était jamais atteinte, un autre certificat échouant déjà sur l’autorité (essai ajouté avec un certificat signé par le certificat épinglé) |
| 48 | Documentation, furniture and version control | DONE | README : le déroulé d’incident suivait l’ancienne page et oubliait la ligne de commande ; `.gitignore`, `.dockerignore`, `LICENSE`, `Dockerfile`, la vérification CI et l’en-tête des outils contrôlés ; un sujet par commit, sans mention d’outil ; réécriture du serveur et de l’interface découpée par sujet (dix commits au lieu de deux), les deux composants embarqués (socle, noVNC) chacun seul |

`catch` restants, par raison :

| Raison | Nombre | Où |
|---|---|---|
| valeur de repli explicite (donnée externe illisible, objet disparu, service absent) | 42 | `outils/`, `socle/`, `src/agents.js`, `src/api.js`, `src/base.js`, `src/consoles.js`, `src/enroll.js`, `src/main.js` et 5 autres |
| sans effet voulu, la raison écrite dans le bloc | 36 | `outils/`, `socle/`, `src/api.js`, `src/base.js`, `src/main.js`, `src/origine-consoles.js`, `src/redfish.js`, `src/vncbridge.js` et 4 autres |
| montrée à l’écran ou rendue au demandeur, avec sa cause | 31 | `socle/`, `src/synapse.js`, `web/app.js` |
| relevée, traduite en erreur du domaine (ErreurHttp, CarteEnEchec) ou transmise | 26 | `socle/`, `src/api.js`, `src/base.js`, `src/cli.js`, `src/main.js`, `src/vncbridge.js` |
| connexion rompue : fermée ou retirée, rien d’autre à faire | 8 | `src/main.js`, `src/origine-consoles.js`, `src/vncbridge.js`, `src/websocket.js` |
| journalisée, ou portée dans l’état du service | 6 | `socle/`, `src/main.js` |
| tâche d’arrière-plan facultative : son échec n’a rien à montrer, l’action suivante le montre | 3 | `socle/` |
| rapportée dans le résultat de l’étape | 2 | `socle/` |

## Tests
Cassures volontaires (REQ-CODE-005) : chacune posée seule, la suite concernée lancée en entier (`test/sentinel.test.js` ou `agent/test_agent.py`), le fichier rétabli (`mutations_sentinel.py`, hors dépôt), sur l’arbre de la passe.

| Cassure | Fichier | Essais en échec | Premier essai qui échoue |
|---|---|---|---|
| le jeton du Hub crée une commande libre | `src/api.js` | 1 | « le jeton du Hub n'ouvre que l'état, les tâches et le réveil » |
| un membre déclare les adresses internes que le serveur joint | `src/api.js` | 2 | « autorisation : chaque route balayée sans session, en lecture seule et en membre » |
| un agent rend le résultat de la tâche d’un autre | `src/taches.js` | 1 | « agent : code d'inscription à usage unique, remontée, relève et résultat de SES tâches seulement » |
| un code d’inscription s’échange deux fois | `src/agents.js` | 1 | « agent : code d'inscription à usage unique, remontée, relève et résultat de SES tâches seulement » |
| les jetons et codes de machine devinés ne comptent plus | `src/api.js` | 1 | « codes et jetons de machine : chaque échec compte pour l'adresse, bloquée après dix, à part des connexions humaines » |
| le cookie de session de Sentinel part vers la carte | `src/proxy.js` | 1 | « origine des consoles : la carte s'affiche hors de l'origine de Sentinel, par une passe liée à la session » |
| un certificat signé par le certificat épinglé passe pour la carte | `src/tls.js` | 1 | « épinglage TLS : un certificat signé par le certificat épinglé n'est pas pour autant la carte épinglée » |
| la sortie d’une commande libre est rendue à tout lecteur | `src/base.js` | 1 | « commande libre : rôle admin + renfort ; un membre ne peut pas » |
| la ronde exécute une commande libre avec SENTINEL_ALLOW_EXEC coupé | `src/taches.js` | 1 | « commande libre désactivée : ni créée, ni lancée, ni réactivée, ni exécutée par la ronde des automatisations » |
| une passe de console survit à la fermeture de sa session | `src/origine-consoles.js` | 1 | « origine des consoles : la carte s'affiche hors de l'origine de Sentinel, par une passe liée à la session » |
| une trame de contrôle démesurée est renvoyée en écho | `src/websocket.js` | 1 | « WebSocket : trames de contrôle démesurées ou fragmentées refusées, jamais renvoyées » |
| un paramètre de requête non déclaré est admis | `src/api.js` | 1 | « autorisation : chaque route balayée sans session, en lecture seule et en membre » |
| l’agent sans empreinte épinglée ne vérifie plus le certificat | `agent/sentinel-agent.py` | 4 | « test_sans_empreinte_autorites_du_systeme_refusent_l_autosigne » |

Les faux services sont de vrais serveurs (carte HTTPS au certificat tiré à la volée, serveur RFB, SYNAPSE, SMTP, écho WebSocket) ; les essais passent par les routes, avec de vrais jetons, de vraies sessions et un vrai TOTP. Ils portent sur les frontières et les chemins d’erreur : chaque route par rôle et par jeton, objets d’un autre agent, codes à usage unique, échecs comptés, commande libre coupée, charges piégées, adresses interdites, certificats non épinglés, trames WebSocket démesurées, révocation, sauvegarde et restauration.

## Repository style profile
Node 24, modules ES, aucune dépendance npm. Serveur : `node:http` sous le portail du socle, `node:sqlite` avec requêtes préparées et `transaction` pour les écritures groupées, `crypto`, WebSocket et RFB écrits à la main. Interface : DOM construit par `h` du socle, jamais de balisage injecté avec une donnée ; noVNC servi sur place. Agent : Python 3, `requests` et `psutil`, sous-processus en liste d’arguments. Vocabulaire : français pour le domaine et tout ce qui est venu avec la version 2 ; les champs du protocole de la 1.x (`host`, `kind`, `payload`, `jobs`, `output`) et les noms de fonctions de l’agent restent en anglais. Erreurs : `ErreurHttp(status, message)` écrite pour l’opérateur ; le socle ne montre jamais le texte d’une erreur imprévue. Configuration : `lireConfigSentinel` sur un schéma, arrêt au démarrage avec toutes les erreurs, secrets par `_FILE`. Journaux : `log.*` pour l’exploitation, `Journal` du socle pour qui a fait quoi (chaîné). Frontières : `src/` (routes, schémas, droits, parc, agents, consoles), `web/`, `agent/`, `socle/` (commun embarqué, modifié dans son propre dépôt seulement), `test/`, `outils/`. Aides reprises plutôt que réécrites : `transaction`, `consolesEffectives`, `identiteEpinglee`/`agentEpingle`, `lookupGarde`/`hoteInterdit`, `chargeRefusee`, `valider` et `Portail.exiger` du socle.

## Detection sweep
Relancé à chaque génération de ce fichier (bash, LC_ALL=C.UTF-8) ; un résultat différent de celui qui a été relu arrête la génération. Annexe B.5 et contrôles des chapitres 41 à 48, sur tout le dépôt hors des deux fichiers de conformité et de noVNC.

| # | Commande | Résultat | Justification |
|---|---|---|---|
| B.5.1 | `cd web/vendor/novnc && grep -E '^  [0-9a-f]{64}  ' PROVENANCE \| sed 's/^  //' \| sha256sum --check --strict --quiet && echo "noVNC conforme ($(grep -cE '^  [0-9a-f]{64}  ' PROVENANCE) fichiers)"` | `noVNC conforme (55 fichiers)` | noVNC est repris tel quel du paquet publié, empreintes de sa provenance vérifiées : c’est du code d’autrui, hors du périmètre des recherches suivantes (`-g '!web/vendor/**'`) |
| B.5.2 | `rg -n '^\s*(#\|//)\s*(Step \d\|Initialize\|Loop through\|Create (a\|an\|the)\|Return the\|Set the\|Get the\|Check if\|Now we\|First,\|Finally,)' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| B.5.3 | `rg -n '^\s*(//\|#\|\*)\s*(Étape \d\|Initialise\|On boucle\|Boucle sur\|Retourne (le\|la\|les\|l.)\|Crée (un\|une\|le\|la)\|Vérifie si\|Maintenant,\|D.abord,\|Enfin,)' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne | la même recherche dans la langue du dépôt |
| B.5.4 | `rg -n '^\s*(#\|//)\s*[-=*_#─]{10,}' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| B.5.5 | `rg -n '^\s*(#\|//)\s*(─{3,}\|-{4} )' src web/*.js agent outils test` | 0 ligne | les bannières plus courtes et les marqueurs « ---- titre ---- » du code de Sentinel, que la recherche précédente ne voit pas |
| B.5.6 | `rg -n -t js -t css -t html -t py '^\s*[-=*_#─]{10,}\s*(\*/)?$' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| B.5.7 | `rg -n 'simplified (implementation\|version)\|in a (real\|production) (system\|app)\|for (demo\|illustration) purposes\|this is just an example' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| B.5.8 | `rg -n --pcre2 '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}]' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| wc -l` | `5` | marques ✓ de fin des scripts d’inscription et de l’agent, lues par l’opérateur dans son terminal ; l’étoile des types d’accès recommandés dans l’interface ; un mot de passe fait d’emoji dans un essai du socle |
| B.5.9 | `rg -n '\b(def\|function\|func\|fn)\s+\w*(process\|handle\|manage\|perform\|execute\|do)_?\w*\s*\(' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| wc -l` | `8` | noms imposés (`init_poolmanager` d’urllib3, `do_GET` et `do_POST` de http.server) et mots français qui contiennent « do » (`dossier`, `windows`) ; aucun gestionnaire générique |
| B.5.10 | `rg -o '\b\w+(Manager\|Service\|Handler\|Provider\|Factory\|Helper\|Util\|Wrapper\|Processor\|Engine)\b' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| cut -d: -f2- \| sort -u` | `BaseHTTPRequestHandler
ServicePointManager` | la classe de la bibliothèque standard dont héritent les faux serveurs des essais de l’agent, et la classe .NET qui règle TLS dans la commande PowerShell |
| B.5.11 | `find . -path ./node_modules -prune -o -path ./web/vendor -prune -o -type f -regextype posix-extended -regex '.*/(utils?\|helpers?\|common\|misc\|shared)\.(py\|ts\|js\|go\|rb\|java)' -print` | 0 ligne | hors de noVNC, qui garde son arborescence d’origine |
| B.5.12 | `rg -n '\b(data\|result\|output\|temp\|tmp\|res\|ret\|val\|obj\|item)\b\s*=' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| wc -l` | `8` | `res`, la réponse HTTP de Node dans les rappels de `http.request` et sa doublure dans un essai du socle (le nom de tout le socle) et la résolution d’une promesse d’essai ; `output`, la colonne de la table des tâches, contrat avec l’agent |
| B.5.13 | `rg -n 'catch\s*\(\s*(e\|err\|error)\s*\)\|catch\s*\{' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| wc -l` | `117` | relus un à un avec les `.catch(` : 154 au total, par raison ci-dessous |
| B.5.14 | `rg -n 'An error occurred\|Something went wrong\|Unexpected error\|Une erreur est survenue\|Quelque chose s.est mal passé' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| B.5.15 | `rg -n 'except\s*:\|except Exception\s*:' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 1 ligne | `except Exception` de la lecture d’inventaire de l’agent, au mieux et dit : un inventaire partiel vaut mieux que pas de remontée ; aucun `except:` nu |
| B.5.16 | `rg -n 'logger\.(info\|debug)\(f?["\x27](Starting\|Entering\|Finished\|Exiting\|Called)' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| 41.1.1 | `git diff --check $(git hash-object -t tree /dev/null) HEAD -- . ':!web/vendor' ':!SECURITY.md' ':!NO-VIBE.md'` | 0 ligne | depuis l’arbre vide : aucune espace en fin de ligne, aucune ligne vide de trop |
| 41.2.1 | `rg -n --pcre2 '[\x{200B}-\x{200D}\x{FEFF}\x{00A0}\x{2028}\x{2029}]' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne | aucun caractère invisible ; la ponctuation typographique française (« », ’, …) est celle de tout le dépôt |
| 45.1.1 | `rg -n ':\s*any\b\|as unknown as' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne | JavaScript sans TypeScript |
| 47.1.1 | `rg -n 'assert\.ok\(true\)\|toBeDefined\(\)\|assert\(true\)\|assertTrue\(True\)' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| 48.3.1 | `rg -n -i 'your-api-key-here\|TODO: implement\|FIXME: AI\|lorem ipsum\|example\.com/api' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| 48.3.2 | `rg -n -i 'placeholder' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**' \| wc -l` | `21` | attributs `placeholder` des champs de l’interface et du socle, leur style, et le champ `placeholder` du manifeste du Hub (une adresse de la plage de documentation) |
| 48.3.3 | `rg -n '\b(TODO\|FIXME\|XXX\|HACK)\b' . -g '!SECURITY.md' -g '!NO-VIBE.md' -g '!web/vendor/**'` | 0 ligne |  |
| 48.4.1 | `git log --all --format='%B' \| rg -i 'co-authored-by\|generated with'` | 0 ligne | tout l’historique |

## Report (chapter 49.6)
Comptes : 38 lignes de bannières et de marqueurs retirées, 1 note recollée à sa fonction, 1 commentaire corrigé, 3 `except` expliqués et 1 `chmod` rendu bruyant, 2 `catch` d’essais expliqués, 2 imports morts et 3 morceaux de code mort retirés, 26 exports ramenés à leur module, 6 duplications repliées, une trentaine de noms génériques remplacés, 1 document corrigé, 1 essai renforcé et 1 essai ajouté, 0 dépendance ajoutée. Fichiers laissés tels quels : les autres — leur densité de commentaires, leurs noms et leur gestion d’erreurs relèvent du profil ci-dessus.

Défauts réels trouvés pendant la passe, corrigés dans leurs propres commits : un contrôle d’upgrade WebSocket calculé puis ignoré ; un échec de `chmod` du fichier du jeton de l’agent tu ; des libellés d’alimentation jamais lus ; un croquis de charge qui recevait deux paramètres sans les lire ; le README qui renvoyait l’incident à la mauvaise page et ignorait la ligne de commande ; deux invariants de sécurité sans essai qui les tienne (cookie de Sentinel seul vers la carte, empreinte d’un certificat signé par le certificat épinglé), trouvés par les cassures volontaires.

Choix non faits, et pourquoi :
- Les noms anglais de l’agent (`poll_jobs`, `run_job`, `pkg_cmd`, `collect_updates`) et les champs du protocole agent-serveur (`hostname`, `kind`, `payload`, `jobs`, `output`, `rc`) restent : ils viennent de la 1.x, les agents déjà posés les parlent, et les renommer changerait le contrat que la passe doit laisser intact.
- Les scripts d’inscription Linux et macOS partagent une douzaine de lignes : ce sont des gabarits de texte lus par l’opérateur avant de les lancer en root ; les assembler par morceaux les rendrait plus difficiles à relire que la répétition.
- Les méthodes internes `_recevoir`, `_trame`, `_envoyer`, `_finir` du WebSocket et `_uneFois` de SYNAPSE gardent leur tiret bas : il marque ce qu’aucun appelant ne doit toucher, dans des classes qui n’ont pas d’autre moyen de le dire.

Commits de la passe :
- `9dc61ca commentaires : bannières et marqueurs de section retirés, un titre gardé quand il dit ce que le code ne dit pas`
- `dbbb34c commentaires : la règle des rôles déclarés rendue à la fonction qui déclare les routes`
- `d6a871c nettoyage : code mort retiré (échappement LIKE, libellés Redfish, contrôle d'upgrade sans effet), exports sans lecteur ramenés à leur module`
- `839996e structure : les accès distants d'une machine lus par le parc seul, plus une seconde lecture dans l'API`
- `13570b3 structure : l'identité d'une carte épinglée vérifiée par une seule fonction, en HTTPS comme en WebSocket`
- `e3d66b6 structure : le rescellement des secrets d'appareils passe par la transaction commune`
- `043ef02 structure : l'état rendu après chaque geste écrit une seule fois dans l'API`
- `6156c02 agents : résolution d'un jeton sans branche en double, son commentaire dit ce qu'elle rend`
- `4da2893 nommage : noms génériques remplacés par ce qu'ils désignent (entrées d'accès, remontée, verdict VNC, carte, en-têtes retirés), dans la langue du dépôt`
- `2bf4dbf défense : chaque exception tue dit pourquoi, le resserrement des droits du jeton de l'agent n'est plus tu en cas d'échec`
- `9569a59 documentation : le déroulé d'incident du README suit celui qui est joué, page Comptes et ligne de commande comprises`
- `99b70d8 nettoyage : imports inutilisés retirés du démarrage et des essais`
- `816d03d interface : la liste des types d'accès écrite une fois, le libellé d'une carte lu dans la table des types plutôt que dans le texte de l'option`
- `20d1fa9 interface : paramètres inutilisés du croquis de charge retirés, noms génériques remplacés`
- `da1733e structure : la reprise de la 1.x passe par la transaction commune`
- `17f3ff6 essais : aucun cookie de Sentinel ne part vers la carte, même quand la carte n'en a posé aucun`
- `4a8e159 essais : un certificat signé par le certificat épinglé n'est pas la carte épinglée, en HTTPS comme en WebSocket`

## Verification (chapter 49)
- [x] Full suite passes and matches the baseline — les 109 essais de la référence, verts avant et après la passe, plus 11 ajouté (120 en tout), relancés à la génération de ce fichier
- [x] Public API diff empty — inventaire de la surface publique identique sur la passe ; depuis, un ajout déclaré, aucun retrait
- [x] Characterisation tests deleted after use — aucun n’a été écrit
- [x] Read-aloud test passed — les 21 fichiers de code touchés par la passe, relus aux endroits touchés, autour de chaque fonction dont une instruction a changé
- [x] Blind-comparison test passed — les passages touchés, commentaires compris, ont la forme de ceux qui les entourent et du socle : même langue, phrases courtes, raisons plutôt que descriptions
- [x] Commit history: one concern per commit, repository style, no attribution trailers
- [x] REQ-CODE-001 to REQ-CODE-006 all PASS
