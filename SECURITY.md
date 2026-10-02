# Security compliance — NEXARC RMM

Standard: Project Baseline Requirements & Security Manual, Edition 2.0 (258 controls)
Audited: 2026-10-02   ·   Owner: Codex64   ·   Status: NON-COMPLIANT

## Summary
| Part | Controls | Pass | Fail | N/A | Unknown |
|---|---|---|---|---|---|
| I — Baseline requirements | 68 | 54 | 12 | 2 | 0 |
| II — Security controls | 190 | 91 | 28 | 71 | 0 |
| Total | 258 | 145 | 40 | 73 | 0 |

## Authentication posture
Deux publics. Les opérateurs passent par le socle commun, embarqué avec ses essais : quatre facteurs cumulables sur chaque compte — mot de passe (Argon2id, 64 Mio, 3 passes, parallélisme 4, plancher 19 Mio / 2 / 1, rehachage transparent, empreinte scrypt de la 1.x reprise puis rehachée à la connexion, liste de fuites locale, 12 à 1024 caractères), application TOTP (RFC 6238, secret généré côté serveur et scellé AES-256-GCM, QR code dessiné dans le navigateur, rejeu refusé), clés d’accès WebAuthn (résidentes, vérification de l’utilisateur exigée, jusqu’à vingt, nommées et révocables) et dix codes de secours de 100 bits hachés. Politique par facteur : mot de passe et TOTP facultatifs, clé requise pour les administrateurs, qui tiennent deux facteurs dont une clé (deux facteurs sans clé en mode HTTP dégradé, affiché partout). Un mot de passe seul n’ouvre qu’une session d’inscription. Sessions serveur (jeton de 256 bits, empreinte seule en base), renouvelées à chaque changement de niveau, 12 heures au plus et 60 minutes d’inactivité, listées et révocables une à une ou toutes ; les WebSockets de console revérifient la session à la mise à niveau ; l’origine à part des consoles web ne s’ouvre que sur une passe de 256 bits tirée sous une session de membre, gardée par son empreinte, morte avec cette session et au plus tard après huit heures. Renfort de cinq minutes avec le facteur le plus fort avant tout changement de facteur, de rôle ou de politique, avant une suppression, un export, un secret d’appareil, un épinglage, une coupure d’alimentation, une commande libre, ou avant de déclarer une console ou une carte. Rôles : lecture (voit le parc), membre (tâches, réveil, allumage, acquittement), administrateur (commande libre, secrets et accès distants, alimentation qui coupe, comptes). Les machines présentent un jeton d’agent de 192 bits, propre à chacune, gardé en SHA-256, obtenu contre un code d’inscription de 128 bits à usage unique, gardé haché, valable une heure ; le Hub présente un jeton de service (Bearer, 24 caractères au moins, comparé en temps constant) qui n’ouvre que l’état, les tâches (sans la commande libre) et le réveil. Limiteur persistant par adresse et par compte pour les humains, preuve de travail après trois échecs, paliers de verrouillage ; échecs de code et de jeton de machine plafonnés par adresse. La clé maîtresse et le poivre se tournent sans réinscription.


## Findings (audit before fixes)
Relevés en lecture seule avant toute correction (« * » : relevés pendant les corrections et le sondage exploratoire), classés par gravité ; chacun est corrigé dans cette passe par le commit indiqué, avec son essai quand un essai peut l’exprimer.

| # | Gravité | Contrôles | Constat | Commits |
|---|---|---|---|---|
| C1 | CRITICAL | REQ-WEB-002, REQ-WEB-003, SEC-XSS-001, SEC-XSS-004, SEC-HDR-002, SEC-HDR-005, SEC-BE-001 | Le mandataire des consoles servait le HTML d’une carte de gestion sous l’origine de NEXARC, sans politique de script, avec un script en ligne injecté et les en-têtes de cache de la carte : le code d’une carte s’exécutait avec les droits d’une session de NEXARC. | 6b55554, c143c6e |
| C2 | CRITICAL | SEC-CSRF-004, REQ-WEB-005, SEC-AUTHZ-002 | Un simple membre déclarait les adresses internes que le serveur joint (consoles, cartes, nœuds Mesh) ; le mandataire transmettait à la carte le cookie de session de NEXARC. | 5bf30c5, 2e2051c |
| C3 | CRITICAL | REQ-WEB-006, SEC-AUTHZ-002, SEC-AUTHZ-007, SEC-AUTHZ-008 | Une automatisation « commande libre » se réactivait ou se supprimait par un membre et s’exécutait même avec NEXARC_ALLOW_EXEC coupé ; la charge d’une tâche n’était pas validée selon son type, un réveil pouvait viser n’importe quelle adresse. | 201bd1a, d844a37 |
| C4 | CRITICAL | REQ-AUTH-010, SEC-AUTH-003 | Codes d’inscription, jetons d’agents et jeton du Hub sans plafond d’échecs : seul le débit global de 900 requêtes par minute bornait une recherche exhaustive. | 878383a |
| C5 | HIGH | REQ-CRYPT-005, REQ-CRYPT-006 | Code d’inscription de 72 bits, gardé en clair : une lecture de la base donnait des codes encore échangeables contre un jeton d’agent. | 4b84069 |
| C6 | HIGH | REQ-CFG-004, SEC-SECRETS-007, SEC-SECRETS-008 | Clé de connexion Mesh mal formée et jeton SYNAPSE court ou d’exemple acceptés au démarrage. | cc370ed |
| C7 | HIGH | REQ-CFG-005, SEC-LOG-007 | Aucune révocation des jetons d’agents, ni d’un poste ni du parc, sans supprimer les machines et leur historique. | f5c8825 |
| C8 | HIGH | REQ-WEB-005, SEC-CSRF-003 | Trois GET changeaient l’état : tirer un code, l’échanger, relever ses tâches. | b2d52fb |
| C9 | HIGH | REQ-DATA-004, SEC-LOG-001, SEC-DB-010 | Refus décidés par NEXARC, jetons et codes de machine refusés, automatisations, accès distants, réveils et bureaux Mesh absents du journal chaîné. | 8f73149, 5bf30c5, 201bd1a, c403eac |
| C10 | HIGH | REQ-DATA-002 | Redfish acceptait une carte en HTTP et lui envoyait ses identifiants en clair. | 2665875 |
| C11 | HIGH | REQ-CI-003, SEC-DEP-001, SEC-DEP-004 | Dépendances de l’agent en plages de versions, installées sur les postes sans empreinte. | 473830a |
| C12 | HIGH | REQ-DATA-003 | Aucune sauvegarde : rien ne sortait un instantané chiffré de la base. | ced7d3d |
| C13 | HIGH | SEC-API-004 | * La sortie d’une commande libre était rendue à tout compte qui lit le parc, lecture seule comprise. | 76ef8b4 |
| C14 | HIGH | SEC-AUTHZ-003 | * Le rôle de relais venait de la remontée de l’agent : un poste se déclarait relais et recevait les réveils de son segment. | 23936f5 |
| C15 | HIGH | REQ-AUTH-006, REQ-DATA-005 | * Relevé en préparant la mise à jour : l’opérateur d’une 1.x resté au mot de passe d’amorçage était repris sans mot de passe, seul administrateur, sans aucun moyen de reprendre la main (personne pour lui envoyer un lien). | 1048ff3 |
| C16 | MEDIUM | REQ-WEB-008, SEC-API-002, SEC-API-003 | Mises à niveau WebSocket hors du débit, flux d’activité et automatisations sans plafond, inventaire de 512 Kio lu et validé avant le jeton de l’agent. | 9db7974 |
| C17 | MEDIUM | SEC-XSS-006, SEC-API-007 | Message réseau et réponse brute d’une carte rendus au client ; échange d’un code, remontée, relève, passage d’automatisation et acquittement écrits en plusieurs requêtes sans transaction. | fd4ed01, 82e0c38 |
| C18 | MEDIUM | SEC-DB-004 | Installé seul, la clé maîtresse se créait dans le volume de données, à côté de ce qu’elle scelle. | b92e3a0 |
| C19 | MEDIUM | REQ-CI-002 | Analyse statique sans l’agent Python ; aucune mise à jour proposée pour les actions, l’image et les dépendances de l’agent. | 8b742f6 |
| C20 | MEDIUM | REQ-WEB-006 | * Paramètres de requête lus sans schéma et références du chemin sans contrôle de forme. | e480fc9 |
| C21 | MEDIUM | SEC-CSRF-004 | * Les appels à SYNAPSE suivaient une redirection, jeton compris. | 148b701 |
| C22 | MEDIUM | SEC-SECRETS-004 | * Sous Windows, le dossier du jeton de l’agent héritait des droits de lecture des utilisateurs du poste. | 50f6326 |
| C23 | MEDIUM | REQ-WEB-008 | * Le WebSocket écrit à la main renvoyait en écho une trame de contrôle fragmentée ou de plus de 125 octets. | aca6b33 |
| C24 | LOW | SEC-API-007 | * Régression de cette passe (introduite par 8f73149), relevée par le sondage : une commande libre venue du Hub, ou avec le réglage coupé, finissait en erreur interne (500) au lieu d’un refus 403. | cfebf32 |
| C25 | LOW | REQ-DATA-005, SEC-PRIV-003 | * Runbook jamais déroulé ; notice de confidentialité muette sur les sauvegardes et l’origine des consoles. | 694d771, e63412a |

## Control status
| ID | Severity | Status | Evidence | Notes |
|---|---|---|---|---|
| REQ-AUTH-001 | CRITICAL | PASS | `socle/src/comptes.js:24` ; mot de passe, TOTP, clés et codes de secours cumulables : essai `socle/test/parcours.test.js:135` | socle embarqué, ses essais rejoués par la vérification de NEXARC (`.github/workflows/verification.yml:38`) ; QR code du TOTP dessiné dans le navigateur (`socle/web/qr.js:240`) |
| REQ-AUTH-002 | CRITICAL | PASS | `socle/src/comptes.js:27` ; `socle/src/index.js:49` ; réglable sans déploiement : `socle/src/portail.js:460` | défaut : mot de passe et TOTP facultatifs, clé requise pour les administrateurs |
| REQ-AUTH-003 | CRITICAL | PASS | `socle/src/webauthn.js:26` ; vingt clés nommées : `socle/src/comptes.js:35` ; renommer et retirer : `socle/src/portail.js:300` | liste avec dates de création et d’usage dans la page Sécurité |
| REQ-AUTH-004 | CRITICAL | PASS | `socle/src/webauthn.js:46` ; origine `socle/src/webauthn.js:47` ; rpIdHash `socle/src/webauthn.js:103` | défi à usage unique lié à la session, UP et UV exigés, signature et compteur vérifiés |
| REQ-AUTH-005 | CRITICAL | PASS | `socle/src/comptes.js:640` ; renfort et fermeture des autres sessions : `socle/src/comptes.js:656` | la notification part à l’adresse vérifiée quand un relais existe (voir REQ-AUTH-014) |
| REQ-AUTH-006 | CRITICAL | PASS | `socle/src/comptes.js:888` ; jeton de 20 minutes, haché, unique : `socle/src/comptes.js:33` | essai `socle/test/parcours.test.js:218` ; rejoué par le runbook (`outils/exercice-incident.mjs:77`) ; l’opérateur de la 1.x repris sans mot de passe est remis en selle par ce lien (`src/migration.js:34`) |
| REQ-AUTH-007 | HIGH | PASS | `socle/src/comptes.js:36` ; 100 bits, haché Argon2id, usage unique : `socle/src/comptes.js:440` | alerte « secours.utilise » (courriel si relais, voir REQ-AUTH-014) ; la 1.x n’avait pas de codes de secours |
| REQ-AUTH-008 | HIGH | PASS | `socle/src/totp.js:35` ; rejeu refusé : `socle/src/comptes.js:532` | RFC 6238, 6 chiffres, 30 s, ±1 pas, secret scellé AES-256-GCM ; le secret TOTP en clair de la 1.x est scellé à la reprise (`src/migration.js:36`) |
| REQ-AUTH-009 | CRITICAL | PASS | aucune voie SMS ni code par courriel : `grep -rniE "sms\|twilio" socle/src src` → 0 ; connexions possibles : `socle/src/comptes.js:373`, `socle/src/comptes.js:399`, `socle/src/comptes.js:421`, `socle/src/comptes.js:486` | un mot de passe seul n’ouvre qu’une session d’inscription ; un code d’inscription ou un jeton d’agent n’ouvre jamais de session humaine |
| REQ-AUTH-010 | CRITICAL | PASS | humains : `socle/src/limiteur.js:20` (SQLite, par adresse et par compte, paliers de verrou, preuve de travail après trois échecs) ; codes d’inscription, jetons d’agents et jeton du Hub : chaque échec compte pour l’adresse dans le même limiteur persistant, sous une clé à part (`src/api.js:97`, `src/api.js:100`) : dix échecs bloquent une minute, puis par paliers jusqu’à une heure | essai `test/nexarc.test.js:289` (dix 401 puis 429, verrou journalisé, connexions humaines à part) ; ces secrets de machine (128 à 256 bits) n’ont ni compte à verrouiller ni navigateur pour une preuve de travail : le verrou de l’adresse en tient lieu ; un agent refusé se tait plus d’une heure (`agent/nexarc-agent.py:55`) |
| REQ-AUTH-011 | HIGH | PASS | vérification leurre : `socle/src/argon.js:110` ; message unique | essai `socle/test/parcours.test.js:81` |
| REQ-AUTH-012 | HIGH | PASS | `socle/src/comptes.js:927` : l’adresse n’existe que dans le jeton haché tant qu’elle n’est pas vérifiée ; `socle/src/comptes.js:936` | l’adresse ne sert qu’aux alertes : ni identifiant, ni récupération, ni droit ; pas d’inscription libre (invitation seulement) |
| REQ-AUTH-013 | HIGH | PASS | `socle/src/comptes.js:726` | l’opérateur de la 1.x devient administrateur et doit inscrire une clé avant tout accès complet |
| REQ-AUTH-014 | MEDIUM | FAIL | `socle/src/notifications.js:97` ; « ce n’était pas moi » : `socle/src/comptes.js:914` | implémenté et essayé (`socle/test/courriel.test.js:63`) ; ne part que si un relais SMTP est configuré → action H2 |
| REQ-CRYPT-001 | CRITICAL | PASS | `socle/src/argon.js:15` ; 64 Mio, t=3, p=4 par défaut : `socle/src/index.js:42` | Argon2id natif de Node, sel de 16 octets par empreinte ; les essais tournent aux paramètres de production |
| REQ-CRYPT-002 | HIGH | PASS | `socle/src/argon.js:72` ; écrit dans la même requête : `socle/src/argon.js:129` | l’empreinte scrypt de la 1.x est reprise telle quelle puis passe en Argon2id à la connexion suivante : essai `test/nexarc.test.js:781` |
| REQ-CRYPT-003 | MEDIUM | N/A | bcrypt absent : `grep -rniE "bcrypt" socle/src src agent` → 0 ; Argon2id seul |  |
| REQ-CRYPT-004 | HIGH | PASS | `socle/src/motdepasse.js:12`, `socle/src/motdepasse.js:13`, liste de fuites locale `socle/src/motdepasse.js:18` | contrôlé côté serveur, sans règle de composition ni rotation forcée |
| REQ-CRYPT-005 | HIGH | PASS | `socle/src/outils.js:16` ; codes d’inscription de 128 bits : `src/agents.js:37` ; jetons d’agents de 192 bits : `src/agents.js:55` ; passes de console de 256 bits : `src/origine-consoles.js:54` ; jeton du Hub comparé en temps constant : `src/api.js:111` ; `grep -rnE "Math\.random\|uuidv1" src web/*.js agent` → 0 | codes, jetons et passes retrouvés par leur empreinte SHA-256, jamais comparés en clair |
| REQ-CRYPT-006 | MEDIUM | PASS | jetons d’agents : `src/agents.js:19` ; codes d’inscription : `src/agents.js:22`, l’ancienne table en clair écartée (`src/base.js:42`) ; passes de console gardées par leur empreinte : `src/origine-consoles.js:55` ; sessions : `socle/src/comptes.js:273` | essais `test/nexarc.test.js:210` et `test/nexarc.test.js:810` |
| REQ-SESS-001 | CRITICAL | PASS | `socle/src/http.js:103` ; __Host- en HTTPS : `socle/src/portail.js:50` ; essai `test/nexarc.test.js:125` | aucune session dans le stockage du navigateur ; aucun cookie de NEXARC ne part vers une carte (`src/proxy.js:87`) |
| REQ-SESS-002 | CRITICAL | PASS | `socle/src/comptes.js:283` à la connexion, au renfort et à chaque changement de facteur ou de rôle | pas de jeton de rafraîchissement : sessions serveur |
| REQ-SESS-003 | HIGH | PASS | `socle/src/comptes.js:319` ; révocation : `socle/src/portail.js:310` et incident : `socle/src/portail.js:473` | appareil, adresse IP, première et dernière vue ; une passe de console meurt avec sa session (`src/origine-consoles.js:51`) |
| REQ-SESS-004 | HIGH | PASS | `socle/src/comptes.js:658` ; déconnexion serveur : `socle/src/portail.js:267` | les WebSockets de console revérifient la session à la mise à niveau ; runbook : `outils/exercice-incident.mjs:59` |
| REQ-SESS-005 | HIGH | PASS | `socle/src/comptes.js:335` ; routes de NEXARC sous renfort : accès distants et secrets d’appareils, cartes, nœuds Mesh, épinglage, suppressions (`grep -c "session(ctx, { role: 'admin', renfort: true })" src/api.js` → 8), coupure d’alimentation (`src/api.js:286`), commande libre en tâche comme en automatisation (`src/api.js:349`) | essais `test/nexarc.test.js:493` et `test/nexarc.test.js:992` |
| REQ-SESS-006 | MEDIUM | PASS | 12 h absolues, 60 min d’inactivité : `socle/src/index.js:40` | pas de JWT ; passe de console : huit heures au plus, jamais au-delà de sa session (`src/origine-consoles.js:20`) |
| REQ-ANON-001 | CRITICAL | PASS | `git log --all --format="%an <%ae>" \| sort -u` et `--format="%cn <%ce>"` → une ligne chacun, le pseudonyme ; posée dans le dépôt : `git config --local user.name` → 1 | dépôt neuf de la version 2, commits en UTC |
| REQ-ANON-002 | CRITICAL | PASS | arbre : annexe B.1 → une seule correspondance, le nom `.env.local` dans `.gitignore:10` ; aucun terme de la liste d’anonymat ; historique local complet : le motif « infrastructure personnelle » ne relève que des mots qui le contiennent (annexe B ci-dessous) | l’historique de la 1.x n’est pas dans ce dépôt : il vit sur l’ancien dépôt publié, qui expose des termes de la liste (section Anonymity) et que seul l’exploitant peut remplacer → action H12 |
| REQ-ANON-003 | CRITICAL | FAIL | liste et crochet global à poser sur le poste de développement ; contrôle CI par secret : `.github/workflows/verification.yml:92` | action H4 |
| REQ-ANON-004 | CRITICAL | PASS | commande de REQ-ANON-004 sur tout l’historique (`git log --all --format=%B \| grep -niE "co-authored-by\|generated with\|assistant\|claude\|copilot\|cursor\|gpt\|🤖"`) → 0 | contrôlé en CI sur chaque nouveau commit : `.github/workflows/verification.yml:70` |
| REQ-ANON-005 | HIGH | PASS | `package.json:6` sans champ auteur ; `LICENSE:3` | le README décrit le logiciel, jamais une machine ni une personne ; contact de sécurité : le signalement privé du dépôt (`src/main.js:26`) |
| REQ-ANON-006 | HIGH | PASS | `git log --all --name-only --format= \| grep -iE "\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$" \| wc -l` → 0 : aucune image ni document binaire dans tout l’historique ; l’icône est un SVG sans métadonnées (`web/icone.svg:1`) | polices WOFF2 du socle : métadonnées de la fonderie seulement ; captures du parcours gardées hors dépôt |
| REQ-ANON-007 | HIGH | PASS | comptes « ana », « bruno », « chloe », « lea », « dora », « victor » ; machines « poste-x », « serveur-a », « srv-alim » ; adresses de la plage de documentation (`test/nexarc.test.js:57`) ; jetons d’essai fabriqués (`test/nexarc.test.js:24`) ; certificats d’essai tirés à la volée (`test/faux.js:72`) | essais, outils et exemples relus ; les plages privées n’apparaissent que dans le classement des adresses, assemblées à l’exécution (`src/reseau.js:18`) |
| REQ-ANON-008 | MEDIUM | PASS | `git log --all --format=%aI \| grep -v "+00:00$" \| wc -l` → 0 ; `git log --all --format=%cI \| grep -v "+00:00$" \| wc -l` → 0 | auteur et validateur en UTC sur tout l’historique |
| REQ-ANON-009 | MEDIUM | FAIL | pages d’erreur sans chemin : `socle/src/http.js:163` ; domaine et WHOIS hors dépôt | action H13 |
| REQ-ANON-010 | MEDIUM | PASS | identité stable et unique, dates réelles (TZ=UTC, jamais antidatées) | aucune politique de contribution externe |
| REQ-CFG-001 | CRITICAL | PASS | gitleaks sur tout l’historique, toutes références comprises (`--log-opts=--all`), relancé à chaque génération de ce fichier → aucune fuite ; `git grep` de l’annexe B.2 → valeurs d’essai fabriquées et vecteur publié de la RFC 6238 ; `-----BEGIN … PRIVATE` → 0 | détail dans l’annexe B ci-dessous |
| REQ-CFG-002 | CRITICAL | PASS | secrets d’appareils jamais rendus : `src/base.js:126` ; identifiants Redfish réduits à « en place » (`src/base.js:153`) ; jeton d’agent échangé par l’agent lui-même, jamais par le navigateur | aucune construction : web/ est servi tel quel ; essais `test/nexarc.test.js:486`, `test/nexarc.test.js:424` |
| REQ-CFG-003 | HIGH | FAIL | VM d’essai et production distinctes (instruction de l’exploitant) | clés séparées par environnement à vérifier et à émettre : action H6 |
| REQ-CFG-004 | HIGH | PASS | `src/config.js:9` sur `socle/src/config.js:14` : clé Mesh de 32 à 80 octets hexadécimaux (`src/config.js:54`), jeton SYNAPSE de 24 caractères au moins et jamais une valeur d’exemple (`src/config.js:60`), secret de clé maîtresse vide refusé (`src/config.js:13`), origine des consoles sans chemin (`src/config.js:70`) | essai `test/nexarc.test.js:823` ; aucun mode de débogage ni contournement par variable |
| REQ-CFG-005 | HIGH | PASS | chaque secret, son lieu et sa rotation : section « Secrets inventory » ci-dessous ; SOCLE_CLE tournée de bout en bout (`outils/exercice-rotation.mjs:1`, 24 vérifications le 2026-09-30) ; jeton d’un agent ou de tout le parc révoqué sans perdre la machine : `src/cli.js:60` | essai `test/nexarc.test.js:249` ; runbook joué par `outils/exercice-incident.mjs:99` (23 vérifications le 2026-09-30) ; clés chez les fournisseurs : actions H5, H6 |
| REQ-CI-001 | CRITICAL | FAIL | `.github/workflows/verification.yml:58` | Actions, crochet local et protection de poussée à activer : actions H3, H4 |
| REQ-CI-002 | HIGH | FAIL | CodeQL, requêtes « security-extended », sur le serveur et sur l’agent : `.github/workflows/verification.yml:117` | bloquant une fois les Actions actives et le contrôle requis : action H3 |
| REQ-CI-003 | HIGH | FAIL | aucune dépendance npm (`package.json:8` sans dépendances) ; image de base épinglée `Dockerfile:6` ; dépendances de l’agent à version exacte, chaque fichier par son empreinte (`agent/requirements.txt:6`), installées par empreinte sur les postes (`src/enroll.js:47`) comme en CI (`.github/workflows/verification.yml:36`) ; mises à jour proposées, jamais appliquées seules (`.github/dependabot.yml:14`) ; crible de l’image `.github/workflows/publish.yml:53` ; SBOM `.github/workflows/publish.yml:89` | le dépôt est prêt ; l’exécution en CI, les alertes Dependabot et le contrôle requis dépendent de GitHub : action H3 |
| REQ-CI-004 | HIGH | FAIL | `.github/workflows/verification.yml:92` | échoue tant que le secret n’existe pas : action H4 |
| REQ-CI-005 | MEDIUM | FAIL | permissions minimales `.github/workflows/verification.yml:15` ; actions épinglées par commit | protection de branche : action H3 |
| REQ-CI-006 | MEDIUM | PASS | `test/nexarc.test.js:159` (sans preuve → 401, lecture sur écriture → 403, membre sur route d’administration → 403) ; listes figées dans l’essai : `test/nexarc.test.js:186` | objets d’un agent essayés depuis un autre agent (`test/nexarc.test.js:230`) ; cassures volontaires : NO-VIBE.md |
| REQ-WEB-001 | CRITICAL | FAIL | HSTS dès que la requête est chiffrée : `socle/src/http.js:86` | NEXARC est servi en HTTP sur le réseau local tant qu’aucun relais TLS n’est posé : action H1 |
| REQ-WEB-002 | HIGH | PASS | chaque page de NEXARC : `src/main.js:106` sur `socle/src/http.js:62` (script-src 'self' et un nonce par requête, object-src 'none', base-uri 'none', frame-ancestors 'none', aucun unsafe-inline ni unsafe-eval pour les scripts) ; seules l’origine des consoles et, intégré, le bureau Mesh s’y affichent en cadre (`src/main.js:98`) ; le code d’une carte ne s’exécute jamais sous l’origine de NEXARC : servi par une origine à part (`src/origine-consoles.js:26`), encadrable par la seule page qui a tiré la passe (`src/proxy.js:111`), réancré par un script servi, jamais en ligne (`src/proxy.js:48`) | essais `test/nexarc.test.js:108` et `test/nexarc.test.js:506` ; parcours navigateur du 2026-09-30 : 84 écrans et largeurs, aucune erreur en console ; même hôte et autre port : scripts séparés, cookies non (README, « Consoles et cartes de gestion ») |
| REQ-WEB-003 | HIGH | PASS | NEXARC : `socle/src/http.js:79`, Referrer-Policy, Permissions-Policy, X-Frame-Options, COOP, CORP, no-store, ni Server ni X-Powered-By (annexe B.4) ; origine des consoles : nosniff, no-referrer, no-store, COOP, capacités fermées sauf plein écran et presse-papiers (`src/origine-consoles.js:85`), en-têtes de la carte remplacés (`src/proxy.js:19`) | essai `test/nexarc.test.js:551` ; HSTS dès HTTPS (H1) |
| REQ-WEB-004 | HIGH | PASS | aucun en-tête CORS émis : `curl -sI -H "Origin: https://evil.example" /api/state` → aucun Access-Control-* (annexe B.4) | API de même origine pour le navigateur ; agents et Hub appellent de serveur à serveur ; l’origine des consoles n’émet pas de CORS non plus |
| REQ-WEB-005 | HIGH | PASS | CSRF : `socle/src/portail.js:92` (SameSite=Strict, origine et jeton) ; JSON exigé : `socle/src/http.js:120` ; aucun GET n’écrit : code tiré, échangé, tâches relevées en POST (`src/api.js:409`, `src/api.js:430`, `src/api.js:515`) ; SSRF : adresses internes déclarées par un administrateur sous renfort, métadonnées et plages réservées refusées en littéral comme à la résolution (`src/reseau.js:52`), SYNAPSE sans redirection suivie (`src/synapse.js:34`) ; aucun cookie de NEXARC ne part vers une carte (`src/proxy.js:87`) ; aucune redirection pilotée par paramètre | essais `test/nexarc.test.js:184`, `test/nexarc.test.js:491`, `test/nexarc.test.js:545`, `test/nexarc.test.js:724` ; aucun webhook reçu |
| REQ-WEB-006 | CRITICAL | PASS | corps : schéma strict, champ inconnu refusé (`socle/src/schema.js:69`) ; paramètres de requête : schéma par route, tout paramètre non déclaré refusé (`src/api.js:597`) ; références du chemin au format des références publiques (`src/api.js:592`) ; charge d’une tâche validée selon son type (`src/taches.js:22`) ; rôle vérifié dans chaque gestionnaire, objets d’un agent filtrés par sa machine ; erreurs génériques (`socle/src/http.js:163`) | essais `test/nexarc.test.js:159`, `test/nexarc.test.js:347`, `test/nexarc.test.js:193` ; sondage exploratoire ci-dessous |
| REQ-WEB-007 | HIGH | PASS | requêtes préparées partout ; aucun processus lancé par le serveur (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; l’agent n’appelle que des binaires fixes, arguments en liste (`agent/nexarc-agent.py:165`) ; valeurs des scripts d’inscription contrôlées par motif puis entre apostrophes (`src/enroll.js:17`) ; `innerHTML` seulement dans le gabarit du socle, sur du balisage écrit dans le code (`socle/web/gabarit.js:115`) | eval et Function absents ; la commande libre est la fonction elle-même (voir SEC-INJ-004) |
| REQ-WEB-008 | MEDIUM | PASS | débit global par adresse `src/main.js:96`, mises à niveau WebSocket comprises (`src/main.js:121`), et sur l’origine des consoles ; flux d’activité plafonnés (`src/main.js:31`) ; automatisations bornées (`src/base.js:19`) ; tâches par 25, alertes par 500, parc par NEXARC_MAX_MACHINES ; corps bornés à 64 Kio (512 Kio pour un inventaire, lu seulement après le jeton : `src/api.js:507`) ; `?limit=100000` refusé (paramètre non déclaré) | essai `test/nexarc.test.js:309` ; aucun appel à une IA |
| REQ-DATA-001 | CRITICAL | PASS | SQLite embarqué, aucun port : `src/base.js:38` ; dossier en 0700 et base en 0600 : `src/base.js:36` |  |
| REQ-DATA-002 | HIGH | FAIL | secrets d’appareils et TOTP scellés AES-256-GCM : `socle/src/chiffre.js:60` ; trafic vers les cartes en TLS épinglé, Redfish en HTTPS seulement (`src/redfish.js:25`, `src/api.js:25`) | restent le chiffrement du disque des hôtes et HTTPS vers NEXARC lui-même : actions H7, H1 |
| REQ-DATA-003 | HIGH | FAIL | sauvegarde chiffrée pour une clé publique RSA : `src/cli.js:77` ; restauration ailleurs avec la clé privée seule : `src/cli.js:23` ; restauration réelle puis démarrage sur la base restaurée : `outils/exercice-incident.mjs:90` (2026-09-30, instance d’essai) | essai `test/nexarc.test.js:267` ; planification quotidienne, copie hors hôte, trente jours de garde et restauration datée sur la VM : action H8 |
| REQ-DATA-004 | HIGH | PASS | socle : connexions, facteurs, rôles, refus (`socle/src/portail.js:104`), verrous du limiteur ; NEXARC : refus décidés par l’API (`src/api.js:602`) et par l’origine des consoles (`src/origine-consoles.js:109`), jetons et codes de machine refusés (`src/api.js:101`), accès distants, cartes, nœuds Mesh, secrets et épinglage, alimentation, réveils (`src/api.js:340`), consoles ouvertes, automatisations, tâches, révocations et sauvegardes en ligne de commande ; jamais un secret : `socle/src/journal.js:10` | essais `test/nexarc.test.js:651`, `test/nexarc.test.js:534`, `test/nexarc.test.js:503` |
| REQ-DATA-005 | MEDIUM | PASS | vigie : `socle/src/vigie.js:11` (connexions, refus, limites, erreurs internes), jetons et codes de machine refusés compris (`src/api.js:101`) ; runbook d’une page ci-dessous, joué de bout en bout sur une instance lancée comme en production le 2026-09-30 (`outils/exercice-incident.mjs:99`, 23 vérifications) : détection au journal, sessions fermées en une requête, commande libre et Hub coupés au redéploiement, jetons d’agents révoqués, mot de passe forcé, restauration | rotation de SOCLE_CLE jouée à part (`outils/exercice-rotation.mjs:1`) ; alertes hors de l’application par courriel : action H2 |
| REQ-DATA-006 | MEDIUM | PASS | `web/confidentialite.txt:7` ; alertes résolues gardées trente jours (`src/alertes.js:15`), flux d’activité borné à soixante lignes, codes et jetons en attente purgés à expiration ; export et effacement : `src/main.js:79` | essai `test/nexarc.test.js:682` |
| REQ-DATA-007 | MEDIUM | N/A | aucun envoi de fichier ni import depuis une adresse : corps JSON seulement (`socle/src/http.js:120`), `grep -rniE "multipart\|busboy\|formidable" src socle/src` → 0 |  |
| REQ-CODE-001 | HIGH | PASS | essais de référence relevés avant la passe (voir NO-VIBE.md) ; surface publique inchangée : mêmes routes, mêmes schémas, mêmes codes | voir NO-VIBE.md |
| REQ-CODE-002 | HIGH | PASS | voir NO-VIBE.md, couche des commentaires |  |
| REQ-CODE-003 | HIGH | PASS | voir NO-VIBE.md, couches structurelle et défensive |  |
| REQ-CODE-004 | HIGH | PASS | voir NO-VIBE.md, profil de style du dépôt |  |
| REQ-CODE-005 | MEDIUM | PASS | cassures volontaires, chacune détectée par au moins un essai : NO-VIBE.md, « Tests » |  |
| REQ-CODE-006 | MEDIUM | PASS | un sujet par commit, message d’une seule ligne dans le style du dépôt : `git log --format=%b \| grep -c .` → 0 (aucun corps, aucune ligne de fin) ; `git log --format=%B \| grep -ciE "co-authored\|generated\|claude\|anthropic\|assistant"` → 0 ; `git log --shortstat` : réécriture découpée par sujet (serveur en huit commits, interface en deux) : le plus gros commit de code écrit ici ajoute 967 lignes dans 3 fichiers (agent) ; seuls les deux composants embarqués entrent chacun en un commit, copies vérifiées par leurs empreintes (socle : `socle/EMPREINTES:14` ; noVNC 1.5.0 : `web/vendor/novnc/PROVENANCE:37`) | en UTC : `git log --format=%cI \| grep -v "+00:00$" \| wc -l` → 0 ; relevés commités seuls, jamais mêlés à un changement |
| GOV-001 | HIGH | PASS | ce document : revue datée, périmètre (258 contrôles), résolution ligne par ligne, deux passes complètes | à refaire à chaque changement généré important |
| GOV-002 | MEDIUM | PASS | section « Inventory » ci-dessous : routes, données, tiers, secrets |  |
| GOV-003 | LOW | FAIL | `socle/src/portail.js:142` ; contact : `src/main.js:26` | `curl /.well-known/security.txt` → Contact et Expires ; activer le signalement privé sur le dépôt : action H3 |
| GOV-004 | MEDIUM | FAIL | VM d’essai distincte de la production (règle de l’exploitant) ; données d’essai fabriquées | secrets et comptes tiers distincts à confirmer : action H6 |
| GOV-005 | HIGH | FAIL | jeton CI éphémère et limité : `.github/workflows/publish.yml:27` | 2FA sur GitHub et consoles des fournisseurs : action H3 |
| SEC-SECRETS-001 | CRITICAL | PASS | gitleaks sur tout l’historique → aucune fuite ; `git grep` de REQ-CFG-001 → valeurs d’essai seulement | gitleaks en CI (H3) |
| SEC-SECRETS-002 | CRITICAL | PASS | aucune variable publique ni construction : web/ servi tel quel, `grep -rnE "\bsk-[A-Za-z0-9_-]{20}\|sk_live\|service_role\|-----BEGIN" web/*.js web/*.html socle/web` → 0 | rien n’est injecté dans le code servi, sauf le nonce CSP : `web/index.html:11` |
| SEC-SECRETS-003 | CRITICAL | PASS | `.gitignore:9` ; seuls web/ et socle/web sont servis, tout segment caché → 404 (annexe B.2, `/.env` demandé à l’instance d’essai) | secrets vides dans `.env.example:9` |
| SEC-SECRETS-004 | HIGH | PASS | installé par le Hub : secrets posés depuis son coffre (`deploy/compose.hub.yml:55`) ; installé seul : secret Docker hors du volume (`docker-compose.yml:14`) ; fichiers acceptés : `socle/src/config.js:5` | jamais dans la CI |
| SEC-SECRETS-005 | HIGH | FAIL | une clé par usage, lue par NEXARC seul | restreindre et séparer les clés par environnement : action H6 |
| SEC-SECRETS-006 | HIGH | FAIL | procédures de rotation ci-dessous ; SOCLE_CLE exercée de bout en bout (`outils/exercice-rotation.mjs:1`) | jetons et mots de passe vus pendant le développement : action H5 |
| SEC-SECRETS-007 | HIGH | PASS | clé maîtresse de 32 octets aléatoires : `socle/src/chiffre.js:24` ; jeton du Hub et jeton SYNAPSE de 24 caractères au moins (`src/config.js:22`, `src/config.js:60`) ; clé de connexion Mesh de 32 à 80 octets hexadécimaux (`src/config.js:54`) ; valeurs d’exemple refusées : `socle/src/config.js:54` | essai `test/nexarc.test.js:823` ; codes, jetons d’agents et passes tirés par le serveur (voir REQ-CRYPT-005) |
| SEC-SECRETS-008 | MEDIUM | PASS | `src/config.js:9` : une valeur invalide arrête le démarrage avec la liste des erreurs, clé Mesh et jeton SYNAPSE compris ; aucun mode de débogage ; mode HTTP dégradé affiché en permanence : `socle/web/compte.js:703` | essai `test/nexarc.test.js:823` |
| SEC-AUTH-001 | CRITICAL | PASS | voir REQ-CRYPT-001 |  |
| SEC-AUTH-002 | MEDIUM | PASS | voir REQ-CRYPT-004 |  |
| SEC-AUTH-003 | CRITICAL | PASS | voir REQ-AUTH-010 : humains par adresse et par compte, codes et jetons de machine par adresse, dans le même limiteur persistant |  |
| SEC-AUTH-004 | MEDIUM | PASS | voir REQ-AUTH-011 |  |
| SEC-AUTH-005 | CRITICAL | PASS | voir REQ-AUTH-006 ; lien depuis l’adresse publique : `socle/src/portail.js:55` | sans adresse publique, l’origine attestée par le navigateur de l’administrateur, contrôlée sur la même requête |
| SEC-AUTH-006 | MEDIUM | PASS | confirmation sur la nouvelle adresse et avis à l’ancienne : `socle/src/comptes.js:942` | essai `socle/test/courriel.test.js:122` |
| SEC-AUTH-007 | HIGH | PASS | TOTP et clés pour tous, second facteur imposé aux administrateurs : `socle/src/comptes.js:161` | codes de secours toujours émis |
| SEC-AUTH-008 | HIGH | N/A | aucune connexion par fournisseur externe : `grep -rniE "oauth\|openid\|id_token\|redirect_uri" socle/src src` → 0 |  |
| SEC-AUTH-009 | HIGH | PASS | les liens reçus par courriel demandent un geste : `socle/web/compte.js:449` ; uniques et courts : `socle/src/comptes.js:34` | aucune connexion sans mot de passe par courriel |
| SEC-AUTH-010 | CRITICAL | PASS | chaque route non publique appelle `session()` en tête : `src/api.js:114` ; jeton du Hub et jeton d’agent vérifiés dans la route, avant la lecture du corps (`src/api.js:507`) ; WebSocket : session exigée avant la mise à niveau (`src/main.js:124`) ; origine des consoles : passe liée à une session encore vivante, revérifiée à chaque requête (`src/origine-consoles.js:51`) | essai `test/nexarc.test.js:159` |
| SEC-AUTH-011 | HIGH | PASS | jeton d’agent inconnu → 401 : `src/api.js:507` ; erreur imprévue réduite à un numéro : `socle/src/http.js:163` | le jeton du Hub présenté et faux ne vaut jamais session : 401 (`test/nexarc.test.js:673`) |
| SEC-SESS-001 | CRITICAL | PASS | voir REQ-SESS-001 |  |
| SEC-SESS-002 | HIGH | PASS | `grep -rn "localStorage" web/*.js socle/web` → thème seulement (`socle/web/compte.js:299`), jamais une session |  |
| SEC-SESS-003 | HIGH | PASS | 256 bits : `socle/src/comptes.js:268` | renouvelé à chaque changement de niveau |
| SEC-SESS-004 | HIGH | PASS | voir REQ-SESS-003, REQ-SESS-004 et REQ-SESS-006 |  |
| SEC-SESS-005 | CRITICAL | N/A | aucun JWT : `grep -rniE "jwt\|jsonwebtoken\|jose" src web/*.js socle agent` → 0 |  |
| SEC-SESS-006 | MEDIUM | N/A | aucun jeton de rafraîchissement : sessions serveur (voir SEC-SESS-005) ; jetons d’agents sans expiration, révoqués par l’administrateur |  |
| SEC-SESS-007 | MEDIUM | PASS | voir REQ-SESS-005 ; avis par courriel via le canal d’alerte | courriel : H2 |
| SEC-AUTHZ-001 | CRITICAL | PASS | le parc est partagé entre les opérateurs, sans propriétaire ; les objets d’un agent sont filtrés dans la requête par sa machine : `src/taches.js:67`, relève : `src/taches.js:58` | essai `test/nexarc.test.js:231` |
| SEC-AUTHZ-002 | CRITICAL | PASS | rôle humain lu en base par le socle (`socle/src/portail.js:114`) ; portée du Hub fermée (`test/nexarc.test.js:664`) ; automatisation « commande libre » : réglage, rôle d’administrateur et renfort à chaque geste qui la fait exister ou exécuter (`src/api.js:349`), suppression d’une automatisation sous renfort ; accès distants, cartes et nœuds Mesh déclarés par un administrateur sous renfort ; rôle de relais fixé par le code d’inscription, jamais par la remontée de l’agent (`src/agents.js:139`) | essais `test/nexarc.test.js:159`, `test/nexarc.test.js:603` ; la table des rôles de chaque route est figée dans l’essai |
| SEC-AUTHZ-003 | HIGH | PASS | schémas stricts, champ inconnu refusé : `socle/src/schema.js:69` ; l’auteur d’une tâche vient de la session, jamais du corps (`src/taches.js:37`) |  |
| SEC-AUTHZ-004 | HIGH | PASS | route /api inconnue → 404, méthode inconnue → 405 avec Allow : `src/api.js:588` ; routes publiques figées dans l’essai (`test/nexarc.test.js:179`) | aucune route de débogage ni de semis |
| SEC-AUTHZ-005 | CRITICAL | N/A | aucune notion de locataire : un site est un libellé du parc, pas une frontière de droits ; `grep -rniE "tenant\|organisation\|workspace" src` → 0 |  |
| SEC-AUTHZ-006 | LOW | PASS | références publiques de 96 bits aléatoires pour les machines, tâches, alertes et automatisations : `src/base.js:20` ; l’entier interne ne sort pas | motif exigé avant toute lecture : `src/base.js:16` |
| SEC-AUTHZ-007 | HIGH | PASS | invariants tenus par le serveur : vingt tâches en attente au plus par machine (`src/api.js:176`), charge validée selon son type (`src/taches.js:22`), réveil créé par sa seule route, qui calcule l’adresse et la diffusion elle-même (`src/taches.js:16`), commande libre soumise à NEXARC_ALLOW_EXEC à la création, au lancement, à la réactivation et dans la ronde (`src/taches.js:114`) ; code d’inscription consommé et jeton tiré en une transaction (`src/agents.js:50`) | essais `test/nexarc.test.js:641`, `test/nexarc.test.js:347`, `test/nexarc.test.js:206` ; aucun prix, crédit ni solde |
| SEC-AUTHZ-008 | MEDIUM | PASS | réglage lu côté serveur à chaque geste : tâche (`src/api.js:171`) et automatisation (`src/api.js:349`), rôle et renfort exigés par le serveur, jamais par l’interface | essai `test/nexarc.test.js:641` (403 sur chaque route appelée directement) |
| SEC-INJ-001 | CRITICAL | PASS | requêtes préparées ; filtre de cible fait de fragments constants et de valeurs liées : `src/taches.js:84` | annexe B.3 : aucune interpolation de valeur dans le texte SQL |
| SEC-INJ-002 | HIGH | N/A | aucun ORM : node:sqlite, requêtes préparées seulement |  |
| SEC-INJ-003 | HIGH | N/A | aucune base documentaire : SQLite seulement ; JSON rangé en colonne texte |  |
| SEC-INJ-004 | CRITICAL | PASS | serveur : aucun processus (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; agent : binaire fixe, arguments en liste, `shell=False` (`agent/nexarc-agent.py:165`), paquet validé par motif (`agent/nexarc-agent.py:50`) | la commande libre est la fonction elle-même : un shell fixe reçoit la commande en unique argument (`agent/nexarc-agent.py:520`), réservée à l’administrateur sous renfort et désactivée par défaut |
| SEC-INJ-005 | HIGH | PASS | `socle/src/http.js:186` ; l’agent servi a un chemin fixe (`src/api.js:441`) | aucun nom de fichier fourni par une requête n’est ouvert |
| SEC-INJ-006 | HIGH | PASS | les scripts d’inscription (exécutés en root ou SYSTEM) ne reçoivent que des valeurs contrôlées par motif, placées entre apostrophes : `src/enroll.js:22` | essai `test/nexarc.test.js:1062` ; `grep -rnE "new Function\|node:vm" src socle/src` → 0 |
| SEC-INJ-007 | HIGH | N/A | aucun analyseur XML : Redfish en JSON, `grep -rniE "xml2js\|sax\|libxml\|fast-xml\|DOMParser" src socle/src agent` → 0 |  |
| SEC-INJ-008 | HIGH | PASS | JSON seulement ; clés de prototype refusées : `socle/src/schema.js:6` ; inventaire à profondeur bornée : `src/api.js:37` | l’agent ne lit que du JSON (`json.loads`), jamais pickle ni yaml |
| SEC-XSS-001 | CRITICAL | PASS | interface : DOM construit par `h()`, texte seulement (`web/app.js:5`) ; le HTML d’une carte de gestion ne s’exécute plus sous l’origine de NEXARC : origine à part (voir REQ-WEB-002) | essai `test/nexarc.test.js:506` |
| SEC-XSS-002 | HIGH | N/A | aucun texte riche ni Markdown rendu : sorties de tâches et textes d’alertes affichés en texte brut (`web/app.js:460`) |  |
| SEC-XSS-003 | HIGH | PASS | aucun eval, setTimeout chaîne ni affectation de location depuis une donnée : `grep -rnE "eval\(\|new Function\|location\.href *=" web/*.js socle/web` → 0 | le hash ne choisit qu’une page connue : `web/app.js:86` |
| SEC-XSS-004 | HIGH | PASS | voir REQ-WEB-002 |  |
| SEC-XSS-005 | MEDIUM | PASS | seul échange : le Worker de preuve de travail, de même origine : `socle/web/compte.js:233` | aucune écoute de window message |
| SEC-XSS-006 | MEDIUM | PASS | une carte en échec : une cause courte et une référence au client, le détail au seul journal du serveur (`src/api.js:74`, `src/api.js:117`) ; erreurs imprévues réduites à un numéro (`socle/src/http.js:163`) | essais `test/nexarc.test.js:596`, `test/nexarc.test.js:997` |
| SEC-XSS-007 | MEDIUM | N/A | aucune redirection pilotée par paramètre ; `curl -sI "/login?next=https://evil.example"` → aucun Location (annexe B.4) |  |
| SEC-XSS-008 | MEDIUM | PASS | aucun script tiers : noVNC servi par NEXARC, empreintes vérifiées (`web/vendor/novnc/PROVENANCE:37`) | vérification CI : `.github/workflows/verification.yml:44` |
| SEC-HDR-001 | HIGH | FAIL | voir REQ-WEB-001 | action H1 |
| SEC-HDR-002 | HIGH | PASS | voir REQ-WEB-002 |  |
| SEC-HDR-003 | MEDIUM | PASS | voir REQ-WEB-003 |  |
| SEC-HDR-004 | LOW | PASS | `curl -sI /` : ni Server ni X-Powered-By (annexe B.4) |  |
| SEC-HDR-005 | MEDIUM | PASS | no-store sur l’API et les pages : `socle/src/http.js:148` ; origine des consoles : no-store sur chaque réponse (`src/proxy.js:114`), en-têtes de cache de la carte retirés ; seuls les fichiers publics du socle sont mis en cache (`src/main.js:110`) | aucun CDN |
| SEC-HDR-006 | CRITICAL | PASS | voir REQ-WEB-004 |  |
| SEC-HDR-007 | HIGH | PASS | voir REQ-SESS-001 |  |
| SEC-CSRF-001 | HIGH | PASS | SameSite=Strict + origine + jeton : `socle/src/portail.js:92` appelé par chaque écriture de session | essai `test/nexarc.test.js:704` ; agents et Hub présentent un jeton en en-tête, que le navigateur n’envoie jamais seul |
| SEC-CSRF-002 | MEDIUM | PASS | `socle/src/http.js:120` | 415 sur tout autre type |
| SEC-CSRF-003 | MEDIUM | PASS | voir REQ-WEB-005 : tirer un code, l’échanger et relever ses tâches sont des POST | essai `test/nexarc.test.js:184` ; annexe B.4 : un GET d’échange répond 405 |
| SEC-CSRF-004 | CRITICAL | PASS | adresses internes (consoles, cartes, Redfish, nœuds Mesh) déclarées par un administrateur sous renfort et journalisées (`src/api.js:212`) : c’est la liste des destinations admises ; métadonnées, lien local et plages réservées refusés en littéral comme à la résolution (`src/reseau.js:52`) ; Redfish en HTTPS sur certificat épinglé ; SYNAPSE à l’adresse de la configuration, sans redirection suivie (`src/synapse.js:34`) ; aucun cookie de NEXARC vers une carte (`src/proxy.js:87`) | essais `test/nexarc.test.js:1175`, `test/nexarc.test.js:585`, `test/nexarc.test.js:724` ; les cartes vivent sur le réseau interne par nature : le bouclage et les plages privées y restent permis à l’administrateur |
| SEC-CSRF-005 | HIGH | N/A | aucun webhook reçu ni envoyé vers une adresse d’utilisateur : SYNAPSE est joint à l’adresse de la configuration (`src/config.js:59`) |  |
| SEC-CSRF-006 | MEDIUM | N/A | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |  |
| SEC-API-001 | HIGH | PASS | voir REQ-WEB-006 |  |
| SEC-API-002 | HIGH | PASS | voir REQ-WEB-008 ; remontées, réveils et alimentation limités (`src/api.js:91`) ; échecs de codes et de jetons de machine plafonnés par adresse (voir REQ-AUTH-010) |  |
| SEC-API-003 | MEDIUM | PASS | tâches listées par 25 (`src/api.js:159`), alertes par 500, parc borné par NEXARC_MAX_MACHINES, automatisations bornées (`src/base.js:19`), flux d’activité plafonnés ; aucun paramètre de pagination ou de taille accepté (`src/api.js:597`) | essai `test/nexarc.test.js:309` |
| SEC-API-004 | HIGH | PASS | réponses construites champ par champ : `src/base.js:137`, `src/base.js:230` : la charge d’une commande libre n’est rendue à personne, ce qu’elle a affiché à un administrateur seulement ; secrets d’appareils réduits à « en place » ; résumé du Hub réduit à des comptes (`src/base.js:179`) | essai `test/nexarc.test.js:374` ; sondage exploratoire ci-dessous |
| SEC-API-005 | MEDIUM | PASS | 405 avec Allow : `src/api.js:589` ; aucune page de documentation ni de débogage (`test/nexarc.test.js:108`) |  |
| SEC-API-006 | HIGH | N/A | aucun GraphQL : `grep -rniE "graphql\|apollo" src web/*.js socle` → 0 |  |
| SEC-API-007 | MEDIUM | PASS | un seul formateur d’erreurs : `socle/src/http.js:157` ; carte en échec rendue en 502 avec une cause et une référence (voir SEC-XSS-006) ; écritures multiples en une transaction : échange d’un code, remontée, relève, passage d’automatisation, acquittement, révocation (`src/base.js:105`) | essai `test/nexarc.test.js:624` (passage interrompu au milieu : ni tâche ni passage compté) |
| SEC-API-008 | MEDIUM | N/A | aucune opération monétaire ni crédit : `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |  |
| SEC-API-009 | HIGH | PASS | pas de RPC implicite : mises à niveau WebSocket revérifiées comme une route (`src/main.js:137`) | essai `test/nexarc.test.js:1188` |
| SEC-API-010 | MEDIUM | PASS | `socle/src/http.js:126` ; 64 Kio par défaut, 512 Kio pour l’inventaire d’un agent (`src/api.js:126`) |  |
| SEC-DB-001 | CRITICAL | PASS | voir REQ-DATA-001 |  |
| SEC-DB-002 | HIGH | N/A | SQLite embarqué sans rôle ni identifiant : `src/base.js:38` |  |
| SEC-DB-003 | HIGH | FAIL | aucun trafic réseau vers la base ; secrets de facteurs et d’appareils chiffrés | chiffrement du disque des hôtes : action H7 |
| SEC-DB-004 | MEDIUM | PASS | secrets TOTP et d’appareils scellés AES-256-GCM, sous-clé par usage : `socle/src/chiffre.js:60` ; jetons et codes gardés par leur empreinte ; clé maîtresse jamais dans le volume : secret du Hub, ou secret Docker hors du volume pour l’installation seule (`docker-compose.yml:14`, `README.md:132`), secret vide refusé au démarrage | lecture brute des colonnes : essais `test/nexarc.test.js:486`, `test/nexarc.test.js:210` |
| SEC-DB-005 | CRITICAL | PASS | voir SEC-INJ-001 |  |
| SEC-DB-006 | HIGH | FAIL | voir REQ-DATA-003 | action H8 |
| SEC-DB-007 | MEDIUM | PASS | essais sur données fabriquées ; aucun compte par défaut : jeton d’installation exigé (`socle/src/comptes.js:228`) |  |
| SEC-DB-008 | CRITICAL | N/A | le navigateur ne parle jamais à la base : SQLite côté serveur seulement |  |
| SEC-DB-009 | LOW | PASS | `src/base.js:39` ; listes plafonnées | un seul processus, pas de pool nécessaire |
| SEC-DB-010 | LOW | PASS | voir REQ-DATA-004 : accès distants, automatisations, alimentation, réveils, révocations et sauvegardes au journal chaîné |  |
| SEC-FILE-001 | HIGH | N/A | aucun envoi de fichier : corps JSON seulement (`socle/src/http.js:120`) |  |
| SEC-FILE-002 | MEDIUM | N/A | aucun envoi de fichier ; corps JSON bornés (voir SEC-API-010) |  |
| SEC-FILE-003 | HIGH | N/A | aucun fichier d’utilisateur écrit ; seule écriture : la base, nommée par le serveur |  |
| SEC-FILE-004 | HIGH | N/A | aucun fichier d’utilisateur servi |  |
| SEC-FILE-005 | CRITICAL | N/A | aucun fichier d’utilisateur stocké |  |
| SEC-FILE-006 | MEDIUM | N/A | aucun fichier partagé entre utilisateurs |  |
| SEC-FILE-007 | LOW | N/A | aucune image acceptée |  |
| SEC-FILE-008 | HIGH | N/A | aucun import par adresse : voir SEC-CSRF-004 |  |
| SEC-PAY-001 | CRITICAL | N/A | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |  |
| SEC-PAY-002 | CRITICAL | N/A | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |  |
| SEC-PAY-003 | HIGH | N/A | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun abonnement |  |
| SEC-PAY-004 | HIGH | N/A | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |  |
| SEC-PAY-005 | HIGH | N/A | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |  |
| SEC-PAY-006 | HIGH | PASS | vérification : 5 par heure par compte et par adresse (`socle/src/portail.js:37`) ; alertes : 30 par heure et par compte (`socle/src/notifications.js:98`) | destinataires et contenus jamais choisis par une requête |
| SEC-PAY-007 | MEDIUM | FAIL | le domaine d’expédition est celui du relais de l’exploitant | SPF, DKIM et DMARC à publier avec le relais : action H2 |
| SEC-PAY-008 | MEDIUM | PASS | aucun mot de passe dans un courriel ; liens uniques, hachés, de 30 minutes (`socle/src/comptes.js:34`) ou 72 heures pour fermer les sessions (`socle/src/notifications.js:27`) | le lien de révocation ne peut que fermer des sessions |
| SEC-NEXT-001 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-002 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-003 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-004 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-005 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-006 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-007 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |  |
| SEC-NEXT-008 | MEDIUM | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 ; aucun déploiement Vercel |  |
| SEC-NEXT-009 | MEDIUM | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 ; aucune bibliothèque de cache client |  |
| SEC-BAAS-001 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-002 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-003 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-004 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-005 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-006 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-007 | MEDIUM | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-008 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-009 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-010 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BAAS-011 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |  |
| SEC-BE-001 | MEDIUM | PASS | en-têtes posés avant toute route, erreurs et 429 compris : `src/main.js:106` ; plus aucun mandataire avant eux ; origine des consoles : ses propres en-têtes sur chaque réponse, refus compris (`src/origine-consoles.js:85`) | annexe B.4 ; essai `test/nexarc.test.js:108` |
| SEC-BE-002 | MEDIUM | PASS | corps bornés ; 404 pour l’inconnu ; relais de confiance explicites : `socle/src/http.js:14` ; délais du serveur : `src/main.js:158` | formateur d’erreurs unique : `src/main.js:114` |
| SEC-BE-003 | HIGH | PASS | voir SEC-INJ-004 et SEC-INJ-008 ; aucun import dynamique d’un chemin fourni | noVNC importé depuis un chemin fixe dans le navigateur (`web/app.js:532`) |
| SEC-BE-004 | HIGH | PASS | aucune dépendance npm : `package.json:8` sans dépendances, rien à verrouiller | dépendances Python de l’agent : voir SEC-DEP-001 |
| SEC-BE-005 | CRITICAL | N/A | aucun Django : serveur Node, agent Python sans cadriciel web |  |
| SEC-BE-006 | HIGH | N/A | aucun Flask ni FastAPI : l’agent est un client HTTP, il n’écoute sur aucun port (`grep -rnE "flask\|fastapi\|uvicorn\|http.server" agent/nexarc-agent.py` → 0) |  |
| SEC-BE-007 | HIGH | PASS | agent : ni os.system, ni shell=True, ni pickle, ni yaml, ni eval (`grep -nE "os\.system\|subprocess\.[a-z_]+\(.*shell=True\|pickle\|yaml\.\|eval\(\|exec\(" agent/nexarc-agent.py` → 0) ; JSON seulement | la commande libre passe par un shell fixe, en unique argument (voir SEC-INJ-004) |
| SEC-BE-008 | HIGH | N/A | aucun PHP |  |
| SEC-BE-009 | MEDIUM | PASS | `Dockerfile:31` ; base slim épinglée ; dossier de données en 0700, base et fichiers WAL en 0600 : `src/base.js:37` |  |
| SEC-BE-010 | MEDIUM | PASS | `socle/src/http.js:157` ; sonde publique réduite à « vivant » : `src/api.js:128` | essai `test/nexarc.test.js:118` |
| SEC-WP-001 | CRITICAL | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-002 | HIGH | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-003 | HIGH | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-004 | MEDIUM | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-005 | MEDIUM | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-006 | CRITICAL | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-007 | HIGH | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-WP-008 | MEDIUM | N/A | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |  |
| SEC-INFRA-001 | HIGH | FAIL | voir REQ-WEB-001 | action H1 |
| SEC-INFRA-002 | MEDIUM | FAIL | aucun domaine dans le dépôt | DNS, CAA et verrou du registraire du domaine éventuel : action H13 |
| SEC-INFRA-003 | HIGH | FAIL | hôtes de l’exploitant | pare-feu, SSH par clé, mises à jour : action H9 |
| SEC-INFRA-004 | MEDIUM | FAIL | `Dockerfile:6` ; `Dockerfile:31` ; `deploy/compose.hub.yml:15` ; `deploy/compose.hub.yml:18` ; `deploy/compose.hub.yml:20` | crible de l’image (Grype en CI, Trivy au déploiement) à exécuter : actions H3, H14 |
| SEC-INFRA-005 | CRITICAL | N/A | aucun stockage objet : `grep -rniE "s3\|aws\|gcs\|azure\|bucket" src socle/src` → 0 |  |
| SEC-INFRA-006 | HIGH | N/A | aucun nuage : service auto-hébergé, aucune clé IAM |  |
| SEC-INFRA-007 | HIGH | FAIL | permissions minimales, actions épinglées par commit, aucun secret pour les demandes de fusion | protection de branche et revue requise : action H3 |
| SEC-INFRA-008 | MEDIUM | FAIL | empreinte d’image, provenance et SBOM à la publication : `.github/workflows/publish.yml:88` | la publication tourne sur les Actions : action H3 |
| SEC-INFRA-009 | MEDIUM | N/A | aucune infrastructure décrite en code : `find . -name "*.tf" -o -name "Pulumi.yaml"` → 0 fichier |  |
| SEC-DEP-001 | HIGH | PASS | aucune dépendance npm ; dépendances de l’agent verrouillées par empreinte (`agent/requirements.txt:7`), installées en mode verrouillé en CI (`.github/workflows/verification.yml:36`) comme sur les postes (`src/enroll.js:47`) ; image de base par empreinte (`Dockerfile:6`), noVNC par empreinte |  |
| SEC-DEP-002 | HIGH | FAIL | aucune dépendance npm ; image passée au crible à chaque publication (`.github/workflows/publish.yml:53`) | alertes Dependabot (pip) et contrôle requis : action H3 |
| SEC-DEP-003 | MEDIUM | PASS | aucune dépendance npm ; l’agent n’en a que deux, maintenues et connues (`psutil`, `requests`) ; noVNC vendu avec sa provenance |  |
| SEC-DEP-004 | MEDIUM | PASS | versions exactes (`agent/requirements.txt:6`) ; actions épinglées par commit (`.github/workflows/verification.yml:22`) ; mises à jour proposées en demandes de fusion, jamais fusionnées seules (`.github/dependabot.yml:14`) | revue requise avant fusion : protection de branche, action H3 |
| SEC-DEP-005 | MEDIUM | PASS | aucune installation de paquet npm : ni npm install ni script de cycle de vie, dans le dépôt comme dans l’image (`Dockerfile:23` sans installation) | les dépendances de l’agent s’installent sur le poste (voir SEC-DEP-001) |
| SEC-DEP-006 | LOW | FAIL | `.github/workflows/publish.yml:89` | produit par la publication (H3) |
| SEC-DEP-007 | MEDIUM | PASS | voir SEC-XSS-008 |  |
| SEC-DEP-008 | LOW | FAIL | crible de l’image à chaque publication | abonnement aux avis GitHub (npm, pip) : action H3 |
| SEC-LLM-001 | CRITICAL | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-002 | CRITICAL | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-003 | HIGH | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-004 | HIGH | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-005 | CRITICAL | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) ; les actions offertes à l’assistant du Hub passent par le jeton du Hub, qui n’ouvre ni la commande libre ni les comptes (`src/api.js:170`) |  |
| SEC-LLM-006 | HIGH | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-007 | MEDIUM | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-008 | LOW | N/A | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LOG-001 | MEDIUM | PASS | voir REQ-DATA-004 ; chaque ligne : date, acteur, adresse, action, objet, résultat (`socle/src/journal.js:10`) ; identifiant de requête : `socle/src/requete.js:12` | magasin persistant : le journal chaîné en base ; hors hôte : action H11 |
| SEC-LOG-002 | HIGH | PASS | `socle/src/journal.js:10` ; jamais un jeton ni le contenu d’une commande libre au journal (`src/taches.js:43`) |  |
| SEC-LOG-003 | MEDIUM | FAIL | sortie standard conservée par Docker, hors de portée du service : `deploy/compose.hub.yml:31` | collecteur central hors hôte : action H11 |
| SEC-LOG-004 | MEDIUM | FAIL | règles : rafales d’échecs de connexion, jetons et codes de machine refusés compris, refus d’accès, verrous et limites, erreurs internes, connexion d’un administrateur (`socle/src/vigie.js:11`) ; alerte tirée de bout en bout jusqu’à la page Sécurité des administrateurs (`socle/test/surveillance.test.js:59`) | hors de l’application, l’alerte ne part que par courriel : tant qu’aucun relais n’est posé, personne ne la reçoit sans ouvrir NEXARC → action H2 |
| SEC-LOG-005 | LOW | FAIL | santé du conteneur : `Dockerfile:35` ; sondes du Hub (`hub.json:490`) | surveillance externe : action H10 |
| SEC-LOG-006 | MEDIUM | PASS | runbook ci-dessous |  |
| SEC-LOG-007 | HIGH | PASS | sessions : fermeture globale `socle/src/portail.js:473` ; jetons d’agents : révocation d’un poste ou de tout le parc (`src/cli.js:60`) ; jeton du Hub et commande libre coupés au redéploiement ; SOCLE_CLE tournée sans réinscription ; chaque procédure écrite dans le runbook ci-dessous | joué de bout en bout le 2026-09-30 : `outils/exercice-incident.mjs:99` (23 vérifications), `outils/exercice-rotation.mjs:1` (24) |
| SEC-PRIV-001 | MEDIUM | PASS | `web/confidentialite.txt:7` avec durées ; purges automatiques : `src/alertes.js:114`, `src/agents.js:29`, `socle/src/comptes.js:957` |  |
| SEC-PRIV-002 | MEDIUM | PASS | un cookie de session indispensable, documenté ; aucun traceur (`web/confidentialite.txt:77`) |  |
| SEC-PRIV-003 | MEDIUM | PASS | `web/confidentialite.txt:61` nomme chaque destinataire ; lien depuis la page Sécurité (`web/app.js:47`) |  |
| SEC-PRIV-004 | MEDIUM | PASS | export : `socle/src/portail.js:328` complété par NEXARC (`src/base.js:356`) ; effacement en libre-service sous renfort : `socle/src/comptes.js:827`, tâches et acquittements du compte neutralisés (`src/base.js:366`) | essai `test/nexarc.test.js:682` |
| SEC-PRIV-005 | HIGH | FAIL | voir REQ-DATA-002 | action H7 |
| SEC-PRIV-006 | LOW | FAIL | aucun sous-traitant dans le code : cartes, SYNAPSE et MeshCentral sont chez l’exploitant ; le relais SMTP est choisi par lui | si ce relais est un prestataire hors de l’UE : accord de traitement ou relais européen, action H15 |
| SEC-PRIV-007 | MEDIUM | PASS | runbook : notification sous 72 heures |  |
| SEC-PRIV-008 | LOW | PASS | `web/confidentialite.txt:100` | aucune catégorie particulière de données |
| SEC-TEST-001 | MEDIUM | FAIL | `.github/workflows/verification.yml:119` | Actions : H3 |
| SEC-TEST-002 | HIGH | FAIL | voir REQ-CI-001 | actions H3, H4 |
| SEC-TEST-003 | HIGH | FAIL | image : `.github/workflows/publish.yml:50` | actions H3, H14 |
| SEC-TEST-004 | MEDIUM | FAIL | aucun passage DAST encore | ZAP en mode « baseline » contre la VM d’essai : action H14 |
| SEC-TEST-005 | LOW | FAIL | voir REQ-WEB-001 | notation après HTTPS : action H1 |
| SEC-TEST-006 | HIGH | PASS | voir REQ-CI-006 |  |
| SEC-TEST-007 | LOW | PASS | sondage exploratoire du 2026-09-30, rejoué à chaque génération de ce fichier : section « Exploratory probing » ci-dessous (références devinées, objets d’un autre agent, champs et paramètres inconnus, rôles, corps géants, injections dans les scripts d’inscription, adresses internes, jetons inventés, rafales) | chaque trouvaille est devenue un essai de non-régression |
| SEC-TEST-008 | LOW | N/A | ni argent, ni santé, ni large public : service auto-hébergé pour quelques comptes invités ; `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |  |

## Not applicable
| ID | Why, with proof |
|---|---|
| REQ-CRYPT-003 | bcrypt absent : `grep -rniE "bcrypt" socle/src src agent` → 0 ; Argon2id seul |
| REQ-DATA-007 | aucun envoi de fichier ni import depuis une adresse : corps JSON seulement (`socle/src/http.js:120`), `grep -rniE "multipart\|busboy\|formidable" src socle/src` → 0 |
| SEC-AUTH-008 | aucune connexion par fournisseur externe : `grep -rniE "oauth\|openid\|id_token\|redirect_uri" socle/src src` → 0 |
| SEC-SESS-005 | aucun JWT : `grep -rniE "jwt\|jsonwebtoken\|jose" src web/*.js socle agent` → 0 |
| SEC-SESS-006 | aucun jeton de rafraîchissement : sessions serveur (voir SEC-SESS-005) ; jetons d’agents sans expiration, révoqués par l’administrateur |
| SEC-AUTHZ-005 | aucune notion de locataire : un site est un libellé du parc, pas une frontière de droits ; `grep -rniE "tenant\|organisation\|workspace" src` → 0 |
| SEC-INJ-002 | aucun ORM : node:sqlite, requêtes préparées seulement |
| SEC-INJ-003 | aucune base documentaire : SQLite seulement ; JSON rangé en colonne texte |
| SEC-INJ-007 | aucun analyseur XML : Redfish en JSON, `grep -rniE "xml2js\|sax\|libxml\|fast-xml\|DOMParser" src socle/src agent` → 0 |
| SEC-XSS-002 | aucun texte riche ni Markdown rendu : sorties de tâches et textes d’alertes affichés en texte brut (`web/app.js:460`) |
| SEC-XSS-007 | aucune redirection pilotée par paramètre ; `curl -sI "/login?next=https://evil.example"` → aucun Location (annexe B.4) |
| SEC-CSRF-005 | aucun webhook reçu ni envoyé vers une adresse d’utilisateur : SYNAPSE est joint à l’adresse de la configuration (`src/config.js:59`) |
| SEC-CSRF-006 | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |
| SEC-API-006 | aucun GraphQL : `grep -rniE "graphql\|apollo" src web/*.js socle` → 0 |
| SEC-API-008 | aucune opération monétaire ni crédit : `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |
| SEC-DB-002 | SQLite embarqué sans rôle ni identifiant : `src/base.js:38` |
| SEC-DB-008 | le navigateur ne parle jamais à la base : SQLite côté serveur seulement |
| SEC-FILE-001 | aucun envoi de fichier : corps JSON seulement (`socle/src/http.js:120`) |
| SEC-FILE-002 | aucun envoi de fichier ; corps JSON bornés (voir SEC-API-010) |
| SEC-FILE-003 | aucun fichier d’utilisateur écrit ; seule écriture : la base, nommée par le serveur |
| SEC-FILE-004 | aucun fichier d’utilisateur servi |
| SEC-FILE-005 | aucun fichier d’utilisateur stocké |
| SEC-FILE-006 | aucun fichier partagé entre utilisateurs |
| SEC-FILE-007 | aucune image acceptée |
| SEC-FILE-008 | aucun import par adresse : voir SEC-CSRF-004 |
| SEC-PAY-001 | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |
| SEC-PAY-002 | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |
| SEC-PAY-003 | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun abonnement |
| SEC-PAY-004 | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |
| SEC-PAY-005 | `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |
| SEC-NEXT-001 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-002 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-003 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-004 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-005 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-006 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-007 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 |
| SEC-NEXT-008 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 ; aucun déploiement Vercel |
| SEC-NEXT-009 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle/src socle/web/*.js` → 0 ; aucune bibliothèque de cache client |
| SEC-BAAS-001 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-002 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-003 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-004 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-005 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-006 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-007 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-008 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-009 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-010 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BAAS-011 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:38` |
| SEC-BE-005 | aucun Django : serveur Node, agent Python sans cadriciel web |
| SEC-BE-006 | aucun Flask ni FastAPI : l’agent est un client HTTP, il n’écoute sur aucun port (`grep -rnE "flask\|fastapi\|uvicorn\|http.server" agent/nexarc-agent.py` → 0) |
| SEC-BE-008 | aucun PHP |
| SEC-WP-001 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-002 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-003 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-004 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-005 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-006 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-007 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-WP-008 | application Node écrite ici : `grep -rniE "wordpress\|wp-admin\|bubble\|webflow\|airtable" src web/*.js socle` → 0 |
| SEC-INFRA-005 | aucun stockage objet : `grep -rniE "s3\|aws\|gcs\|azure\|bucket" src socle/src` → 0 |
| SEC-INFRA-006 | aucun nuage : service auto-hébergé, aucune clé IAM |
| SEC-INFRA-009 | aucune infrastructure décrite en code : `find . -name "*.tf" -o -name "Pulumi.yaml"` → 0 fichier |
| SEC-LLM-001 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-002 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-003 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-004 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-005 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) ; les actions offertes à l’assistant du Hub passent par le jeton du Hub, qui n’ouvre ni la commande libre ni les comptes (`src/api.js:170`) |
| SEC-LLM-006 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-007 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-008 | NEXARC n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-TEST-008 | ni argent, ni santé, ni large public : service auto-hébergé pour quelques comptes invités ; `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |

## Anonymity (REQ-ANON-001 to -010)
Arbre de travail : 0 occurrence de la liste d’anonymat ; les motifs de l’annexe B.1 y relèvent 1 ligne, un nom de fichier du .gitignore. Historique local complet (82 commits, tous les arbres, tous les messages, auteurs et validateurs) : 0 occurrence de la liste, une seule identité, toutes les dates en UTC, aucune mention d’outil ; le motif « infrastructure personnelle » y relève 4 lignes, toutes des mots qui le contiennent. Aucun binaire image ni document dans tout l’historique. Le dépôt ne contient pas l’historique de la 1.x : l’ancien dépôt publié, relu depuis un clone hors dépôt (4 commits), porte 29 occurrences de la liste dans 11 fichiers de son dernier arbre ; son premier commit suit par erreur un dossier de construction de l’agent qui garde les chemins du poste de développement ; 4 de ses commits portent un terme de la liste, 2 identités y signent, dont une adresse provisoire, et toutes ses dates ont un décalage horaire non nul → H12, détail dans le rapport d’anonymat hors dépôt. Le balayage est fait sur motifs et sur une liste finie : il ne prouve pas l’absence de ce que la liste ne nomme pas.

## Human actions required
Ce qu’aucun agent ne peut faire à la place de l’exploitant. Cette liste bloque la mise en production tant qu’elle n’est pas vide.

| # | Action | Contrôles | Étapes |
|---|---|---|---|
| H1 | Servir NEXARC en HTTPS | REQ-WEB-001, SEC-HDR-001, SEC-INFRA-001, SEC-TEST-005 | Dans le Hub : Relay ou certificat de l’autorité locale pour NEXARC ; déclarer l’adresse du relais dans « Relais de confiance » (SOCLE_PROXYS) ; « Accès sans HTTPS » à Non ; « Adresse publique » en https:// ; vérifier `curl -sI https://<nexarc>/ \| grep -i strict-transport-security` ; noter le résultat de testssl.sh. Installé seul : relais TLS devant le port publié, mêmes variables dans `.env`. Les agents joignent alors NEXARC en HTTPS (NEXARC_PUBLIC_URL en https://). Consoles web : leur donner un nom d’hôte à elles, servi en HTTPS par le même relais (par exemple `consoles.nexarc.exemple.org` vers NEXARC_CONSOLE_PORT), et le poser dans « Adresse des consoles web » (NEXARC_CONSOLE_URL) ; un simple autre port du même nom sépare les scripts des cartes de NEXARC, pas les cookies (NEXARC le signale au démarrage). |
| H2 | Relais SMTP et adresses d’alerte | REQ-AUTH-014, SEC-PAY-007, SEC-LOG-004 | Réglages avancés de NEXARC dans le Hub (ou `SOCLE_SMTP_*` dans `.env`) : relais, port, chiffrement, identifiants, expéditeur, adresse publique ; publier SPF, DKIM et DMARC pour le domaine d’expédition ; chaque administrateur ajoute puis confirme son adresse dans Sécurité → Alertes par courriel. |
| H3 | GitHub | REQ-CI-001…005, GOV-003, GOV-005, SEC-INFRA-007/008, SEC-TEST-001…003, SEC-DEP-002/006/008 | Activer les Actions ; Settings → Branches : protéger `main` (pas de poussée forcée, contrôles requis : essais, secrets, identite, anonymat, analyse) ; Code security : Dependabot alerts (npm et pip), secret scanning et push protection, private vulnerability reporting ; 2FA sur le compte et sur chaque console de fournisseur. |
| H4 | Liste d’anonymat | REQ-ANON-003, REQ-CI-004, REQ-CI-001 | Sur le poste : gitleaks installé ; `~/.config/git/denylist.txt`, un terme par ligne ; un crochet global `pre-commit` qui refuse un commit dont le diff contient un terme de la liste, puis `git config --global core.hooksPath ~/.config/git/hooks`. Sur GitHub : secret de dépôt `LISTE_ANONYMAT` avec les mêmes termes. Vérifier : un commit d’essai portant un terme est refusé par le crochet, puis par la vérification. |
| H5 | Brûler les secrets vus pendant le développement | SEC-SECRETS-006 | Dans le Hub, régénérer le jeton de service de NEXARC (HUB_TOKEN) et redéployer ; sur la VM d’essai, tourner SOCLE_CLE une fois (README, « Tourner la clé maîtresse » ; déjà exercé hors de la VM par `outils/exercice-rotation.mjs`) ; si une clé de connexion MeshCentral a servi aux essais, `meshcentral --logintokenkey` pour en tirer une neuve ; changer, sur les cartes et serveurs VNC, tout mot de passe saisi pendant les essais ; révoquer les jetons des agents enrôlés sur la VM d’essai (`node src/cli.js agents revoquer --tous`) avant de la remettre en service. |
| H6 | Clés par environnement | REQ-CFG-003, SEC-SECRETS-005, GOV-004 | Un jeton du Hub, une clé maîtresse, une clé Mesh et des comptes de cartes pour la VM d’essai, d’autres pour la production ; aucune carte de production déclarée sur la VM d’essai. |
| H7 | Chiffrement des disques | REQ-DATA-002, SEC-DB-003, SEC-PRIV-005 | LUKS (ou chiffrement du stockage de l’hyperviseur) sur l’hôte qui porte le volume de NEXARC. |
| H8 | Sauvegardes et exercices | REQ-DATA-003, SEC-DB-006, REQ-DATA-005 | Paire RSA 3072 bits créée hors de la machine de NEXARC (README, « Sauvegardes ») ; cron quotidien `docker exec -i <nexarc> node src/cli.js sauvegarde < nexarc-sauvegarde.pub > nexarc-$(date -u +%F).sauv` ; copie hors hôte, trente jours ; restauration réelle sur la VM avec `node src/cli.js restaurer`, datée ici ; dérouler une fois le runbook ci-dessous. |
| H9 | Hôtes | SEC-INFRA-003 | Pare-feu (seuls les ports publiés), SSH par clé sans root, mises à jour de sécurité automatiques, fail2ban. |
| H10 | Disponibilité vue de l’extérieur | SEC-LOG-005 | Une sonde externe sur `/api/health`, ou décision écrite : service de réseau local seulement, sondes du Hub suffisantes. |
| H11 | Journaux centralisés | SEC-LOG-003 | Transférer les journaux du conteneur (dont les lignes `"journal":"nexarc"`) vers un collecteur hors de l’hôte : pilote de journalisation Docker ou agent. |
| H12 | Publication de la version 2 | REQ-ANON-002 | L’historique de la 1.x n’est pas dans ce dépôt : il reste sur l’ancien dépôt publié, qui expose les chemins du poste de développement (un dossier de construction de l’agent suivi par erreur dans son premier commit) et d’autres termes de la liste : le remplacer est urgent. Le service s’appelait Sentinel : supprimer l’ancien dépôt `sentinel-rmm` (le contenu poussé par-dessus ne purge pas ses anciens commits, toujours lisibles par leur empreinte), vérifier qu’aucune bifurcation n’existe, puis publier ce dépôt sous `nexarc`, créé vide ; supprimer aussi, dans les paquets du compte, les images de la 1.x et les journaux d’Actions antérieurs à cette version. |
| H13 | Domaine | REQ-ANON-009, SEC-INFRA-002 | Si NEXARC reçoit un nom public : protection WHOIS, verrou du registraire, 2FA, enregistrement CAA, suppression des enregistrements orphelins. |
| H14 | Crible au déploiement | SEC-INFRA-004, SEC-TEST-003, SEC-TEST-004 | Sur la VM : `trivy image ghcr.io/codexx64/nexarc:2.0.0` sans CRITICAL ni HIGH corrigeable ; `zap-baseline.py -t http://<vm>:<port>` ; résultats notés ici. |
| H15 | Relais SMTP hors UE | SEC-PRIV-006 | Si le relais SMTP choisi (H2) est un prestataire hors de l’Union européenne : accepter son accord de traitement, ou choisir un relais européen ou auto-hébergé. |
| H16 | Clé maîtresse hors ligne | REQ-DATA-003, SEC-DB-006 | Garder une copie hors ligne de SOCLE_CLE (coffre du Hub, ou `secrets/socle_cle` installé seul), à part des sauvegardes de la base : sans elle, une sauvegarde restaurée ne déchiffre ni les secrets TOTP ni les secrets d’appareils. |

Orthographe du pseudonyme : le manuel nomme l’identité « Codex64 » ; les commits, la licence et le compte GitHub portent la forme du compte, identique dans tout l’historique. Changer maintenant créerait une seconde identité dans le journal git ; à trancher par l’exploitant.

## Secrets inventory
| Secret | Where it lives | Scope | Rotation procedure | Last rotated |
|---|---|---|---|---|
| SOCLE_CLE (tirée par le Hub, ou par l’exploitant installé seul) | coffre du Hub → variable du conteneur ; installé seul : secret Docker `secrets/socle_cle`, hors du volume | scelle les secrets TOTP, les mots de passe VNC et les identifiants Redfish | README, « Tourner la clé maîtresse » : l’actuelle dans « Clé maîtresse remplacée » (SOCLE_CLE_ANCIENNE), une neuve (`openssl rand -base64 32`) dans « Clé maîtresse », redéployer (TOTP et secrets d’appareils rescellés, journal `coffre.tourne`), vider le champ, redéployer | création à l’installation ; procédure exercée le 2026-09-30 (`outils/exercice-rotation.mjs`) |
| NEXARC_HUB_TOKEN (HUB_TOKEN du Hub, tiré par le Hub) | coffre du Hub → variable | état, tâches sans commande libre, réveil | régénérer dans le Hub, redéployer NEXARC (l’ancien cesse au démarrage) | création à l’installation |
| Jetons d’agents (`sag_…`, tirés par NEXARC) | empreinte SHA-256 dans `machines` ; le clair dans `agent.json` (0600) sur le poste | remontée, relève et résultat des tâches de SA machine | `docker exec <nexarc> node src/cli.js agents revoquer <hôte>` (ou `--tous`) : le jeton cesse aussitôt ; l’agent se réinscrit avec un nouveau code et retrouve sa machine par son nom d’hôte | à l’inscription |
| Codes d’inscription (tirés par NEXARC) | empreinte SHA-256 dans `enrolements`, le clair dans la commande copiée par l’opérateur | un échange contre un jeton d’agent, pendant une heure | aucun : usage unique, expirent seuls | à chaque ajout de poste |
| Mots de passe VNC, identifiants Redfish (posés par un administrateur) | table `machines`, scellés sous SOCLE_CLE | console ou alimentation d’une machine | changer sur la carte, ressaisir dans « Accès distants » (administrateur, renfort) | à la pose |
| NEXARC_MESH_LOGIN_KEY (tirée par MeshCentral) | coffre du Hub → variable ; installé seul : `.env` (0600) | jetons de connexion au bureau distant | `meshcentral --logintokenkey`, coller dans le Hub, redéployer | à la pose |
| SYNAPSE_JETON (jeton de cerveau dérivé par le Hub) | coffre du Hub → variable | écriture des événements du parc dans SYNAPSE | tourné avec le jeton du Hub de SYNAPSE (HUB_TOKEN_SEED), puis redéploiement de NEXARC | géré par le Hub |
| SOCLE_JETON_INSTALLATION (tiré par le socle) | tiré au premier démarrage, journaux du conteneur | création du premier compte, puis inutile | aucun : invalide dès qu’un compte existe | — |
| SOCLE_SMTP_MOTDEPASSE (émis par le fournisseur de courriel) | coffre du Hub → variable ; installé seul : `.env` | relais des alertes | changer chez le fournisseur de courriel, coller dans le Hub, redéployer | à la mise en service (H2) |
| Clé privée des sauvegardes (tirée par l’exploitant, `openssl genpkey`) | hors de la machine de NEXARC, jamais dans le conteneur | relit les sauvegardes | nouvelle paire, sauvegardes suivantes chiffrées pour la nouvelle clé publique ; garder l’ancienne privée tant que ses sauvegardes sont conservées | à créer (H8) |
| SOCLE_POIVRE (tiré par l’exploitant, s’il en pose un) | non posé par défaut | poivre HMAC des mots de passe | le nouveau dans `SOCLE_POIVRE`, l’ancien dans `SOCLE_POIVRE_ANCIEN` : chaque mot de passe passe au nouveau à la connexion suivante | — |

## Incident runbook
Détecter : alertes « vigie » dans la page Sécurité des administrateurs (et par courriel, H2) ; refus : `docker logs <nexarc> | grep '"resultat":"refus"'` ; jetons d’agents refusés : `docker logs <nexarc> | grep connexion.jeton`.

```bash
# 1. Fermer toutes les sessions sauf la sienne (renfort demandé)
#    Page Comptes → « Fermer toutes les sessions », ou :
curl -X POST -H 'Content-Type: application/json' -H "X-CSRF: $CSRF" -b "$COOKIE" https://<nexarc>/api/compte/admin/sessions/fermer-tout -d '{}'
# 2. Couper la commande libre sur tout le parc : Hub → NEXARC → Réglages → « Autoriser la commande libre » : Non → Redéployer
#    (NEXARC_ALLOW_EXEC=0 : plus aucune commande libre créée, lancée ni automatisée)
# 3. Couper le Hub : régénérer son jeton de service (HUB_TOKEN) → Redéployer
# 4. Révoquer les jetons d'agents : un poste, ou tout le parc (chaque agent se réinscrit ensuite avec un code)
docker exec <nexarc> node src/cli.js agents revoquer <hôte>
docker exec <nexarc> node src/cli.js agents revoquer --tous
# 5. Tourner les secrets touchés : voir « Secrets inventory »
# 6. Forcer un nouveau mot de passe : Page Comptes → compte → « Réinitialiser » (le second facteur reste exigé)
# 7. Restaurer, depuis le poste qui garde la clé privée, puis remettre la base dans le volume
node src/cli.js restaurer nexarc-sauvegarde.pem nexarc.db < nexarc-AAAA-MM-JJ.sauv
docker stop <nexarc> && docker run --rm -v <volume>:/data -v "$PWD":/b busybox sh -c 'cp /b/nexarc.db /data/nexarc.db && rm -f /data/nexarc.db-wal /data/nexarc.db-shm && chown 10001:10001 /data/nexarc.db && chmod 600 /data/nexarc.db' && docker start <nexarc>
#    Base sauvegardée avant une rotation : poser la clé d'alors dans SOCLE_CLE_ANCIENNE avant de démarrer
# 8. Vérifier la chaîne du journal : Page Comptes → Journal de sécurité (« chaîne intacte »)
```
Qui : l’exploitant de l’instance tient chaque étape ; supports pour révoquer : console du Hub (jeton de service), MeshCentral (clé de connexion), support.github.com pour le dépôt. Communiquer : prévenir les comptes concernés ; si des données personnelles ont pu être lues (comptes, inventaires, sorties de tâches), notifier l’autorité de contrôle sous 72 heures à compter de la découverte (heure de découverte, nature, comptes touchés, mesures prises), et les personnes si le risque est élevé. Revue après incident : cause, chronologie, contrôle qui a manqué, correctif et essai de non-régression.

## Inventory
Routes publiques : `GET /api/health` (`{ok:true}` seulement), `GET /.well-known/security.txt`, `GET /api/compte/etat`, cérémonies de connexion et d’installation du socle (`/api/compte/connexion*`, `/api/compte/installation`, `/api/compte/jeton*`, `/api/compte/courriel/verifier`, `/api/compte/pas-moi/lien`, `/api/compte/deconnexion`), fichiers de `web/` et `socle/web/` (tout segment commençant par un point → 404). Code d’inscription : `POST /api/enroll/config` (échange), `GET /api/enroll/agent.py`, `GET /api/enroll/requirements.txt`, `GET /api/enroll/script`. Jeton d’agent : `POST /api/ingest`, `POST /api/agent/jobs`, `POST /api/agent/jobs/:ref/result`. Jeton du Hub : `GET /api/state`, `GET /api/summary`, `POST /api/machines/:ref/jobs` (sans commande libre), `POST /api/machines/:ref/wake`. Session : 28 routes sous `/api/`, chacune avec son rôle déclaré et vérifié dans le gestionnaire (table figée dans l’essai « autorisation ») ; WebSocket `/vnc/:ref/:idx` (membre) ; origine des consoles (NEXARC_CONSOLE_URL, port à part) : `/c/:passe/…` en HTTP et WebSocket, ouverte par une passe tirée sous session (membre) et liée à elle.

Données : `nexarc.db` (comptes, sessions, jetons hachés, journal chaîné, machines et inventaires, logiciels et mises à jour, tâches et leurs sorties, alertes, automatisations, secrets d’appareils scellés — sensibilité : personnelle et opérationnelle), volume `/data` en 0700, base en 0600.

Tiers (tous chez l’exploitant) : les cartes de gestion et serveurs VNC déclarés (TLS épinglé), MeshCentral s’il est configuré, SYNAPSE s’il est installé, le relais SMTP s’il est configuré. Aucun service en ligne tiers.


## Appendix B sweep
Relancé à chaque génération de ce fichier (bash, LC_ALL=C.UTF-8) ; un résultat différent de celui qui a été relu arrête la génération. B.5 est dans NO-VIBE.md.

| # | Commande | Résultat | Justification |
|---|---|---|---|
| B.1.1 | `git log --all --format='%an <%ae>' \| sort -u` | `CodexX64 <CodexX64@users.noreply.github.com>` | le pseudonyme seul |
| B.1.2 | `git log --all --format='%cn <%ce>' \| sort -u` | `CodexX64 <CodexX64@users.noreply.github.com>` | le pseudonyme seul |
| B.1.3 | `git log --all --format='%B' \| rg -in 'co-authored-by\|generated (by\|with)\|assistant\|as an ai'` | 0 ligne |  |
| B.1.4 | `find . -path ./node_modules -prune -o \( -name .ai -o -name .cursor -o -name .aider -o -name .continue -o -name .windsurfrules \) -print` | 0 ligne |  |
| B.1.5 | `find . -path ./node_modules -prune -o -regextype posix-extended -regex '.*/(CLAUDE\|AGENTS?\|PROMPTS?\|GEMINI)\.md' -print` | 0 ligne |  |
| B.1.6 | `git log --all --name-only --format= \| sort -u \| rg -i '(^\|/)(CLAUDE\|AGENTS?\|PROMPTS?\|GEMINI)\.md$\|copilot-instructions\|\.cursor\|\.aider'` | 0 ligne | aucun fichier de consignes d’outil dans tout l’historique |
| B.1.7 | `rg -n 'copilot-instructions' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.1.8 | `git grep -nIiE` avec le motif « personal infrastructure, paths and networks » de l’annexe B.1, hors des deux fichiers de conformité | 1 ligne | le nom de fichier `.env.local` du .gitignore |
| B.1.9 | `git log --all -p` filtré par le motif « infrastructure personnelle » de l’annexe B.1, compté | `4` | le mot « cadenas » (icône de la page Sécurité) et un mot anglais d’un commentaire de noVNC, qui contiennent le motif ; aucun terme d’infrastructure |
| B.1.10 | `git log --all --format='%aI' \| rg -v '\+00:00' \| wc -l` | `0` | tout l’historique en UTC |
| B.1.11 | `git log --all --format='%cI' \| rg -v '\+00:00' \| wc -l` | `0` | idem pour le validateur |
| B.1.12 | `git grep -nIE '/home/[a-z]\|/[U]sers/[A-Za-z]\|/tmp/[c]laude\|[c]laude-0\|[s]cratchpad' $(git rev-list --all) \| wc -l` | `0` | aucun chemin d’un poste ni d’un espace de travail d’outil dans aucun arbre de l’historique, relevés compris |
| B.1.13 | `git log --all --name-only --format= \| sort -u \| rg -i '\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$'` | 0 ligne | aucun binaire image ou document dans tout l’historique : exiftool n’a rien à lire |
| B.1.14 | `git log --all -p` filtré par la liste d’anonymat (hors dépôt), compté | `0` | liste d’anonymat, hors dépôt, sur tout l’historique : arbres, messages, identités |
| B.2.1 | `gitleaks git --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | tout l’historique |
| B.2.2 | `gitleaks dir --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | arbre de travail |
| B.2.3 | `git grep -nIiE '(api[_-]?key\|secret\|token\|password\|bearer)\s*[=:]\s*["'"'"'][^"'"'"']{8,}' -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 7 lignes | mots de passe de cartes fabriqués pour les essais et l’exercice de rotation, vecteur publié de la RFC 6238 ; aucune vraie clé |
| B.2.4 | `git grep -nI -e '-----BEGIN (RSA\|EC\|OPENSSH\|PGP) PRIVATE' -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 0 ligne |  |
| B.2.5 | `rg -ni 'sk_live\|service_role\|xox[baprs]-\|-----BEGIN' web socle/web` | 0 ligne | aucune étape de construction : le navigateur reçoit web/ et socle/web tels quels |
| B.2.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/.env` | `404` | instance locale ; tout segment caché répond 404 |
| B.3.1 | `rg -n 'dangerouslySetInnerHTML\|innerHTML *=\|outerHTML *=\|document\.write' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 2 lignes | le gabarit du socle : balisage écrit dans le code, valeurs posées en nœuds texte ou attributs (SEC-XSS-001) |
| B.3.2 | `rg -n 'eval\(\|new Function\(\|execSync\|child_process\|os\.system\|subprocess.*shell=True' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 6 lignes | outils et essais seulement, chacun sans shell, binaire fixe et arguments en tableau : les exercices de rotation et d’incident lancent NEXARC et sa ligne de commande (`process.execPath`), les essais du service lancent la ligne de commande, `bash -n` (contrôle de syntaxe des scripts d’inscription) et openssl (certificats chaînés tirés à la volée), ceux du socle openssl et python3 ; rien dans src/ ni dans l’agent |
| B.3.3 | `rg -n '[^.]\bexec\(' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.4 | `rg -n 'f"SELECT\|"SELECT .*" *\+\|\$\{.*\} *FROM\|\.raw\(\|query\(.*\+ *req\.' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.5 | `rg -n 'Math\.random\|uuidv1\|new Random\(\)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.6 | `rg -n 'verify *= *False\|rejectUnauthorized: *false\|InsecureSkipVerify' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 5 lignes | cinq lignes, justifiées une à une dans le tableau « B.3 — TLS sans vérification par autorité, ligne à ligne » ci-dessous : la sonde de confiance au premier usage (`src/tls.js`), la session épinglée de l’agent (`agent/nexarc-agent.py`), trois commentaires |
| B.3.7 | `rg -n 'jwt\.decode\(\|algorithms: *\[.*none\|verify: *false' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.4.1 | `curl -sI http://localhost:18142/ \| rg -i 'content-security\|x-content-type\|referrer-policy\|permissions-policy\|x-frame\|cross-origin' \| wc -l` | `7` | CSP à nonce sans joker, nosniff, no-referrer, DENY, COOP et CORP same-origin, Permissions-Policy ; HSTS dès que la requête est chiffrée (H1) |
| B.4.2 | `curl -sI http://localhost:18142/ \| rg -i '^(server\|x-powered-by\|x-aspnet\|x-generator)'` | 0 ligne |  |
| B.4.3 | `curl -sI -H 'Origin: https://evil.example' http://localhost:18142/api/state \| rg -i access-control` | 0 ligne | aucun CORS : même origine seulement |
| B.4.4 | `curl -sI 'http://localhost:18142/login?next=https://evil.example' \| rg -i '^location'` | 0 ligne | aucune redirection : 404 |
| B.4.5 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/.git/config` | `404` |  |
| B.4.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/console/AAAAAAAAAAAAAAAA/0/` | `404` | plus aucun mandataire sous l’origine de NEXARC : les consoles web ont leur propre origine |
| B.4.7 | `curl -s -o /dev/null -w '%{http_code}' 'http://localhost:18142/api/enroll/config?code=AAAAAAAAAAAAAAAAAAAAAA'` | `405` | l’échange d’un code est un POST ; un GET ne change rien |
| B.4.8 | `for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:18142/api/compte/connexion -H 'Content-Type: application/json' -H 'Origin: http://localhost:18142' -d '{"identifiant":"quelquun","motDePasse":"mauvais mot de passe"}'; done` | `401 401 401 428` | trois échecs, puis preuve de travail exigée (428) ; 429 et verrouillage au-delà |
| B.4.9 | quarante `POST /api/ingest` avec un jeton d’agent inventé, codes de réponse comptés (la commande exacte cite un jeton fabriqué : elle reste dans le générateur, hors dépôt) | `10 401 30 429` | un jeton d’agent inventé : 401, puis 429 une fois le plafond d’échecs de l’adresse atteint |

### B.3 — TLS sans vérification par autorité, ligne à ligne
Chaque ligne rendue par la commande B.3 correspondante, avec sa justification ; une ligne sans justification arrête la génération.

| Ligne | Ce qu’elle est | Pourquoi elle est admise |
|---|---|---|
| `test/nexarc.test.js:436` | commentaire d’un essai | aucun code : l’essai prouve que l’alimentation reste refusée (409) tant que le certificat de la carte n’est pas épinglé |
| `agent/nexarc-agent.py:106` | commentaire de `session_http()` | explique la ligne précédente ; aucun code |
| `agent/nexarc-agent.py:113` | la session HTTP de l’agent quand une empreinte est épinglée (`session_http()`) | urllib3 n’accepte `assert_fingerprint` qu’avec `verify=False` : la vérification par autorité est remplacée par la comparaison exacte de l’empreinte SHA-256 épinglée (`EpingleAdapter`), avant le moindre octet envoyé ; un seul certificat passe. Sans empreinte bien formée (64 caractères hexadécimaux), l’autorité vérifie toujours : le fichier NEXARC_CA, sinon celles du système. Essais `test_empreinte_juste_acceptee`, `test_empreinte_differente_refusee`, `test_empreinte_mal_formee_ne_desactive_rien`, `test_verify_false_seulement_avec_une_empreinte`, contre un vrai serveur HTTPS local |
| `agent/test_agent.py:6` | présentation des essais de l’agent | aucun code |
| `src/tls.js:44` | la sonde `observer()` de confiance au premier usage, seule connexion du serveur sans vérification par autorité | bornée par trois garanties écrites au-dessus d’elle et essayées : (1) atteinte seulement par `GET` et `POST /api/machines/:ref/pin`, administrateur sous renfort récent ; (2) aucune donnée applicative envoyée, socket fermée dès la poignée finie ; (3) ne rend que l’empreinte SHA-256 et le sujet, le certificat n’étant gardé qu’après confirmation de l’empreinte montrée (le POST revérifie qu’elle n’a pas changé). Toute connexion d’exploitation passe par `agentEpingle()` : `rejectUnauthorized: true`, certificat épinglé pour seule autorité, feuille exactement épinglée. Essais « sonde TLS : admin + renfort seulement, aucun octet applicatif, empreinte et sujet seuls » et « épinglage TLS : le certificat épinglé passe, une empreinte différente est refusée » |

## Exploratory probing (SEC-TEST-007)
Sondage exploratoire du 2026-09-30, rejoué à chaque génération de ce fichier sur une instance neuve (vrais comptes, vrais agents, carte simulée, origine des consoles) : 40 cas d’abus tentés, chacun avec la réponse obtenue et celle qu’exige la règle ; un seul écart arrête la génération. Chaque trouvaille de ce sondage est devenue un essai (constats marqués « * »).

| # | Cas d’abus | Tenté | Obtenu | Attendu |
|---|---|---|---|---|
| P1 | référence de machine inventée | `GET /api/machines/ZZZZZZZZZZZZZZZZ/jobs (membre)` | 404 | 404 |
| P2 | entier interne à la place d’une référence | `GET /api/machines/1/jobs (membre)` | 404 | 404 |
| P3 | tâche d’un autre agent | `POST /api/agent/jobs/<tâche de A>/result avec le jeton de B` | 404 | 404 |
| P4 | relève croisée | `POST /api/agent/jobs avec le jeton de B : tâches de A visibles ?` | 0 | 0 |
| P5 | anonyme sur l’état du parc | `GET /api/state` | 401 | 401 |
| P6 | lecture seule qui écrit | `POST /api/machines/<A>/jobs (lecture)` | 403 | 403 |
| P7 | membre sur une route d’administration | `DELETE /api/machines/<A> (membre)` | 403 | 403 |
| P8 | membre qui déclare une carte | `POST /api/hosts (membre)` | 403 | 403 |
| P9 | commande libre par un membre | `POST jobs kind=cmd (membre)` | 403 | 403 |
| P10 | commande libre par le jeton du Hub | `POST jobs kind=cmd (Hub)` | 403 | 403 |
| P11 | jeton du Hub sur les comptes | `GET /api/compte/admin/comptes (Hub)` | 401 | 401 |
| P12 | champ privilégié glissé dans un corps | `POST /api/automations {…, actif: 1, role: "admin"}` | 400 | 400 |
| P13 | agent qui se déclare relais | `POST /api/ingest role=relais (poste enrôlé comme poste)` | poste | poste |
| P14 | corps de 2 Mio | `POST /api/automations, 2 Mio` | 413 | 413 |
| P15 | corps en formulaire | `POST /api/automations en x-www-form-urlencoded` | 415 | 415 |
| P16 | paramètre de requête non déclaré | `GET /api/state?limit=100000` | 400 | 400 |
| P17 | charge shell dans un paquet | `install « htop; rm -rf / »` | 422 | 422 |
| P18 | option déguisée en paquet | `install « --config=/etc/shadow »` | 422 | 422 |
| P19 | réveil dicté dans une tâche | `POST jobs kind=wol` | 400 | 400 |
| P20 | SQL dans une cible d’automatisation | `cible host = « ' OR '1'='1 », puis lancement` | 0 | 0 |
| P21 | balisage dans un nom | `automatisation nommée « <img onerror> », relue telle quelle (texte, jamais balisage : DOM par h())` | true | true |
| P22 | valeur piégée pour un script root | `POST /api/enroll/info site « x';id;' »` | 422 | 422 |
| P23 | prototype dans un corps JSON | `PUT consoles avec __proto__ (admin)` | 400 | 400 |
| P24 | métadonnées de nuage comme carte | `POST /api/hosts cible 169.254.169.254 (admin)` | 422 | 422 |
| P25 | Redfish en HTTP | `PUT redfish http:// (admin)` | 422 | 422 |
| P26 | fichier caché | `GET /.env` | 404 | 404 |
| P27 | dépôt git servi ? | `GET /.git/config` | 404 | 404 |
| P28 | remontée de répertoire | `GET /..%2f..%2fetc%2fpasswd` | 404 | 404 |
| P29 | sonde de santé anonyme | `GET /api/health` | {"ok":true} | {"ok":true} |
| P30 | écriture d’un autre site | `POST /api/automations, Origin étrangère` | 403 | 403 |
| P31 | écriture sans jeton anti-CSRF | `POST /api/automations sans X-CSRF` | 403 | 403 |
| P32 | pont VNC ouvert depuis un autre site | `mise à niveau /vnc/… avec Origin étrangère et cookie du membre` | 403 | 403 |
| P33 | suppression sans renfort récent | `DELETE /api/machines/<B> (admin, renfort expiré)` | 403 | 403 |
| P34 | sortie d’une commande libre lue par un membre | `GET /api/machines/<A>/jobs (membre)` | "" | "" |
| P35 | passe de console inventée | `GET /c/<43 caractères>/ sur l’origine des consoles` | 404 | 404 |
| P36 | passe utilisée depuis un autre site pour écrire | `POST /c/<passe>/… avec Origin étrangère` | 403 | 403 |
| P37 | API de NEXARC sur l’origine des consoles | `GET /api/state sur l’origine des consoles` | 404 | 404 |
| P38 | jetons d’agents devinés en rafale | `12 POST /api/ingest avec un jeton inventé` | 429 429 | 429 429 |
| P39 | mot de passe deviné en rafale | `6 POST /api/compte/connexion` | 401 428 | 401 428 |
| P40 | flux d’activité en rafale | `5 GET /api/activite ouverts ensemble, même session` | 200 200 200 200 429 | 200 200 200 200 429 |
