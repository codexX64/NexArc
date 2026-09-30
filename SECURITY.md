# Security compliance — Sentinel RMM

Standard: Project Baseline Requirements & Security Manual, Edition 2.0 (258 controls)
Audited: 2026-09-30   ·   Owner: Codex64   ·   Status: NON-COMPLIANT

## Summary
| Part | Controls | Pass | Fail | N/A | Unknown |
|---|---|---|---|---|---|
| I — Baseline requirements | 68 | 38 | 23 | 2 | 5 |
| II — Security controls | 190 | 66 | 52 | 71 | 1 |
| Total | 258 | 104 | 75 | 73 | 6 |

## Authentication posture
Deux publics. Les opérateurs passent par le socle commun, embarqué avec ses essais : quatre facteurs cumulables sur chaque compte — mot de passe (Argon2id, 64 Mio, 3 passes, parallélisme 4, plancher 19 Mio / 2 / 1, rehachage transparent, empreinte scrypt de la 1.x reprise puis rehachée à la connexion, liste de fuites locale, 12 à 1024 caractères), application TOTP (RFC 6238, secret généré côté serveur et scellé AES-256-GCM, QR code dessiné dans le navigateur, rejeu refusé), clés d’accès WebAuthn (résidentes, vérification de l’utilisateur exigée, jusqu’à vingt, nommées et révocables) et dix codes de secours de 100 bits hachés. Politique par facteur : mot de passe et TOTP facultatifs, clé requise pour les administrateurs, qui tiennent deux facteurs dont une clé (deux facteurs sans clé en mode HTTP dégradé, affiché partout). Un mot de passe seul n’ouvre qu’une session d’inscription. Sessions serveur (jeton de 256 bits, empreinte seule en base), renouvelées à chaque changement de niveau, 12 heures au plus et 60 minutes d’inactivité, listées et révocables une à une ou toutes ; les WebSockets de console revérifient la session à la mise à niveau. Renfort de cinq minutes avec le facteur le plus fort avant tout changement de facteur, de rôle ou de politique, avant une suppression, un export, un secret d’appareil, un épinglage, une coupure d’alimentation, une commande libre . Rôles : lecture (voit le parc), membre (tâches, réveil, allumage, acquittement), administrateur (commande libre, secrets et accès distants, alimentation qui coupe, comptes). Les machines présentent un jeton d’agent de 192 bits, propre à chacune, gardé en SHA-256, obtenu contre un code d’inscription de 72 bits gardé en clair (à corriger, REQ-CRYPT-005 et -006) ; le Hub présente un jeton de service (Bearer, 24 caractères au moins, comparé en temps constant) qui n’ouvre que l’état, les tâches (sans la commande libre) et le réveil. Limiteur persistant par adresse et par compte pour les humains, preuve de travail après trois échecs, paliers de verrouillage . La clé maîtresse et le poivre se tournent sans réinscription.


## Control status
| ID | Severity | Status | Evidence | Notes |
|---|---|---|---|---|
| REQ-AUTH-001 | CRITICAL | PASS | `socle/src/comptes.js:24` ; mot de passe, TOTP, clés et codes de secours cumulables : essai `socle/test/parcours.test.js:135` | socle embarqué, ses essais rejoués par la vérification de Sentinel (`.github/workflows/verification.yml:37`) ; QR code du TOTP dessiné dans le navigateur (`socle/web/qr.js:240`) |
| REQ-AUTH-002 | CRITICAL | PASS | `socle/src/comptes.js:27` ; `socle/src/index.js:49` ; réglable sans déploiement : `socle/src/portail.js:363` | défaut : mot de passe et TOTP facultatifs, clé requise pour les administrateurs |
| REQ-AUTH-003 | CRITICAL | PASS | `socle/src/webauthn.js:26` ; vingt clés nommées : `socle/src/comptes.js:35` ; renommer et retirer : `socle/src/portail.js:291` | liste avec dates de création et d’usage dans la page Sécurité |
| REQ-AUTH-004 | CRITICAL | PASS | `socle/src/webauthn.js:46` ; origine `socle/src/webauthn.js:47` ; rpIdHash `socle/src/webauthn.js:103` | défi à usage unique lié à la session, UP et UV exigés, signature et compteur vérifiés |
| REQ-AUTH-005 | CRITICAL | PASS | `socle/src/comptes.js:623` ; renfort et fermeture des autres sessions : `socle/src/comptes.js:639` | la notification part à l’adresse vérifiée quand un relais existe (voir REQ-AUTH-014) |
| REQ-AUTH-006 | CRITICAL | PASS | `socle/src/comptes.js:828` ; jeton de 20 minutes, haché, unique : `socle/src/comptes.js:33` | essai `socle/test/parcours.test.js:218` ; l’opérateur de la 1.x repris sans mot de passe est remis en selle par ce lien (`src/migration.js:34`) |
| REQ-AUTH-007 | HIGH | PASS | `socle/src/comptes.js:36` ; 100 bits, haché Argon2id, usage unique : `socle/src/comptes.js:423` | alerte « secours.utilise » (courriel si relais, voir REQ-AUTH-014) ; la 1.x n’avait pas de codes de secours |
| REQ-AUTH-008 | HIGH | PASS | `socle/src/totp.js:35` ; rejeu refusé : `socle/src/comptes.js:515` | RFC 6238, 6 chiffres, 30 s, ±1 pas, secret scellé AES-256-GCM ; le secret TOTP en clair de la 1.x est scellé à la reprise (`src/migration.js:36`) |
| REQ-AUTH-009 | CRITICAL | PASS | aucune voie SMS ni code par courriel : `grep -rniE "sms\|twilio" socle/src src` → 0 ; connexions possibles : `socle/src/comptes.js:356`, `socle/src/comptes.js:382`, `socle/src/comptes.js:404`, `socle/src/comptes.js:469` | un mot de passe seul n’ouvre qu’une session d’inscription |
| REQ-AUTH-010 | CRITICAL | FAIL | humains : `socle/src/limiteur.js:20` (SQLite, par adresse et par compte, paliers de verrou, preuve de travail) ; mais les codes d’inscription et les jetons d’agents, reçus sur des routes publiques (`src/api.js:357`, `src/api.js:404`), et le jeton du Hub (`src/api.js:63`) ne sont bornés que par le débit global de 900 requêtes par minute | à corriger : un plafond d’échecs par adresse sur chaque route qui accepte un code ou un jeton |
| REQ-AUTH-011 | HIGH | PASS | vérification leurre : `socle/src/argon.js:110` ; message unique | essai `socle/test/parcours.test.js:81` |
| REQ-AUTH-012 | HIGH | PASS | `socle/src/comptes.js:867` : l’adresse n’existe que dans le jeton haché tant qu’elle n’est pas vérifiée ; `socle/src/comptes.js:876` | l’adresse ne sert qu’aux alertes : ni identifiant, ni récupération, ni droit ; pas d’inscription libre (invitation seulement) |
| REQ-AUTH-013 | HIGH | PASS | `socle/src/comptes.js:709` | l’opérateur de la 1.x devient administrateur et doit inscrire une clé avant tout accès complet |
| REQ-AUTH-014 | MEDIUM | FAIL | `socle/src/notifications.js:78` ; « ce n’était pas moi » : `socle/src/comptes.js:854` | implémenté et essayé (`socle/test/courriel.test.js:63` par courriel») ; ne part que si un relais SMTP est configuré → action H2 |
| REQ-CRYPT-001 | CRITICAL | PASS | `socle/src/argon.js:15` ; 64 Mio, t=3, p=4 par défaut : `socle/src/index.js:42` | Argon2id natif de Node, sel de 16 octets par empreinte ; les essais tournent aux paramètres de production |
| REQ-CRYPT-002 | HIGH | PASS | `socle/src/argon.js:72` ; écrit dans la même requête : `socle/src/argon.js:129` | l’empreinte scrypt de la 1.x est reprise telle quelle puis passe en Argon2id à la connexion suivante : essai `test/sentinel.test.js:415` |
| REQ-CRYPT-003 | MEDIUM | N/A | bcrypt absent : `grep -rniE "bcrypt" socle/src src agent` → 0 ; Argon2id seul |  |
| REQ-CRYPT-004 | HIGH | PASS | `socle/src/motdepasse.js:12`, `socle/src/motdepasse.js:13`, liste de fuites locale `socle/src/motdepasse.js:18` | contrôlé côté serveur, sans règle de composition ni rotation forcée |
| REQ-CRYPT-005 | HIGH | FAIL | `socle/src/outils.js:16` ; jetons d’agents de 192 bits : `src/agents.js:50` ; jeton du Hub comparé en temps constant : `src/api.js:63` ; mais le code d’inscription n’a que 72 bits : `src/agents.js:35` | à corriger : 128 bits au moins pour tout jeton |
| REQ-CRYPT-006 | MEDIUM | FAIL | jetons d’agents gardés hachés : `src/agents.js:19` ; sessions : `socle/src/comptes.js:259` ; mais les codes d’inscription sont gardés en clair (`src/base.js:74`, `src/agents.js:47`) | à corriger : une lecture de la base donnerait des codes encore échangeables contre un jeton d’agent |
| REQ-SESS-001 | CRITICAL | PASS | `socle/src/http.js:103` ; __Host- en HTTPS : `socle/src/portail.js:44` ; essai `test/sentinel.test.js:112` | aucune session dans le stockage du navigateur |
| REQ-SESS-002 | CRITICAL | PASS | `socle/src/comptes.js:269` à la connexion, au renfort et à chaque changement de facteur ou de rôle | pas de jeton de rafraîchissement : sessions serveur |
| REQ-SESS-003 | HIGH | PASS | `socle/src/comptes.js:305` ; révocation : `socle/src/portail.js:301` et incident : `socle/src/portail.js:376` | appareil, adresse IP, première et dernière vue |
| REQ-SESS-004 | HIGH | PASS | `socle/src/comptes.js:641` ; déconnexion serveur : `socle/src/portail.js:258` | les WebSockets de console revérifient la session à la mise à niveau |
| REQ-SESS-005 | HIGH | PASS | `socle/src/comptes.js:321` ; routes de Sentinel sous renfort : secrets d’appareils (`src/api.js:152`), épinglage et alimentation (`src/api.js:226`), suppression d’une machine, commande libre |  |
| REQ-SESS-006 | MEDIUM | PASS | 12 h absolues, 60 min d’inactivité : `socle/src/index.js:40` | pas de JWT |
| REQ-ANON-001 | CRITICAL | PASS | `git log --all --format="%an <%ae>" \| sort -u` et `--format="%cn <%ce>"` → une ligne chacun, le pseudonyme ; posée dans le dépôt : `git config --local user.name` → 1 | dépôt neuf de la version 2, commits en UTC |
| REQ-ANON-002 | CRITICAL | PASS | arbre : annexe B.1 → une seule correspondance, le nom `.env.local` dans `.gitignore:10` ; aucun terme de la liste d’anonymat ; historique local complet : le motif « infrastructure personnelle » ne relève que des mots qui le contiennent (annexe B ci-dessous) | l’historique de la 1.x n’est pas dans ce dépôt : il vit sur l’ancien dépôt publié, que seul l’exploitant peut remplacer → action H12 |
| REQ-ANON-003 | CRITICAL | FAIL | liste et crochet global à poser sur le poste de développement ; contrôle CI par secret : `.github/workflows/verification.yml:91` | action H4 |
| REQ-ANON-004 | CRITICAL | PASS | commande de REQ-ANON-004 sur tout l’historique (`git log --all --format=%B \| grep -niE "co-authored-by\|generated with\|assistant\|claude\|copilot\|cursor\|gpt\|🤖"`) → 0 | contrôlé en CI sur chaque nouveau commit : `.github/workflows/verification.yml:69` |
| REQ-ANON-005 | HIGH | PASS | `package.json:6` sans champ auteur ; `LICENSE:3` | le README décrit le logiciel, jamais une machine ni une personne ; contact de sécurité : le signalement privé du dépôt (`src/main.js:27`) |
| REQ-ANON-006 | HIGH | PASS | `git log --all --name-only --format= \| grep -iE "\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$" \| wc -l` → 0 : aucune image ni document binaire dans tout l’historique ; l’icône est un SVG sans métadonnées (`web/icone.svg:1`) | polices WOFF2 du socle : métadonnées de la fonderie seulement ; captures du parcours gardées hors dépôt |
| REQ-ANON-007 | HIGH | PASS | comptes « ana », « bruno », « chloe », « lea », « dora » ; machines « poste-x », « serveur-a », « srv-alim » ; adresses de la plage de documentation (`test/sentinel.test.js:44`) ; jetons d’essai fabriqués (`test/sentinel.test.js:24`) ; certificats d’essai tirés à la volée (`test/faux.js:64`) | essais, outils et exemples relus ; les plages privées n’apparaissent que dans le classement des adresses, assemblées à l’exécution (`src/reseau.js:18`) |
| REQ-ANON-008 | MEDIUM | PASS | `git log --all --format=%aI \| grep -v "+00:00$" \| wc -l` → 0 ; `git log --all --format=%cI \| grep -v "+00:00$" \| wc -l` → 0 | auteur et validateur en UTC sur tout l’historique |
| REQ-ANON-009 | MEDIUM | FAIL | pages d’erreur sans chemin : `socle/src/http.js:163` ; domaine et WHOIS hors dépôt | action H13 |
| REQ-ANON-010 | MEDIUM | PASS | identité stable et unique, dates réelles (TZ=UTC, jamais antidatées) | aucune politique de contribution externe |
| REQ-CFG-001 | CRITICAL | PASS | gitleaks sur tout l’historique, relancé à chaque génération de ce fichier → aucune fuite ; `git grep` de l’annexe B.2 → valeurs d’essai fabriquées et vecteur publié de la RFC 6238 ; `-----BEGIN … PRIVATE` → 0 | détail dans l’annexe B ci-dessous |
| REQ-CFG-002 | CRITICAL | PASS | secrets d’appareils jamais rendus : `src/base.js:107` ; identifiants Redfish réduits à « en place » (`src/base.js:135`) ; jeton d’agent échangé par l’agent lui-même, jamais par le navigateur | aucune construction : web/ est servi tel quel ; essais `test/sentinel.test.js:288`, `test/sentinel.test.js:252` |
| REQ-CFG-003 | HIGH | FAIL | VM d’essai et production distinctes (instruction de l’exploitant) | clés séparées par environnement à vérifier et à émettre : action H6 |
| REQ-CFG-004 | HIGH | FAIL | `src/config.js:8` sur `socle/src/config.js:14` ; mais une clé de connexion Mesh mal formée passe le démarrage (`src/config.js:46`) et n’échoue qu’à l’ouverture d’un bureau, et `SYNAPSE_JETON` n’a ni longueur minimale ni contrôle de valeur d’exemple (`src/config.js:52`) | à corriger : refuser au démarrage |
| REQ-CFG-005 | HIGH | FAIL | SOCLE_CLE se tourne sans réinscription (README, « Tourner la clé maîtresse », exercice `outils/exercice-rotation.mjs`) ; mais un jeton d’agent ne se remplace qu’en supprimant sa machine et son historique : aucune révocation ni réémission | à corriger : révoquer le jeton d’un agent (ou de tous) sans perdre la machine |
| REQ-CI-001 | CRITICAL | FAIL | `.github/workflows/verification.yml:57` | Actions, crochet local et protection de poussée à activer : actions H3, H4 |
| REQ-CI-002 | HIGH | FAIL | `.github/workflows/verification.yml:114` | bloquant une fois les Actions actives et le contrôle requis : action H3 |
| REQ-CI-003 | HIGH | FAIL | aucune dépendance npm (`package.json:8` sans dépendances) ; image de base épinglée `Dockerfile:6` ; SBOM `.github/workflows/publish.yml:89` ; mais les dépendances de l’agent sont des plages (`agent/requirements.txt:1`) et le script d’inscription installe la dernière version publiée, sans empreinte (`src/enroll.js:114`) | à corriger ; exécution en CI et contrôle requis : action H3 |
| REQ-CI-004 | HIGH | FAIL | `.github/workflows/verification.yml:91` | échoue tant que le secret n’existe pas : action H4 |
| REQ-CI-005 | MEDIUM | FAIL | permissions minimales `.github/workflows/verification.yml:15` ; actions épinglées par commit | protection de branche : action H3 |
| REQ-CI-006 | MEDIUM | PASS | `test/sentinel.test.js:146` (sans preuve → 401, lecture sur écriture → 403, membre sur route d’administrateur → 403) ; listes figées dans l’essai : `test/sentinel.test.js:171` | objets d’un agent essayés depuis un autre agent (`test/sentinel.test.js:200`) ; cassures volontaires : NO-VIBE.md |
| REQ-WEB-001 | CRITICAL | FAIL | HSTS dès que la requête est chiffrée : `socle/src/http.js:86` | Sentinel est servi en HTTP sur le réseau local tant qu’aucun relais TLS n’est posé : action H1 |
| REQ-WEB-002 | HIGH | FAIL | pages de Sentinel : `socle/src/http.js:62` (script-src 'self' 'nonce-…') ; mais le mandataire des consoles sert le HTML d’une carte depuis l’origine de Sentinel sans aucune politique de script (`src/main.js:99`, `src/proxy.js:94`) et y injecte un script en ligne (`src/proxy.js:29`) | à corriger : le code d’une carte ne doit jamais s’exécuter dans l’origine de Sentinel |
| REQ-WEB-003 | HIGH | FAIL | `socle/src/http.js:79` ; no-store sur l’API et les pages ; mais les réponses du mandataire des consoles échappent à l’ensemble des en-têtes (ni nosniff, ni Permissions-Policy, cache de la carte repris tel quel) | à corriger avec REQ-WEB-002 |
| REQ-WEB-004 | HIGH | PASS | aucun en-tête CORS émis : `curl -sI -H "Origin: https://evil.example" /api/state` → aucun Access-Control-* (annexe B.4) | API de même origine pour le navigateur ; agents et Hub appellent de serveur à serveur |
| REQ-WEB-005 | HIGH | FAIL | CSRF : `socle/src/portail.js:86` ; JSON exigé : `socle/src/http.js:120` ; mais trois GET écrivent (code tiré `src/api.js:337`, code échangé `src/api.js:357`, tâches marquées en cours `src/api.js:404`) ; un membre choisit les adresses internes que le serveur joint (consoles, cartes : `src/api.js:149`, `src/api.js:240`) ; et le mandataire transmet le cookie de session de Sentinel à la carte (`src/proxy.js:21` sans « cookie ») | à corriger |
| REQ-WEB-006 | CRITICAL | FAIL | schéma strict sur chaque corps (`socle/src/schema.js:69`) ; rôle vérifié dans chaque gestionnaire ; mais la charge d’une tâche n’est pas validée selon son type (`src/api.js:31`) : un membre ou le Hub peut confier à un agent un paquet mal formé ou un réveil vers une adresse quelconque ; et une automatisation « commande libre » se réactive par un simple membre (`src/api.js:302`) | à corriger |
| REQ-WEB-007 | HIGH | PASS | requêtes préparées partout ; aucun processus lancé par le serveur (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; l’agent n’appelle que des binaires fixes, arguments en liste (`agent/sentinel-agent.py:163`) ; valeurs des scripts d’inscription contrôlées par motif puis entre apostrophes (`src/enroll.js:16`) ; `innerHTML` seulement dans le gabarit du socle, sur du balisage écrit dans le code (`socle/web/gabarit.js:115`) | eval et Function absents ; la commande libre est la fonction elle-même (voir SEC-INJ-004) |
| REQ-WEB-008 | MEDIUM | FAIL | débit global `src/main.js:90`, corps bornés, listes plafonnées ; mais les mises à niveau WebSocket échappent au débit (`src/main.js:113`), les flux d’activité ouverts ne sont pas plafonnés (`src/api.js:84`), la liste des automatisations n’a pas de borne, et une remontée d’agent lit et valide 512 Kio avant de vérifier le jeton (`src/api.js:397`) | à corriger |
| REQ-DATA-001 | CRITICAL | PASS | SQLite embarqué, aucun port : `src/base.js:27` ; dossier en 0700 et base en 0600 : `src/base.js:25` |  |
| REQ-DATA-002 | HIGH | FAIL | secrets d’appareils et TOTP scellés AES-256-GCM : `socle/src/chiffre.js:60` ; mais Redfish accepte une carte en HTTP et y envoie ses identifiants en clair (`src/redfish.js:26`) | à corriger ; chiffrement du disque des hôtes : action H7 |
| REQ-DATA-003 | HIGH | FAIL | aucune sauvegarde : rien ne sort un instantané chiffré de la base | à corriger ; planification, copie hors hôte et restauration datée : action H8 |
| REQ-DATA-004 | HIGH | FAIL | socle : connexions, facteurs, rôles, refus humains (`socle/src/portail.js:98`) ; Sentinel : secrets d’appareils, épinglage, alimentation, suppression, tâches ; mais les refus levés par l’API elle-même ne sont pas journalisés, contrairement à ce qu’annonce `src/api.js:459`, ni les jetons d’agents refusés sur la relève et le résultat, ni l’activation, le lancement ou la suppression d’une automatisation, ni l’ajout d’une carte ou d’une console | à corriger |
| REQ-DATA-005 | MEDIUM | PASS | vigie : `socle/src/vigie.js:11` (connexions, refus, limites, erreurs), jetons d’agents refusés compris (`connexion.jeton` : `src/api.js:399`) ; runbook ci-dessous ; révocation globale des sessions : `socle/src/portail.js:376` | exercice du runbook à dater : action H8 |
| REQ-DATA-006 | MEDIUM | PASS | `web/confidentialite.txt:7` ; alertes résolues gardées trente jours (`src/alertes.js:15`), flux d’activité borné à soixante lignes, codes et jetons en attente purgés à expiration ; export et effacement : `src/main.js:73` | essai `test/sentinel.test.js:337` |
| REQ-DATA-007 | MEDIUM | N/A | aucun envoi de fichier ni import depuis une adresse : corps JSON seulement (`socle/src/http.js:120`), `grep -rniE "multipart\|busboy\|formidable" src socle/src` → 0 |  |
| REQ-CODE-001 | HIGH | UNKNOWN | passe de qualité pas encore menée | phase 6 |
| REQ-CODE-002 | HIGH | UNKNOWN | passe de qualité pas encore menée | phase 6 |
| REQ-CODE-003 | HIGH | UNKNOWN | passe de qualité pas encore menée | phase 6 |
| REQ-CODE-004 | HIGH | UNKNOWN | passe de qualité pas encore menée | phase 6 |
| REQ-CODE-005 | MEDIUM | UNKNOWN | cassures volontaires pas encore menées | phase 6 |
| REQ-CODE-006 | MEDIUM | PASS | `git log --stat` : un sujet par commit, style du dépôt, aucune mention d’outil |  |
| GOV-001 | HIGH | PASS | ce document : revue datée, périmètre (258 contrôles), résolution ligne par ligne, deux passes complètes | à refaire à chaque changement généré important |
| GOV-002 | MEDIUM | PASS | section « Inventory » ci-dessous : routes, données, tiers, secrets |  |
| GOV-003 | LOW | FAIL | `socle/src/portail.js:134` ; contact : `src/main.js:27` | `curl /.well-known/security.txt` → Contact et Expires ; activer le signalement privé sur le dépôt : action H3 |
| GOV-004 | MEDIUM | FAIL | VM d’essai distincte de la production (règle de l’exploitant) ; données d’essai fabriquées | secrets et comptes tiers distincts à confirmer : action H6 |
| GOV-005 | HIGH | FAIL | jeton CI éphémère et limité : `.github/workflows/publish.yml:27` | 2FA sur GitHub et consoles des fournisseurs : action H3 |
| SEC-SECRETS-001 | CRITICAL | PASS | gitleaks sur tout l’historique → aucune fuite ; `git grep` de REQ-CFG-001 → valeurs d’essai seulement | gitleaks en CI (H3) |
| SEC-SECRETS-002 | CRITICAL | PASS | aucune variable publique ni construction : web/ servi tel quel, `grep -rnE "\bsk-[A-Za-z0-9_-]{20}\|sk_live\|service_role\|-----BEGIN" web/*.js web/*.html socle/web` → 0 | rien n’est injecté dans le code servi, sauf le nonce CSP : `web/index.html:11` |
| SEC-SECRETS-003 | CRITICAL | PASS | `.gitignore:9` ; seuls web/ et socle/web sont servis, tout segment caché → 404 (annexe B.2, `/.env` demandé à l’instance d’essai) | secrets vides dans `.env.example:9` |
| SEC-SECRETS-004 | HIGH | PASS | installé par le Hub : secrets posés depuis son coffre (`deploy/compose.hub.yml:51`) ; installé seul : secret Docker hors du volume (`docker-compose.yml:14`) ; fichiers acceptés : `socle/src/config.js:5` | jamais dans la CI |
| SEC-SECRETS-005 | HIGH | FAIL | une clé par usage, lue par Sentinel seul | restreindre et séparer les clés par environnement : action H6 |
| SEC-SECRETS-006 | HIGH | FAIL | procédures de rotation ci-dessous ; SOCLE_CLE exercée de bout en bout (`outils/exercice-rotation.mjs:1`) | jetons et mots de passe vus pendant le développement : action H5 |
| SEC-SECRETS-007 | HIGH | FAIL | clé maîtresse 32 octets aléatoires : `socle/src/chiffre.js:24` ; jeton du Hub d’au moins 24 caractères : `src/config.js:16` ; valeurs d’exemple refusées : `socle/src/config.js:54` ; mais `SYNAPSE_JETON` et la clé de connexion Mesh échappent à ces contrôles (voir REQ-CFG-004) | à corriger |
| SEC-SECRETS-008 | MEDIUM | FAIL | `src/config.js:8` ; mode dégradé affiché en permanence : `socle/web/compte.js:684` ; mais une clé Mesh mal formée ne se découvre qu’à l’usage (voir REQ-CFG-004) | à corriger |
| SEC-AUTH-001 | CRITICAL | PASS | voir REQ-CRYPT-001 |  |
| SEC-AUTH-002 | MEDIUM | PASS | voir REQ-CRYPT-004 |  |
| SEC-AUTH-003 | CRITICAL | FAIL | voir REQ-AUTH-010 | à corriger |
| SEC-AUTH-004 | MEDIUM | PASS | voir REQ-AUTH-011 |  |
| SEC-AUTH-005 | CRITICAL | PASS | voir REQ-AUTH-006 ; lien depuis l’adresse publique : `socle/src/portail.js:49` | sans adresse publique, l’origine attestée par le navigateur de l’administrateur, contrôlée sur la même requête |
| SEC-AUTH-006 | MEDIUM | PASS | confirmation sur la nouvelle adresse et avis à l’ancienne : `socle/src/comptes.js:882` | essai `socle/test/courriel.test.js:122` |
| SEC-AUTH-007 | HIGH | PASS | TOTP et clés pour tous, second facteur imposé aux administrateurs : `socle/src/comptes.js:158` | codes de secours toujours émis |
| SEC-AUTH-008 | HIGH | N/A | aucune connexion par fournisseur externe : `grep -rniE "oauth\|openid\|id_token\|redirect_uri" socle/src src` → 0 |  |
| SEC-AUTH-009 | HIGH | PASS | les liens reçus par courriel demandent un geste : `socle/web/compte.js:430` ; uniques et courts : `socle/src/comptes.js:34` | aucune connexion sans mot de passe par courriel |
| SEC-AUTH-010 | CRITICAL | PASS | chaque route non publique appelle `session()` (portail du socle) en tête : `src/api.js:65` ; le jeton du Hub et le jeton d’agent sont vérifiés dans la route ; WebSocket : session exigée avant la mise à niveau (`src/main.js:118`) | essai `test/sentinel.test.js:146` |
| SEC-AUTH-011 | HIGH | PASS | jeton d’agent inconnu → 401 : `src/api.js:399` ; erreur imprévue réduite à un numéro : `socle/src/http.js:163` | le jeton du Hub présenté et faux ne vaut jamais session : 401 (`test/sentinel.test.js:333`) |
| SEC-SESS-001 | CRITICAL | PASS | voir REQ-SESS-001 |  |
| SEC-SESS-002 | HIGH | PASS | `grep -rn "localStorage" web/*.js socle/web` → thème seulement (`socle/web/compte.js:296`), jamais une session |  |
| SEC-SESS-003 | HIGH | PASS | 256 bits : `socle/src/comptes.js:254` | renouvelé à chaque changement de niveau |
| SEC-SESS-004 | HIGH | PASS | voir REQ-SESS-003, REQ-SESS-004 et REQ-SESS-006 |  |
| SEC-SESS-005 | CRITICAL | N/A | aucun JWT : `grep -rniE "jwt\|jsonwebtoken\|jose" src web/*.js socle agent` → 0 |  |
| SEC-SESS-006 | MEDIUM | N/A | aucun jeton de rafraîchissement : sessions serveur (voir SEC-SESS-005) ; jetons d’agents sans expiration, révoqués par l’administrateur |  |
| SEC-SESS-007 | MEDIUM | PASS | voir REQ-SESS-005 ; avis par courriel via le canal d’alerte | courriel : H2 |
| SEC-AUTHZ-001 | CRITICAL | PASS | le parc est partagé entre les opérateurs, sans propriétaire ; les objets d’un agent sont filtrés dans la requête par sa machine : `src/taches.js:48`, relève : `src/taches.js:40` | essai `test/sentinel.test.js:201` |
| SEC-AUTHZ-002 | CRITICAL | FAIL | rôle humain lu en base par le socle (`socle/src/portail.js:108`) ; portée du Hub fermée (`test/sentinel.test.js:324`) ; mais une automatisation « commande libre » se réactive ou se supprime par un simple membre (`src/api.js:302`, `src/api.js:310`) et les accès distants se déclarent sans rôle d’administrateur (voir SEC-CSRF-004) | à corriger |
| SEC-AUTHZ-003 | HIGH | PASS | schémas stricts, champ inconnu refusé : `socle/src/schema.js:69` ; l’auteur d’une tâche vient de la session, jamais du corps (`src/taches.js:21`) |  |
| SEC-AUTHZ-004 | HIGH | PASS | route /api inconnue → 404, méthode inconnue → 405 avec Allow : `src/api.js:466` ; routes publiques figées dans l’essai (`test/sentinel.test.js:166`) | aucune route de débogage ni de semis |
| SEC-AUTHZ-005 | CRITICAL | N/A | aucune notion de locataire : un site est un libellé du parc, pas une frontière de droits ; `grep -rniE "tenant\|organisation\|workspace" src` → 0 |  |
| SEC-AUTHZ-006 | LOW | PASS | références publiques de 96 bits aléatoires pour les machines, tâches, alertes et automatisations : `src/base.js:17` ; l’entier interne ne sort pas | motif exigé avant toute lecture : `src/base.js:16` |
| SEC-AUTHZ-007 | HIGH | FAIL | vingt tâches en attente au plus par machine (`src/api.js:121`) ; mais une automatisation « commande libre » s’exécute même quand la commande libre est désactivée : ni la création, ni le lancement, ni la ronde ne consultent SENTINEL_ALLOW_EXEC (`src/taches.js:90`) ; un réveil confié à un agent part vers n’importe quelle adresse IPv4 dictée dans la charge | à corriger |
| SEC-AUTHZ-008 | MEDIUM | FAIL | l’interface cache la commande libre aux non-administrateurs, le serveur l’exige sur une tâche ; mais le réglage SENTINEL_ALLOW_EXEC n’est vérifié que sur la route des tâches (`src/api.js:117`) et pas sur les automatisations | à corriger avec SEC-AUTHZ-007 |
| SEC-INJ-001 | CRITICAL | PASS | requêtes préparées ; filtre de cible fait de fragments constants et de valeurs liées : `src/taches.js:66` | annexe B.3 : aucune interpolation de valeur dans le texte SQL |
| SEC-INJ-002 | HIGH | N/A | aucun ORM : node:sqlite, requêtes préparées seulement |  |
| SEC-INJ-003 | HIGH | N/A | aucune base documentaire : SQLite seulement ; JSON rangé en colonne texte |  |
| SEC-INJ-004 | CRITICAL | PASS | serveur : aucun processus (`grep -rnE "child_process\|execFile\|spawn" src` → 0) ; agent : binaire fixe, arguments en liste, `shell=False` (`agent/sentinel-agent.py:163`), paquet validé par motif (`agent/sentinel-agent.py:50`) | la commande libre est la fonction elle-même : un shell fixe reçoit la commande en unique argument (`agent/sentinel-agent.py:520`), réservée à l’administrateur sous renfort et désactivée par défaut |
| SEC-INJ-005 | HIGH | PASS | `socle/src/http.js:182` ; l’agent servi a un chemin fixe (`src/api.js:368`) | aucun nom de fichier fourni par une requête n’est ouvert |
| SEC-INJ-006 | HIGH | PASS | les scripts d’inscription (exécutés en root ou SYSTEM) ne reçoivent que des valeurs contrôlées par motif, placées entre apostrophes : `src/enroll.js:21` | essai `test/sentinel.test.js:616` ; `grep -rnE "new Function\|node:vm" src socle/src` → 0 |
| SEC-INJ-007 | HIGH | N/A | aucun analyseur XML : Redfish en JSON, `grep -rniE "xml2js\|sax\|libxml\|fast-xml\|DOMParser" src socle/src agent` → 0 |  |
| SEC-INJ-008 | HIGH | PASS | JSON seulement ; clés de prototype refusées : `socle/src/schema.js:6` ; inventaire à profondeur bornée : `src/api.js:29` | l’agent ne lit que du JSON (`json.loads`), jamais pickle ni yaml |
| SEC-XSS-001 | CRITICAL | FAIL | interface : DOM construit par `h()`, texte seulement (`web/app.js:5`) ; mais le HTML d’une carte de gestion est servi tel quel sous l’origine de Sentinel (voir REQ-WEB-002) | à corriger |
| SEC-XSS-002 | HIGH | N/A | aucun texte riche ni Markdown rendu : sorties de tâches et textes d’alertes affichés en texte brut (`web/app.js:460`) |  |
| SEC-XSS-003 | HIGH | PASS | aucun eval, setTimeout chaîne ni affectation de location depuis une donnée : `grep -rnE "eval\(\|new Function\|location\.href *=" web/*.js socle/web` → 0 | le hash ne choisit qu’une page connue : `web/app.js:86` |
| SEC-XSS-004 | HIGH | FAIL | voir REQ-WEB-002 | à corriger |
| SEC-XSS-005 | MEDIUM | PASS | seul échange : le Worker de preuve de travail, de même origine : `socle/web/compte.js:233` | aucune écoute de window message |
| SEC-XSS-006 | MEDIUM | FAIL | erreurs imprévues réduites à un numéro (`socle/src/http.js:163`) ; mais le texte d’erreur réseau d’une carte et sa réponse brute atteignent le client (`src/api.js:181`, `src/redfish.js:85`) | à corriger : un motif générique au client, le détail au journal du serveur |
| SEC-XSS-007 | MEDIUM | N/A | aucune redirection pilotée par paramètre ; `curl -sI "/login?next=https://evil.example"` → aucun Location (annexe B.4) |  |
| SEC-XSS-008 | MEDIUM | PASS | aucun script tiers : noVNC servi par Sentinel, empreintes vérifiées (`web/vendor/novnc/PROVENANCE:37`) | vérification CI : `.github/workflows/verification.yml:43` |
| SEC-HDR-001 | HIGH | FAIL | voir REQ-WEB-001 | action H1 |
| SEC-HDR-002 | HIGH | FAIL | voir REQ-WEB-002 | à corriger |
| SEC-HDR-003 | MEDIUM | FAIL | voir REQ-WEB-003 | à corriger |
| SEC-HDR-004 | LOW | PASS | `curl -sI /` : ni Server ni X-Powered-By (annexe B.4) |  |
| SEC-HDR-005 | MEDIUM | FAIL | no-store sur l’API et les pages : `socle/src/http.js:148` ; mais le mandataire reprend les en-têtes de cache de la carte pour des pages ouvertes sous session | à corriger avec REQ-WEB-002 |
| SEC-HDR-006 | CRITICAL | PASS | voir REQ-WEB-004 |  |
| SEC-HDR-007 | HIGH | PASS | voir REQ-SESS-001 |  |
| SEC-CSRF-001 | HIGH | PASS | SameSite=Strict + origine + jeton : `socle/src/portail.js:86` appelé par chaque écriture de session | essai `test/sentinel.test.js:359` ; agents et Hub présentent un jeton en en-tête, que le navigateur n’envoie jamais seul |
| SEC-CSRF-002 | MEDIUM | PASS | `socle/src/http.js:120` | 415 sur tout autre type |
| SEC-CSRF-003 | MEDIUM | FAIL | trois GET écrivent : voir REQ-WEB-005 | à corriger : POST |
| SEC-CSRF-004 | CRITICAL | FAIL | garde de sortie : métadonnées, lien local et plages réservées refusés, en littéral comme à la résolution (`src/reseau.js:52`) ; mais un simple membre déclare les adresses internes que le serveur joint (consoles, cartes), et le mandataire transmet à la carte le cookie de session de Sentinel (voir REQ-WEB-005) | à corriger : adresses internes posées par un administrateur seulement ; rien de Sentinel ne part vers la carte |
| SEC-CSRF-005 | HIGH | N/A | aucun webhook reçu ni envoyé vers une adresse d’utilisateur : SYNAPSE est joint à l’adresse de la configuration (`src/config.js:51`) |  |
| SEC-CSRF-006 | MEDIUM | N/A | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |  |
| SEC-API-001 | HIGH | FAIL | voir REQ-WEB-006 | à corriger |
| SEC-API-002 | HIGH | FAIL | global par adresse : `src/main.js:90` ; remontées, réveils et alimentation limités (`src/api.js:57`) ; mais voir REQ-WEB-008 (mises à niveau WebSocket, flux) | à corriger |
| SEC-API-003 | MEDIUM | FAIL | tâches listées par 25 (`src/api.js:105`), alertes par 500, parc borné par SENTINEL_MAX_MACHINES ; mais les automatisations ne sont bornées ni en nombre ni en liste | à corriger |
| SEC-API-004 | HIGH | PASS | réponses construites champ par champ : `src/base.js:119`, `src/base.js:209` (charge d’une commande libre jamais rendue) ; résumé du Hub réduit à des comptes (`src/base.js:162`) | essai `test/sentinel.test.js:217` |
| SEC-API-005 | MEDIUM | PASS | 405 avec Allow : `src/api.js:467` ; aucune page de documentation ni de débogage (`test/sentinel.test.js:95`) |  |
| SEC-API-006 | HIGH | N/A | aucun GraphQL : `grep -rniE "graphql\|apollo" src web/*.js socle` → 0 |  |
| SEC-API-007 | MEDIUM | FAIL | un seul formateur d’erreurs : `socle/src/http.js:157` ; mais l’échange d’un code, la première remontée d’un agent, la relève et le lancement d’une automatisation écrivent en plusieurs requêtes sans transaction (`src/taches.js:71`) ; texte brut d’une carte au client (voir SEC-XSS-006) | à corriger |
| SEC-API-008 | MEDIUM | N/A | aucune opération monétaire ni crédit : `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |  |
| SEC-API-009 | HIGH | PASS | pas de RPC implicite : mises à niveau WebSocket revérifiées comme une route (`src/main.js:133`) | essai `test/sentinel.test.js:683` |
| SEC-API-010 | MEDIUM | PASS | `socle/src/http.js:126` ; 64 Kio par défaut, 512 Kio pour l’inventaire d’un agent (`src/api.js:70`) |  |
| SEC-DB-001 | CRITICAL | PASS | voir REQ-DATA-001 |  |
| SEC-DB-002 | HIGH | N/A | SQLite embarqué sans rôle ni identifiant : `src/base.js:27` |  |
| SEC-DB-003 | HIGH | FAIL | aucun trafic réseau vers la base ; secrets de facteurs et d’appareils chiffrés | chiffrement du disque des hôtes : action H7 |
| SEC-DB-004 | MEDIUM | FAIL | secrets TOTP et d’appareils scellés AES-256-GCM, sous-clé par usage : `socle/src/chiffre.js:60` ; jetons d’agents hachés ; mais l’installation seule décrite par le README laisse la clé maîtresse se créer dans le volume, à côté de ce qu’elle scelle (`README.md:125`), et les étapes qui posent le secret Docker n’y figurent pas | à corriger |
| SEC-DB-005 | CRITICAL | PASS | voir SEC-INJ-001 |  |
| SEC-DB-006 | HIGH | FAIL | voir REQ-DATA-003 | action H8 |
| SEC-DB-007 | MEDIUM | PASS | essais sur données fabriquées ; aucun compte par défaut : jeton d’installation exigé (`socle/src/comptes.js:214`) |  |
| SEC-DB-008 | CRITICAL | N/A | le navigateur ne parle jamais à la base : SQLite côté serveur seulement |  |
| SEC-DB-009 | LOW | PASS | `src/base.js:28` ; listes plafonnées | un seul processus, pas de pool nécessaire |
| SEC-DB-010 | LOW | FAIL | export de compte tracé par le socle (`socle/src/portail.js:322`) ; suppression d’une machine, secrets d’appareils et épinglage tracés ; mais voir REQ-DATA-004 (automatisations, accès distants) | à corriger |
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
| SEC-PAY-006 | HIGH | PASS | vérification : 5 par heure par compte et par adresse (`socle/src/portail.js:36`) ; alertes : 30 par heure et par compte (`socle/src/notifications.js:79`) | destinataires et contenus jamais choisis par une requête |
| SEC-PAY-007 | MEDIUM | FAIL | le domaine d’expédition est celui du relais de l’exploitant | SPF, DKIM et DMARC à publier avec le relais : action H2 |
| SEC-PAY-008 | MEDIUM | PASS | aucun mot de passe dans un courriel ; liens uniques, hachés, de 30 minutes (`socle/src/comptes.js:34`) ou 72 heures pour fermer les sessions (`socle/src/notifications.js:27`) | le lien de révocation ne peut que fermer des sessions |
| SEC-NEXT-001 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-002 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-003 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-004 | CRITICAL | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-005 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-006 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-007 | HIGH | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |  |
| SEC-NEXT-008 | MEDIUM | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 ; aucun déploiement Vercel |  |
| SEC-NEXT-009 | MEDIUM | N/A | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 ; aucune bibliothèque de cache client |  |
| SEC-BAAS-001 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-002 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-003 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-004 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-005 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-006 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-007 | MEDIUM | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-008 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-009 | CRITICAL | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-010 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BAAS-011 | HIGH | N/A | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |  |
| SEC-BE-001 | MEDIUM | FAIL | en-têtes posés avant toute route, erreurs comprises : `src/main.js:101` ; mais le mandataire des consoles passe avant eux (`src/main.js:97`) | à corriger avec REQ-WEB-002 |
| SEC-BE-002 | MEDIUM | PASS | corps bornés ; 404 pour l’inconnu ; relais de confiance explicites : `socle/src/http.js:14` ; délais du serveur : `src/main.js:193` | formateur d’erreurs unique : `src/main.js:109` |
| SEC-BE-003 | HIGH | PASS | voir SEC-INJ-004 et SEC-INJ-008 ; aucun import dynamique d’un chemin fourni | noVNC importé depuis un chemin fixe dans le navigateur (`web/app.js:533`) |
| SEC-BE-004 | HIGH | PASS | aucune dépendance npm : `package.json:8` sans dépendances, rien à verrouiller | dépendances Python de l’agent : voir SEC-DEP-001 |
| SEC-BE-005 | CRITICAL | N/A | aucun Django : serveur Node, agent Python sans cadriciel web |  |
| SEC-BE-006 | HIGH | N/A | aucun Flask ni FastAPI : l’agent est un client HTTP, il n’écoute sur aucun port (`grep -rnE "flask\|fastapi\|uvicorn\|http.server" agent/sentinel-agent.py` → 0) |  |
| SEC-BE-007 | HIGH | PASS | agent : ni os.system, ni shell=True, ni pickle, ni yaml, ni eval (`grep -nE "os\.system\|subprocess\.[a-z_]+\(.*shell=True\|pickle\|yaml\.\|eval\(\|exec\(" agent/sentinel-agent.py` → 0) ; JSON seulement | la commande libre passe par un shell fixe, en unique argument (voir SEC-INJ-004) |
| SEC-BE-008 | HIGH | N/A | aucun PHP |  |
| SEC-BE-009 | MEDIUM | PASS | `Dockerfile:20` ; base slim épinglée ; dossier de données en 0700, base et fichiers WAL en 0600 : `src/base.js:26` |  |
| SEC-BE-010 | MEDIUM | PASS | `socle/src/http.js:157` ; sonde publique réduite à « vivant » : `src/api.js:73` | essai `test/sentinel.test.js:105` |
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
| SEC-INFRA-004 | MEDIUM | FAIL | `Dockerfile:6` ; `Dockerfile:20` ; `deploy/compose.hub.yml:14` ; `deploy/compose.hub.yml:17` ; `deploy/compose.hub.yml:19` | crible de l’image (Grype en CI, Trivy au déploiement) à exécuter : actions H3, H14 |
| SEC-INFRA-005 | CRITICAL | N/A | aucun stockage objet : `grep -rniE "s3\|aws\|gcs\|azure\|bucket" src socle/src` → 0 |  |
| SEC-INFRA-006 | HIGH | N/A | aucun nuage : service auto-hébergé, aucune clé IAM |  |
| SEC-INFRA-007 | HIGH | FAIL | permissions minimales, actions épinglées par commit, aucun secret pour les demandes de fusion | protection de branche et revue requise : action H3 |
| SEC-INFRA-008 | MEDIUM | FAIL | empreinte d’image, provenance et SBOM à la publication : `.github/workflows/publish.yml:88` | la publication tourne sur les Actions : action H3 |
| SEC-INFRA-009 | MEDIUM | N/A | aucune infrastructure décrite en code : `find . -name "*.tf" -o -name "Pulumi.yaml"` → 0 fichier |  |
| SEC-DEP-001 | HIGH | FAIL | aucune dépendance npm ; image de base par empreinte (`Dockerfile:6`), noVNC par empreinte ; mais l’agent installe des plages de versions sans empreinte (voir REQ-CI-003) | à corriger |
| SEC-DEP-002 | HIGH | FAIL | aucune dépendance npm ; image passée au crible à chaque publication (`.github/workflows/publish.yml:53`) | alertes Dependabot (pip) et contrôle requis : action H3 |
| SEC-DEP-003 | MEDIUM | PASS | aucune dépendance npm ; l’agent n’en a que deux, maintenues et connues (`psutil`, `requests`) ; noVNC vendu avec sa provenance |  |
| SEC-DEP-004 | MEDIUM | FAIL | plages de versions pour l’agent : voir REQ-CI-003 | à corriger |
| SEC-DEP-005 | MEDIUM | PASS | aucune installation de paquet npm : ni npm install ni script de cycle de vie, dans le dépôt comme dans l’image (`Dockerfile:13` sans installation) | les dépendances de l’agent s’installent sur le poste (voir SEC-DEP-001) |
| SEC-DEP-006 | LOW | FAIL | `.github/workflows/publish.yml:89` | produit par la publication (H3) |
| SEC-DEP-007 | MEDIUM | PASS | voir SEC-XSS-008 |  |
| SEC-DEP-008 | LOW | FAIL | crible de l’image à chaque publication | abonnement aux avis GitHub (npm, pip) : action H3 |
| SEC-LLM-001 | CRITICAL | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-002 | CRITICAL | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-003 | HIGH | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-004 | HIGH | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-005 | CRITICAL | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) ; les actions offertes à l’assistant du Hub passent par le jeton du Hub, qui n’ouvre ni la commande libre ni les comptes (`src/api.js:116`) |  |
| SEC-LLM-006 | HIGH | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-007 | MEDIUM | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LLM-008 | LOW | N/A | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |  |
| SEC-LOG-001 | MEDIUM | FAIL | voir REQ-DATA-004 ; identifiant de requête : `socle/src/requete.js:12` | à corriger |
| SEC-LOG-002 | HIGH | PASS | `socle/src/journal.js:10` ; jamais un jeton ni le contenu d’une commande libre au journal (`src/taches.js:27`) |  |
| SEC-LOG-003 | MEDIUM | FAIL | sortie standard conservée par Docker, hors de portée du service : `deploy/compose.hub.yml:30` | collecteur central hors hôte : action H11 |
| SEC-LOG-004 | MEDIUM | PASS | vigie : échecs de connexion, jetons d’agents refusés, refus d’accès, limites, erreurs (`socle/src/vigie.js:11`) | courriel (H2) pour sortir de l’application |
| SEC-LOG-005 | LOW | FAIL | santé du conteneur : `Dockerfile:24` ; sondes du Hub (`hub.json:95`) | surveillance externe : action H10 |
| SEC-LOG-006 | MEDIUM | PASS | runbook ci-dessous |  |
| SEC-LOG-007 | HIGH | FAIL | fermeture globale des sessions : `socle/src/portail.js:376` ; SOCLE_CLE tournée sans réinscription ; mais aucun moyen de révoquer d’un coup les jetons d’agents (voir REQ-CFG-005) | à corriger |
| SEC-PRIV-001 | MEDIUM | PASS | `web/confidentialite.txt:7` avec durées ; purges automatiques : `src/alertes.js:114`, `src/agents.js:26`, `socle/src/comptes.js:897` |  |
| SEC-PRIV-002 | MEDIUM | PASS | un cookie de session indispensable, documenté ; aucun traceur (`web/confidentialite.txt:68`) |  |
| SEC-PRIV-003 | MEDIUM | PASS | `web/confidentialite.txt:54` nomme chaque destinataire ; lien depuis la page Sécurité (`web/app.js:47`) |  |
| SEC-PRIV-004 | MEDIUM | PASS | export : `socle/src/portail.js:319` complété par Sentinel (`src/base.js:337`) ; effacement en libre-service sous renfort : `socle/src/comptes.js:767`, tâches et acquittements du compte neutralisés (`src/base.js:347`) | essai `test/sentinel.test.js:337` |
| SEC-PRIV-005 | HIGH | FAIL | voir REQ-DATA-002 | action H7 |
| SEC-PRIV-006 | LOW | FAIL | aucun sous-traitant dans le code : cartes, SYNAPSE et MeshCentral sont chez l’exploitant ; le relais SMTP est choisi par lui | si ce relais est un prestataire hors de l’UE : accord de traitement ou relais européen, action H15 |
| SEC-PRIV-007 | MEDIUM | PASS | runbook : notification sous 72 heures |  |
| SEC-PRIV-008 | LOW | PASS | `web/confidentialite.txt:91` | aucune catégorie particulière de données |
| SEC-TEST-001 | MEDIUM | FAIL | `.github/workflows/verification.yml:118` | Actions : H3 |
| SEC-TEST-002 | HIGH | FAIL | voir REQ-CI-001 | actions H3, H4 |
| SEC-TEST-003 | HIGH | FAIL | image : `.github/workflows/publish.yml:50` | actions H3, H14 |
| SEC-TEST-004 | MEDIUM | FAIL | aucun passage DAST encore | ZAP en mode « baseline » contre la VM d’essai : action H14 |
| SEC-TEST-005 | LOW | FAIL | voir REQ-WEB-001 | notation après HTTPS : action H1 |
| SEC-TEST-006 | HIGH | PASS | voir REQ-CI-006 |  |
| SEC-TEST-007 | LOW | UNKNOWN | sondage manuel en cours dans cette passe |  |
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
| SEC-CSRF-005 | aucun webhook reçu ni envoyé vers une adresse d’utilisateur : SYNAPSE est joint à l’adresse de la configuration (`src/config.js:51`) |
| SEC-CSRF-006 | aucune redirection pilotée par paramètre : voir SEC-XSS-007 |
| SEC-API-006 | aucun GraphQL : `grep -rniE "graphql\|apollo" src web/*.js socle` → 0 |
| SEC-API-008 | aucune opération monétaire ni crédit : `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement ; aucun webhook reçu |
| SEC-DB-002 | SQLite embarqué sans rôle ni identifiant : `src/base.js:27` |
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
| SEC-NEXT-001 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-002 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-003 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-004 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-005 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-006 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-007 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 |
| SEC-NEXT-008 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 ; aucun déploiement Vercel |
| SEC-NEXT-009 | Node sans cadriciel : `package.json:5`, aucune dépendance ; `grep -rniE "next/\|nextjs\|use server\|vercel" src web/*.js socle` → 0 ; aucune bibliothèque de cache client |
| SEC-BAAS-001 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-002 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-003 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-004 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-005 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-006 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-007 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-008 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-009 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-010 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BAAS-011 | `grep -rniE "supabase\|firebase\|firestore\|postgrest" src web/*.js socle agent` → 0 ; base SQLite embarquée côté serveur : `src/base.js:27` |
| SEC-BE-005 | aucun Django : serveur Node, agent Python sans cadriciel web |
| SEC-BE-006 | aucun Flask ni FastAPI : l’agent est un client HTTP, il n’écoute sur aucun port (`grep -rnE "flask\|fastapi\|uvicorn\|http.server" agent/sentinel-agent.py` → 0) |
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
| SEC-LLM-001 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-002 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-003 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-004 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-005 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) ; les actions offertes à l’assistant du Hub passent par le jeton du Hub, qui n’ouvre ni la commande libre ni les comptes (`src/api.js:116`) |
| SEC-LLM-006 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-007 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-LLM-008 | Sentinel n’appelle aucun modèle et n’en expose aucun : `grep -rniE "openai\|anthropic\|ollama\|mistral\|completions\|embeddings\|/v1/chat" src web/*.js agent socle/src` → 0 ; les faits racontés à SYNAPSE sont des événements, sa mémoire est un autre service (`src/synapse.js:3`) |
| SEC-TEST-008 | ni argent, ni santé, ni large public : service auto-hébergé pour quelques comptes invités ; `grep -rniE "stripe\|paypal\|checkout\|invoice\|payout\|refund" src web/*.js socle/src socle/web/*.js agent` → 0 : aucun paiement |

## Anonymity (REQ-ANON-001 to -010)
Arbre de travail : 0 occurrence de la liste d’anonymat ; les motifs de l’annexe B.1 y relèvent 1 ligne, un nom de fichier du .gitignore. Historique local complet (10 commits, tous les arbres, tous les messages, auteurs et validateurs) : 0 occurrence de la liste, une seule identité, toutes les dates en UTC, aucune mention d’outil ; le motif « infrastructure personnelle » y relève 4 lignes, toutes des mots qui le contiennent. Aucun binaire image ni document dans tout l’historique. Le dépôt ne contient pas l’historique de la 1.x : l’ancien dépôt publié est hors de portée de ce relevé → H12. Le balayage est fait sur motifs et sur une liste finie : il ne prouve pas l’absence de ce que la liste ne nomme pas.

## Human actions required
Ce qu’aucun agent ne peut faire à la place de l’exploitant. Cette liste bloque la mise en production tant qu’elle n’est pas vide.

| # | Action | Contrôles | Étapes |
|---|---|---|---|
| H1 | Servir Sentinel en HTTPS | REQ-WEB-001, SEC-HDR-001, SEC-INFRA-001, SEC-TEST-005 | Dans le Hub : Relay ou certificat de l’autorité locale pour Sentinel ; déclarer l’adresse du relais dans « Relais de confiance » (SOCLE_PROXYS) ; « Accès sans HTTPS » à Non ; « Adresse publique » en https:// ; vérifier `curl -sI https://<sentinel>/ \| grep -i strict-transport-security` ; noter le résultat de testssl.sh. Installé seul : relais TLS devant le port publié, mêmes variables dans `.env`. Les agents joignent alors Sentinel en HTTPS (SENTINEL_PUBLIC_URL en https://). |
| H2 | Relais SMTP et adresses d’alerte | REQ-AUTH-014, SEC-PAY-007 | Réglages avancés de Sentinel dans le Hub (ou `SOCLE_SMTP_*` dans `.env`) : relais, port, chiffrement, identifiants, expéditeur, adresse publique ; publier SPF, DKIM et DMARC pour le domaine d’expédition ; chaque administrateur ajoute puis confirme son adresse dans Sécurité → Alertes par courriel. |
| H3 | GitHub | REQ-CI-001…005, GOV-003, GOV-005, SEC-INFRA-007/008, SEC-TEST-001…003, SEC-DEP-002/006/008 | Activer les Actions ; Settings → Branches : protéger `main` (pas de poussée forcée, contrôles requis : essais, secrets, identite, anonymat, analyse) ; Code security : Dependabot alerts (npm et pip), secret scanning et push protection, private vulnerability reporting ; 2FA sur le compte et sur chaque console de fournisseur. |
| H4 | Liste d’anonymat | REQ-ANON-003, REQ-CI-004, REQ-CI-001 | Sur le poste : gitleaks installé ; `~/.config/git/denylist.txt`, un terme par ligne ; un crochet global `pre-commit` qui refuse un commit dont le diff contient un terme de la liste, puis `git config --global core.hooksPath ~/.config/git/hooks`. Sur GitHub : secret de dépôt `LISTE_ANONYMAT` avec les mêmes termes. Vérifier : un commit d’essai portant un terme est refusé par le crochet, puis par la vérification. |
| H5 | Brûler les secrets vus pendant le développement | SEC-SECRETS-006 | Dans le Hub, régénérer le jeton de service de Sentinel (HUB_TOKEN) et redéployer ; sur la VM d’essai, tourner SOCLE_CLE une fois (README, « Tourner la clé maîtresse » ; déjà exercé hors de la VM par `outils/exercice-rotation.mjs`) ; si une clé de connexion MeshCentral a servi aux essais, `meshcentral --logintokenkey` pour en tirer une neuve ; changer, sur les cartes et serveurs VNC, tout mot de passe saisi pendant les essais ; réenrôler les agents de la VM après la rotation du jeton du Hub n’est pas nécessaire (leurs jetons sont propres à chacun). |
| H6 | Clés par environnement | REQ-CFG-003, SEC-SECRETS-005, GOV-004 | Un jeton du Hub, une clé maîtresse, une clé Mesh et des comptes de cartes pour la VM d’essai, d’autres pour la production ; aucune carte de production déclarée sur la VM d’essai. |
| H7 | Chiffrement des disques | REQ-DATA-002, SEC-DB-003, SEC-PRIV-005 | LUKS (ou chiffrement du stockage de l’hyperviseur) sur l’hôte qui porte le volume de Sentinel. |
| H8 | Sauvegardes et exercices | REQ-DATA-003, SEC-DB-006, REQ-DATA-005 | Aucune sauvegarde n’est encore possible depuis Sentinel (correction à faire, REQ-DATA-003) ; ensuite : planification quotidienne, copie hors hôte, trente jours de garde, restauration réelle datée ici, et une fois le runbook déroulé. |
| H9 | Hôtes | SEC-INFRA-003 | Pare-feu (seuls les ports publiés), SSH par clé sans root, mises à jour de sécurité automatiques, fail2ban. |
| H10 | Disponibilité vue de l’extérieur | SEC-LOG-005 | Une sonde externe sur `/api/health`, ou décision écrite : service de réseau local seulement, sondes du Hub suffisantes. |
| H11 | Journaux centralisés | SEC-LOG-003 | Transférer les journaux du conteneur (dont les lignes `"journal":"sentinel"`) vers un collecteur hors de l’hôte : pilote de journalisation Docker ou agent. |
| H12 | Publication de la version 2 | REQ-ANON-002 | L’historique de la 1.x n’est pas dans ce dépôt : il reste sur l’ancien dépôt publié, hors de portée de cet audit. Décider de publier ce dépôt à la place (vérifier qu’aucune bifurcation n’existe, supprimer l’ancien dépôt, le recréer vide sous le même nom, pousser), ou de le publier ailleurs ; supprimer aussi, dans les paquets du compte, les images de la 1.x et les journaux d’Actions antérieurs à cette version. |
| H13 | Domaine | REQ-ANON-009, SEC-INFRA-002 | Si Sentinel reçoit un nom public : protection WHOIS, verrou du registraire, 2FA, enregistrement CAA, suppression des enregistrements orphelins. |
| H14 | Crible au déploiement | SEC-INFRA-004, SEC-TEST-003, SEC-TEST-004 | Sur la VM : `trivy image ghcr.io/codexx64/sentinel-rmm:2.0.0` sans CRITICAL ni HIGH corrigeable ; `zap-baseline.py -t http://<vm>:<port>` ; résultats notés ici. |
| H15 | Relais SMTP hors UE | SEC-PRIV-006 | Si le relais SMTP choisi (H2) est un prestataire hors de l’Union européenne : accepter son accord de traitement, ou choisir un relais européen ou auto-hébergé. |
| H16 | Clé maîtresse hors ligne | REQ-DATA-003, SEC-DB-006 | Garder une copie hors ligne de SOCLE_CLE (coffre du Hub, ou `secrets/socle_cle` installé seul), à part des sauvegardes de la base : sans elle, une sauvegarde restaurée ne déchiffre ni les secrets TOTP ni les secrets d’appareils. |

Orthographe du pseudonyme : le manuel nomme l’identité « Codex64 » ; les commits, la licence et le compte GitHub portent la forme du compte, identique dans tout l’historique. Changer maintenant créerait une seconde identité dans le journal git ; à trancher par l’exploitant.

## Secrets inventory
| Secret | Where it lives | Scope | Rotation procedure | Last rotated |
|---|---|---|---|---|
| SOCLE_CLE (tirée par le Hub, ou par l’exploitant installé seul) | coffre du Hub → variable du conteneur ; installé seul : secret Docker `secrets/socle_cle`, hors du volume | scelle les secrets TOTP, les mots de passe VNC et les identifiants Redfish | README, « Tourner la clé maîtresse » : l’actuelle dans « Clé maîtresse remplacée » (SOCLE_CLE_ANCIENNE), une neuve (`openssl rand -base64 32`) dans « Clé maîtresse », redéployer (TOTP et secrets d’appareils rescellés, journal `coffre.tourne`), vider le champ, redéployer | création à l’installation ; procédure exercée le 2026-09-30 (`outils/exercice-rotation.mjs`) |
| SENTINEL_HUB_TOKEN (HUB_TOKEN du Hub, tiré par le Hub) | coffre du Hub → variable | état, tâches sans commande libre, réveil | régénérer dans le Hub, redéployer Sentinel (l’ancien cesse au démarrage) | création à l’installation |
| Jetons d’agents (`sag_…`, tirés par Sentinel) | empreinte SHA-256 dans `machines` ; le clair dans `agent.json` (0600) sur le poste | remontée, relève et résultat des tâches de SA machine | aucune sans supprimer la machine et son historique (à corriger, REQ-CFG-005) | à l’inscription |
| Codes d’inscription (tirés par Sentinel) | en clair dans `enrolements` (à corriger, REQ-CRYPT-006) | un échange contre un jeton d’agent, pendant une heure | aucun : usage unique, expirent seuls | à chaque ajout de poste |
| Mots de passe VNC, identifiants Redfish (posés par un administrateur) | table `machines`, scellés sous SOCLE_CLE | console ou alimentation d’une machine | changer sur la carte, ressaisir dans « Accès distants » (administrateur, renfort) | à la pose |
| SENTINEL_MESH_LOGIN_KEY (tirée par MeshCentral) | coffre du Hub → variable ; installé seul : `.env` (0600) | jetons de connexion au bureau distant | `meshcentral --logintokenkey`, coller dans le Hub, redéployer | à la pose |
| SYNAPSE_JETON (jeton de cerveau dérivé par le Hub) | coffre du Hub → variable | écriture des événements du parc dans SYNAPSE | tourné avec le jeton du Hub de SYNAPSE (HUB_TOKEN_SEED), puis redéploiement de Sentinel | géré par le Hub |
| SOCLE_JETON_INSTALLATION (tiré par le socle) | tiré au premier démarrage, journaux du conteneur | création du premier compte, puis inutile | aucun : invalide dès qu’un compte existe | — |
| SOCLE_SMTP_MOTDEPASSE (émis par le fournisseur de courriel) | coffre du Hub → variable ; installé seul : `.env` | relais des alertes | changer chez le fournisseur de courriel, coller dans le Hub, redéployer | à la mise en service (H2) |
| SOCLE_POIVRE (tiré par l’exploitant, s’il en pose un) | non posé par défaut | poivre HMAC des mots de passe | le nouveau dans `SOCLE_POIVRE`, l’ancien dans `SOCLE_POIVRE_ANCIEN` : chaque mot de passe passe au nouveau à la connexion suivante | — |

## Incident runbook
Détecter : alertes « vigie » dans la page Sécurité des administrateurs (et par courriel, H2) ; refus : `docker logs <sentinel> | grep '"resultat":"refus"'` ; jetons d’agents refusés : `docker logs <sentinel> | grep connexion.jeton`.

```bash
# 1. Fermer toutes les sessions sauf la sienne (renfort demandé)
#    Page Comptes → « Fermer toutes les sessions », ou :
curl -X POST -H 'Content-Type: application/json' -H "X-CSRF: $CSRF" -b "$COOKIE" https://<sentinel>/api/compte/admin/sessions/fermer-tout -d '{}'
# 2. Couper la commande libre sur tout le parc : Hub → Sentinel → Réglages → « Autoriser la commande libre » : Non → Redéployer
#    (SENTINEL_ALLOW_EXEC=0 : plus aucune commande libre créée, lancée ni automatisée)
# 3. Couper le Hub : régénérer son jeton de service (HUB_TOKEN) → Redéployer
# 4. Un agent compromis : supprimer sa machine (administrateur, renfort) ; aucune révocation groupée des jetons d’agents (à corriger)
# 5. Tourner les secrets touchés : voir « Secrets inventory »
# 6. Forcer un nouveau mot de passe : Page Comptes → compte → « Réinitialiser » (le second facteur reste exigé)
# 7. Restaurer : aucune sauvegarde n’est encore produite par Sentinel (à corriger)
# 8. Vérifier la chaîne du journal : Page Comptes → Journal de sécurité (« chaîne intacte »)
```
Qui : l’exploitant de l’instance tient chaque étape ; supports pour révoquer : console du Hub (jeton de service), MeshCentral (clé de connexion), support.github.com pour le dépôt. Communiquer : prévenir les comptes concernés ; si des données personnelles ont pu être lues (comptes, inventaires, sorties de tâches), notifier l’autorité de contrôle sous 72 heures à compter de la découverte (heure de découverte, nature, comptes touchés, mesures prises), et les personnes si le risque est élevé. Revue après incident : cause, chronologie, contrôle qui a manqué, correctif et essai de non-régression.

## Inventory
Routes publiques : `GET /api/health` (`{ok:true}` seulement), `GET /.well-known/security.txt`, `GET /api/compte/etat`, cérémonies de connexion et d’installation du socle (`/api/compte/connexion*`, `/api/compte/installation`, `/api/compte/jeton*`, `/api/compte/courriel/verifier`, `/api/compte/pas-moi/lien`, `/api/compte/deconnexion`), fichiers de `web/` et `socle/web/` (tout segment commençant par un point → 404). Code d’inscription : `GET /api/enroll/config` (échange), `GET /api/enroll/agent.py`, `GET /api/enroll/script`. Jeton d’agent : `POST /api/ingest`, `GET /api/agent/jobs`, `POST /api/agent/jobs/:ref/result`. Jeton du Hub : `GET /api/state`, `GET /api/summary`, `POST /api/machines/:ref/jobs` (sans commande libre), `POST /api/machines/:ref/wake`. Session : 28 routes sous `/api/`, chacune avec son rôle déclaré et vérifié dans le gestionnaire (table figée dans l’essai « autorisation ») ; WebSocket `/vnc/:ref/:idx` (membre) et mandataire des consoles `/console/:ref/:idx/…` (membre), sous l’origine de Sentinel.

Données : `sentinel.db` (comptes, sessions, jetons hachés, journal chaîné, machines et inventaires, logiciels et mises à jour, tâches et leurs sorties, alertes, automatisations, secrets d’appareils scellés — sensibilité : personnelle et opérationnelle), volume `/data` en 0700, base en 0600.

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
| B.1.12 | `git log --all --name-only --format= \| sort -u \| rg -i '\.(png\|jpe?g\|pdf\|mp4\|gif\|webp\|ico)$'` | 0 ligne | aucun binaire image ou document dans tout l’historique : exiftool n’a rien à lire |
| B.1.13 | `git log --all -p` filtré par la liste d’anonymat (hors dépôt), compté | `0` | liste d’anonymat, hors dépôt, sur tout l’historique : arbres, messages, identités |
| B.2.1 | `gitleaks git --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | tout l’historique |
| B.2.2 | `gitleaks dir --no-banner --redact . 2>&1 \| tail -1` | `no leaks found` | arbre de travail |
| B.2.3 | `git grep -nIiE '(api[_-]?key\|secret\|token\|password\|bearer)\s*[=:]\s*["'"'"'][^"'"'"']{8,}' -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 5 lignes | mots de passe de cartes fabriqués pour les essais et l’exercice de rotation, vecteur publié de la RFC 6238 ; aucune vraie clé |
| B.2.4 | `git grep -nI -e '-----BEGIN (RSA\|EC\|OPENSSH\|PGP) PRIVATE' -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 0 ligne |  |
| B.2.5 | `rg -ni 'sk_live\|service_role\|xox[baprs]-\|-----BEGIN' web socle/web` | 0 ligne | aucune étape de construction : le navigateur reçoit web/ et socle/web tels quels |
| B.2.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/.env` | `404` | instance locale ; tout segment caché répond 404 |
| B.3.1 | `rg -n 'dangerouslySetInnerHTML\|innerHTML *=\|outerHTML *=\|document\.write' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 2 lignes | le gabarit du socle : balisage écrit dans le code, valeurs posées en nœuds texte ou attributs (SEC-XSS-001) |
| B.3.2 | `rg -n 'eval\(\|new Function\(\|execSync\|child_process\|os\.system\|subprocess.*shell=True' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 4 lignes | outils et essais seulement : l’exercice de rotation lance Sentinel, les essais lancent bash et openssl ; sans shell, arguments en tableau ; rien dans src/ ni dans l’agent |
| B.3.3 | `rg -n '[^.]\bexec\(' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.4 | `rg -n 'f"SELECT\|"SELECT .*" *\+\|\$\{.*\} *FROM\|\.raw\(\|query\(.*\+ *req\.' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.5 | `rg -n 'Math\.random\|uuidv1\|new Random\(\)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.3.6 | `rg -n 'verify *= *False\|rejectUnauthorized: *false\|InsecureSkipVerify' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 6 lignes | deux emplois : la sonde de confiance au premier usage (`src/tls.js`, justifiée par ses trois garanties, voir SEC-CSRF-004) et la session épinglée de l’agent, qui désactive la vérification par autorité pour comparer l’empreinte (`agent/sentinel-agent.py`, à corriger) ; quatre commentaires |
| B.3.7 | `rg -n 'jwt\.decode\(\|algorithms: *\[.*none\|verify: *false' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.4.1 | `curl -sI http://localhost:18142/ \| rg -i 'content-security\|x-content-type\|referrer-policy\|permissions-policy\|x-frame\|cross-origin' \| wc -l` | `7` | CSP à nonce sans joker, nosniff, no-referrer, DENY, COOP et CORP same-origin, Permissions-Policy ; HSTS dès que la requête est chiffrée (H1) |
| B.4.2 | `curl -sI http://localhost:18142/ \| rg -i '^(server\|x-powered-by\|x-aspnet\|x-generator)'` | 0 ligne |  |
| B.4.3 | `curl -sI -H 'Origin: https://evil.example' http://localhost:18142/api/state \| rg -i access-control` | 0 ligne | aucun CORS : même origine seulement |
| B.4.4 | `curl -sI 'http://localhost:18142/login?next=https://evil.example' \| rg -i '^location'` | 0 ligne | aucune redirection : 404 |
| B.4.5 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/.git/config` | `404` |  |
| B.4.6 | `curl -s -o /dev/null -w '%{http_code}' http://localhost:18142/console/AAAAAAAAAAAAAAAA/0/` | `401` | le mandataire des consoles répond sous l’origine de Sentinel (à corriger, REQ-WEB-002) |
| B.4.7 | `curl -s -o /dev/null -w '%{http_code}' 'http://localhost:18142/api/enroll/config?code=AAAAAAAAAAAAAAAAAAAAAA'` | `401` | l’échange d’un code est un GET (à corriger, SEC-CSRF-003) |
| B.4.8 | `for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:18142/api/compte/connexion -H 'Content-Type: application/json' -H 'Origin: http://localhost:18142' -d '{"identifiant":"quelquun","motDePasse":"mauvais mot de passe"}'; done` | `401 401 401 428` | trois échecs, puis preuve de travail exigée (428) ; 429 et verrouillage au-delà |
| B.4.9 | `for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:18142/api/ingest -H 'Content-Type: application/json' -H 'X-Agent-Token: sag_jeton_invente_pour_le_balayage' -d '{"hostname":"poste-x"}'; done \| tr ' ' '\n' \| sort \| uniq -c \| sed 's/^ *//' \| tr '\n' ' '` | `40 401` | un jeton d’agent inventé : 401 à chaque fois, aucun plafond d’échecs (à corriger, REQ-AUTH-010) |
