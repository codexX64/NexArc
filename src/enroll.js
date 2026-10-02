// Inscription d'un poste : scripts prêts à lancer qui installent l'agent (Python
// et son environnement virtuel), la commande d'une ligne qui les télécharge, et
// un installateur à télécharger par système (exécutable Windows, archive macOS
// avec un fichier à double-cliquer, script Linux) qui lance le même script.
import zlib from 'node:zlib';
//
// Le code d'inscription (128 bits, à usage unique, lié au site) est le seul secret
// transporté ; l'agent l'échange lui-même contre SON jeton, qu'il range dans un
// fichier 0600. Aucun jeton durable ne traverse la ligne de commande, la table
// des processus, ni un fichier d'unité systemd.
//
// Ces scripts s'exécutent en root / SYSTEM : chaque valeur qui y entre est
// d'abord validée par motif (aucune apostrophe, guillemet, dollar, accent grave
// ni barre oblique inverse ne passe), puis placée entre apostrophes, où ni bash
// ni PowerShell n'interprètent rien.
const CODE_INSCRIPTION = /^[A-Za-z0-9_-]{22}$/;
const LIBELLE = /^[\p{L}\p{N} ._()-]{0,60}$/u;
const BASE = /^https?:\/\/(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;

// Refuse ce qui ne peut pas entrer tel quel dans un script (renvoie un message).
// Sans code (avant qu'il soit tiré), seuls l'adresse, le site et le nom comptent.
export function controler(base, { code = null, site = '', nom = '' } = {}) {
  if (!BASE.test(base)) return 'Adresse de Sentinel inutilisable dans un script : pose SENTINEL_PUBLIC_URL.';
  if (code !== null && !CODE_INSCRIPTION.test(code)) return 'Code d\'inscription invalide.';
  if (!LIBELLE.test(site) || !LIBELLE.test(nom)) return 'Site ou nom : lettres, chiffres, espace, point, tiret, parenthèses (60 au plus).';
  return null;
}

const sansBarreFinale = b => b.replace(/\/+$/, '');

function scriptLinux(base, code, { site = 'Agents', nom = '', relais = false } = {}) {
  return `#!/usr/bin/env bash
# Sentinel — installation de l'agent (Linux, systemd). Lance avec sudo.
set -euo pipefail
URL='${sansBarreFinale(base)}'; CODE='${code}'; SITE='${site}'; NOM='${nom}'; RELAIS='${relais ? '1' : '0'}'
DIR=/opt/sentinel-agent
[ "$(id -u)" -eq 0 ] || { echo "Lance ce script avec sudo."; exit 1; }
echo "→ Dépendances"
if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3 python3-venv curl
elif command -v dnf >/dev/null; then dnf install -y -q python3 curl
elif command -v pacman >/dev/null; then pacman -Sy --noconfirm python curl; fi
mkdir -p "$DIR"; chmod 700 "$DIR"
curl -fsSL "$URL/api/enroll/agent.py?code=$CODE" -o "$DIR/sentinel-agent.py"
curl -fsSL "$URL/api/enroll/requirements.txt?code=$CODE" -o "$DIR/requirements.txt"
python3 -m venv "$DIR/venv"
# Versions fixées, chaque paquet vérifié par son empreinte avant installation.
"$DIR/venv/bin/pip" install -q --require-hashes --prefer-binary -r "$DIR/requirements.txt"
# L'agent échange le code, range son jeton en 0600, s'installe en service.
SENTINEL_URL="$URL" SENTINEL_ENROLL_CODE="$CODE" SENTINEL_SITE="$SITE" SENTINEL_NAME="$NOM" SENTINEL_RELAY="$RELAIS" \\
  "$DIR/venv/bin/python" "$DIR/sentinel-agent.py" --enroller
echo "✓ Terminé — le poste doit apparaître dans la console sous une minute."
`;
}

function scriptMacos(base, code, { site = 'Agents', nom = '', relais = false } = {}) {
  return `#!/usr/bin/env bash
# Sentinel — installation de l'agent (macOS, launchd). Lance avec sudo.
set -euo pipefail
URL='${sansBarreFinale(base)}'; CODE='${code}'; SITE='${site}'; NOM='${nom}'; RELAIS='${relais ? '1' : '0'}'
DIR=/usr/local/sentinel-agent
[ "$(id -u)" -eq 0 ] || { echo "Lance ce script avec sudo."; exit 1; }
command -v python3 >/dev/null || { echo "python3 requis (xcode-select --install)"; exit 1; }
mkdir -p "$DIR"; chmod 700 "$DIR"
curl -fsSL "$URL/api/enroll/agent.py?code=$CODE" -o "$DIR/sentinel-agent.py"
curl -fsSL "$URL/api/enroll/requirements.txt?code=$CODE" -o "$DIR/requirements.txt"
python3 -m venv "$DIR/venv"
# Versions fixées, chaque paquet vérifié par son empreinte avant installation.
"$DIR/venv/bin/pip" install -q --require-hashes --prefer-binary -r "$DIR/requirements.txt"
SENTINEL_URL="$URL" SENTINEL_ENROLL_CODE="$CODE" SENTINEL_SITE="$SITE" SENTINEL_NAME="$NOM" SENTINEL_RELAY="$RELAIS" \\
  "$DIR/venv/bin/python" "$DIR/sentinel-agent.py" --enroller
echo "✓ Terminé — le poste doit apparaître dans la console sous une minute."
`;
}

// Windows : même chemin que la 1.1.0 — Python trouvé (ou installé par winget),
// environnement virtuel dans ProgramData, puis l'agent s'enrôle et se pose en
// tâche planifiée SYSTEM au démarrage. Une commande native qui échoue ne lève
// rien en PowerShell : chaque étape vérifie $LASTEXITCODE.
function scriptWindows(base, code, { site = 'Agents', nom = '', relais = false } = {}) {
  return `# Sentinel - installation de l'agent (Windows). PowerShell en administrateur :
#   powershell -ExecutionPolicy Bypass -File .\\installer-sentinel.ps1
$ErrorActionPreference = "Stop"
$Url = '${sansBarreFinale(base)}'; $Code = '${code}'; $Site = '${site}'; $Nom = '${nom}'; $Relais = '${relais ? '1' : '0'}'
$Dir = "$env:ProgramData\\SentinelAgent"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Relance PowerShell en tant qu'administrateur."; exit 1
}
function Find-Python {
  # « python » peut n'être que le raccourci du Microsoft Store, qui ne lance rien.
  foreach ($c in @("py", "python")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if (-not $cmd -or $cmd.Source -like "*WindowsApps*") { continue }
    try {
      $v = if ($c -eq "py") { & $cmd.Source -3 --version 2>$null } else { & $cmd.Source --version 2>$null }
      if ($v -match "Python 3") { return $cmd.Source }
    } catch { continue }
  }
  foreach ($p in @("$env:ProgramFiles\\Python312\\python.exe", "$env:ProgramFiles\\Python311\\python.exe",
                   "$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe", "$env:LOCALAPPDATA\\Programs\\Python\\Python311\\python.exe")) {
    if (Test-Path $p) { return $p }
  }
  return $null
}
Write-Host "-> Python"
$Py = Find-Python
if (-not $Py) {
  winget install -e --id Python.Python.3.12 --silent --scope machine --accept-source-agreements --accept-package-agreements
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $Py = Find-Python
}
if (-not $Py) { Write-Error "Python 3 introuvable. Installe-le puis relance ce script."; exit 1 }
$PyArgs = if ((Split-Path $Py -Leaf) -eq "py.exe") { @("-3") } else { @() }
Unregister-ScheduledTask -TaskName "SentinelAgent" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "-> Agent dans $Dir"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
# Le jeton de l'agent sera rangé ici : SYSTEM et les administrateurs seuls, sans
# la lecture pour tous que ProgramData transmet par héritage.
icacls $Dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Droits du dossier de l'agent non posés."; exit 1 }
Invoke-WebRequest -Uri "$Url/api/enroll/agent.py?code=$Code" -OutFile "$Dir\\sentinel-agent.py" -UseBasicParsing
Invoke-WebRequest -Uri "$Url/api/enroll/requirements.txt?code=$Code" -OutFile "$Dir\\requirements.txt" -UseBasicParsing
& $Py @PyArgs -m venv "$Dir\\venv"
if ($LASTEXITCODE -ne 0) { Write-Error "Environnement virtuel non créé."; exit 1 }
# Versions fixées, chaque paquet vérifié par son empreinte avant installation.
& "$Dir\\venv\\Scripts\\python.exe" -m pip install -q --require-hashes --prefer-binary -r "$Dir\\requirements.txt"
if ($LASTEXITCODE -ne 0) { Write-Error "Dépendances de l'agent non installées."; exit 1 }
Write-Host "-> Inscription et tâche planifiée"
$env:SENTINEL_URL = $Url; $env:SENTINEL_ENROLL_CODE = $Code; $env:SENTINEL_SITE = $Site; $env:SENTINEL_NAME = $Nom; $env:SENTINEL_RELAY = $Relais
& "$Dir\\venv\\Scripts\\python.exe" "$Dir\\sentinel-agent.py" --enroller
if ($LASTEXITCODE -ne 0) { Write-Error "Inscription refusée ou console injoignable : rien n'a été posé en service."; exit 1 }
Remove-Item Env:SENTINEL_ENROLL_CODE
Write-Host "OK - le poste doit apparaitre dans la console sous une minute."
`;
}

export const BUILDERS = {
  linux: [scriptLinux, 'installer-sentinel.sh', 'text/x-shellscript'],
  macos: [scriptMacos, 'installer-sentinel.command', 'text/x-shellscript'],
  windows: [scriptWindows, 'installer-sentinel.ps1', 'text/plain'],
};

// L'adresse du script d'installation, code compris. Ses valeurs ont passé
// controler() : rien n'y sort des apostrophes de bash ou de PowerShell.
export function urlScript(os, base, code, { site = '', nom = '', relais = false } = {}) {
  let url = `${sansBarreFinale(base)}/api/enroll/script?os=${os}&code=${code}`;
  if (site) url += `&site=${encodeURIComponent(site)}`;
  if (nom) url += `&name=${encodeURIComponent(nom)}`;
  if (relais) url += '&relais=1';
  return url;
}

export function uneLigne(os, base, code, options = {}) {
  const url = urlScript(os, base, code, options);
  // TLS 1.2 au moins, même sous un .NET ancien qui proposerait encore TLS 1.0.
  if (os === 'windows') return `powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm '${url}' | iex"`;
  return `curl -fsSL '${url}' | sudo bash`;
}

// Windows : l'exécutable générique (agent/installateur-windows), suivi de
// l'adresse du script, de sa longueur et d'une marque. L'exécutable relit
// cette fin, revérifie l'adresse et lance le script avec élévation.
export const MARQUE_WINDOWS = Buffer.from('SNTLINS1', 'latin1');
export function installateurWindows(executable, url) {
  const adresse = Buffer.from(url, 'utf8');
  const longueur = Buffer.alloc(4);
  longueur.writeUInt32LE(adresse.length);
  return Buffer.concat([executable, adresse, longueur, MARQUE_WINDOWS]);
}

// macOS : une archive zip qui garde le droit d'exécution du fichier
// « .command » (un fichier téléchargé seul le perd, et le Finder refuse alors
// de l'ouvrir). Le fichier relance le script dans le Terminal, sous sudo.
export function installateurMacos(script) {
  const commande = `#!/bin/bash
# Sentinel - installation de l'agent sur ce Mac. Double-clique : le Terminal
# s'ouvre et demande le mot de passe d'un administrateur.
cd "$(dirname "$0")"
TMP="$(mktemp -t sentinel-installation)"
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<'SENTINEL_FIN_DU_SCRIPT'
${script}SENTINEL_FIN_DU_SCRIPT
sudo /bin/bash "$TMP"
echo
read -r -p "Appuie sur Entrée pour fermer." _
`;
  return zipUnFichier('Installer Sentinel.command', Buffer.from(commande, 'utf8'), 0o755);
}

// Une archive zip d'un seul fichier, stocké sans compression (la méthode 0 que
// tout outil lit), avec ses droits Unix dans les attributs externes.
function zipUnFichier(nom, donnees, mode) {
  const n = Buffer.from(nom, 'utf8');
  const crc = zlib.crc32(donnees);
  // 1er janvier 2026, 00:00 : l'archive ne change pas d'un téléchargement à l'autre.
  const heure = 0, date = ((2026 - 1980) << 9) | (1 << 5) | 1;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(0, 8);
  local.writeUInt16LE(heure, 10); local.writeUInt16LE(date, 12); local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(donnees.length, 18); local.writeUInt32LE(donnees.length, 22); local.writeUInt16LE(n.length, 26); local.writeUInt16LE(0, 28);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE((3 << 8) | 20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0, 10); central.writeUInt16LE(heure, 12); central.writeUInt16LE(date, 14); central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(donnees.length, 20); central.writeUInt32LE(donnees.length, 24); central.writeUInt16LE(n.length, 28);
  central.writeUInt16LE(0, 30); central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36);
  central.writeUInt32LE(((0o100000 | mode) << 16) >>> 0, 38); central.writeUInt32LE(0, 42);
  const debutCentral = local.length + n.length + donnees.length;
  const fin = Buffer.alloc(22);
  fin.writeUInt32LE(0x06054b50, 0); fin.writeUInt16LE(1, 8); fin.writeUInt16LE(1, 10);
  fin.writeUInt32LE(central.length + n.length, 12); fin.writeUInt32LE(debutCentral, 16);
  return Buffer.concat([local, n, donnees, central, n, fin]);
}

export const INSTALLATEURS = {
  windows: { fichier: 'installer-sentinel.exe', media: 'application/vnd.microsoft.portable-executable' },
  macos: { fichier: 'installer-sentinel-macos.zip', media: 'application/zip' },
  linux: { fichier: 'installer-sentinel.sh', media: 'text/x-shellscript' },
};
