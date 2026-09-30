#!/usr/bin/env python3
"""Agent de supervision Sentinel.

Posé sur un poste, il remonte son état (CPU/RAM/disque, posture, inventaire,
logiciels, mises à jour) et relève ses tâches. Durci par rapport à la 1.x :

  - TLS TOUJOURS vérifié : autorité (système, ou fichier SENTINEL_CA), ou
    empreinte SHA-256 épinglée (SENTINEL_PIN). La vérification par autorité ne
    cède la place qu'à une empreinte bien formée, jamais à rien.
  - La posture remontée est constatée, jamais supposée : antivirus, pare-feu et
    chiffrement sont lus sur le poste ; ce qui ne peut pas l'être part
    « inconnu », et le serveur n'en tire aucune alerte.
  - Le jeton est PROPRE à cet agent : obtenu à l'inscription contre un code à
    usage unique, rangé avec l'URL dans un fichier 0600. Il ne traîne ni dans
    la table des processus, ni dans un fichier d'unité.
  - Aucun shell=True : chaque commande est un binaire fixe avec ses arguments en
    liste ; les types de tâches sont une liste fermée, identique au serveur ;
    les noms de paquets sont validés ; délais et tailles de sortie bornés.

Installation : le script d'inscription lance « --enroller » (échange du code,
écriture du jeton en 0600, pose du service). Ensuite le service lance l'agent
sans argument : il lit sa configuration et remonte.
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

IS_WIN = sys.platform.startswith('win')
IS_MAC = sys.platform == 'darwin'
IS_LINUX = not IS_WIN and not IS_MAC

try:
    import psutil
except ImportError:
    sys.exit('psutil requis :  pip install psutil requests')
try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    sys.exit('requests requis :  pip install psutil requests')

KINDS = {'cmd', 'install', 'uninstall', 'inventory', 'update', 'wol'}
PAQUET = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,120}$')
SORTIE_MAX = 100_000
FP_SHA256 = re.compile(r'^[0-9a-f]{64}$')
# Sorties des outils de posture en anglais : elles sont analysées, pas affichées.
ENV_C = dict(os.environ, LC_ALL='C', LANG='C')
CONFIG_DIR = (os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'SentinelAgent') if IS_WIN
              else '/usr/local/sentinel-agent' if IS_MAC else '/opt/sentinel-agent')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'agent.json')


# ───────────────────────── TLS : autorité ou empreinte épinglée ─────────────────────────
def normaliser_empreinte(texte):
    """'sha256:AA:BB…' → 'aabb…' (64 hexa), ou ValueError : une empreinte mal
    formée ne doit jamais aboutir à une session sans vérification."""
    brut = re.sub(r'^\s*sha-?256\s*[:=]?\s*', '', str(texte or ''), flags=re.I)
    fp = re.sub(r'[^0-9a-fA-F]', '', brut).lower()
    if not FP_SHA256.match(fp):
        raise ValueError('empreinte SHA-256 invalide (64 caractères hexadécimaux attendus)')
    return fp


class EpingleAdapter(HTTPAdapter):
    """Exige que le certificat présenté ait exactement l'empreinte SHA-256
    épinglée (serveur au certificat auto-signé, confiance au premier usage).
    Sans correspondance, la connexion échoue avant le moindre octet envoyé."""

    def __init__(self, empreinte, **kw):
        self._fp = normaliser_empreinte(empreinte)
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw['assert_fingerprint'] = self._fp
        super().init_poolmanager(*a, **kw)


class SessionAgent(requests.Session):
    """requests laisse REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE, s'ils existent dans
    l'environnement, remplacer session.verify à chaque requête : une empreinte
    épinglée ou un SENTINEL_CA seraient alors ignorés sans bruit. Ici le choix
    configuré l'emporte ; seul le chemin « autorités du système » accepte le
    lot désigné par l'environnement (c'est encore une vérification par autorité)."""

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        reglages = super().merge_environment_settings(url, proxies, stream, verify, cert)
        if verify is None and self.verify is not True:
            reglages['verify'] = self.verify
        return reglages


def session_http(url, pin=None, ca=None):
    """Deux chemins, et seulement deux :
      - empreinte épinglée : la vérification par autorité est remplacée par la
        comparaison de l'empreinte (urllib3 n'accepte assert_fingerprint
        qu'avec verify=False) — ce n'est pas une vérification en moins, c'est
        une vérification plus stricte : un seul certificat passe ;
      - sinon : vérification par autorité, toujours — le fichier SENTINEL_CA
        s'il est donné, les autorités du système autrement."""
    s = SessionAgent()
    if pin:
        s.mount('https://', EpingleAdapter(pin))
        s.verify = False
    else:
        s.verify = ca if ca else True
    return s


# ───────────────────────── collecte ─────────────────────────
def oskind():
    s = platform.system().lower()
    if s == 'windows':
        return 'win'
    if s == 'darwin':
        return 'mac'
    if s == 'linux':
        try:
            racine = os.geteuid() == 0
        except AttributeError:
            racine = False
        return 'srv' if not os.environ.get('DISPLAY') and racine else 'lin'
    return 'lin'


def os_label():
    s = platform.system()
    if s == 'Windows':
        return 'Windows ' + platform.release()
    if s == 'Darwin':
        return 'macOS ' + platform.mac_ver()[0]
    return '%s %s' % (s, platform.release())


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 1))  # adresse de documentation : ne route pas, révèle l'IP locale
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def disk_percent():
    try:
        return int(psutil.disk_usage('C:\\' if IS_WIN else '/').percent)
    except OSError:
        return 0


def run(cmd, timeout=25, env=None):
    """Exécute une commande — binaire fixe, arguments en LISTE, jamais shell=True.
    Renvoie (rc, sortie) et ne lève jamais."""
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout, errors='replace', env=env)
        return r.returncode, ((r.stdout or '') + (r.stderr or ''))[:SORTIE_MAX]
    except subprocess.TimeoutExpired:
        return 124, '[délai dépassé]'
    except (OSError, ValueError) as e:
        return 1, str(e)


# ───────────────────────── posture : lue, jamais supposée ─────────────────────────
# Chaque lecteur rend un état du vocabulaire que le serveur connaît, ou
# « inconnu » quand l'outil manque ou répond de travers. Les analyseurs sont
# des fonctions pures, essayées sur des sorties réelles dans test_agent.py.
POWERSHELL = ['powershell', '-NoProfile', '-NonInteractive', '-Command']


def av_securitycenter(etats):
    """productState des antivirus que Windows déclare (SecurityCenter2) : bit
    0x1000 = moteur actif, bit 0x10 = signatures périmées."""
    if not etats:
        return 'absent'
    actifs = [e for e in etats if (e >> 12) & 0x1]
    if not actifs:
        return 'inactif'
    return 'à jour' if any(not (e & 0x10) for e in actifs) else 'obsolète'


def av_defender(etat):
    """Get-MpComputerStatus (Windows Server, sans centre de sécurité)."""
    if not etat.get('AntivirusEnabled') or not etat.get('RealTimeProtectionEnabled'):
        return 'inactif'
    age = etat.get('AntivirusSignatureAge')
    return 'obsolète' if isinstance(age, int) and age > 7 else 'à jour'


def antivirus_state():
    try:
        if IS_WIN:
            rc, out = run(POWERSHELL + ['(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct '
                                        '-ErrorAction Stop | ForEach-Object { $_.productState }) -join ","'], 30)
            if rc == 0:
                return av_securitycenter([int(x) for x in out.strip().split(',') if x.strip().isdigit()])
            rc, out = run(POWERSHELL + ['Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,'
                                        'RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json'], 30)
            return av_defender(json.loads(out)) if rc == 0 else 'inconnu'
        if IS_MAC:
            # XProtect fait partie du système et ne se désactive pas.
            for chemin in ('/Library/Apple/System/Library/CoreServices/XProtect.bundle',
                           '/System/Library/CoreServices/XProtect.bundle'):
                if os.path.isdir(chemin):
                    return 'actif'
            return 'inconnu'
        # Linux : ClamAV est le seul moteur reconnu ; son absence est dite telle.
        rc, out = run(['systemctl', 'is-active', 'clamav-daemon', 'clamd@scan'], 8, env=ENV_C)
        if 'active' in out.split():
            return 'actif'
        return 'inactif' if (shutil.which('clamscan') or shutil.which('clamdscan')) else 'absent'
    except (OSError, ValueError):
        return 'inconnu'


def pare_feu_windows(sortie):
    """(Get-NetFirewallProfile).Enabled joint par des virgules : 'True,True,True'."""
    vals = [v.strip().lower() for v in sortie.strip().split(',') if v.strip()]
    if not vals or any(v not in ('true', 'false') for v in vals):
        return 'inconnu'
    return 'actif' if all(v == 'true' for v in vals) else 'inactif'


def pare_feu_macos(sortie):
    s = sortie.lower()
    if re.search(r'state = [12]\b', s) or 'is enabled' in s:
        return 'actif'
    if 'state = 0' in s or 'is disabled' in s:
        return 'inactif'
    return 'inconnu'


def nft_filtre_entree(sortie):
    """Vrai si une chaîne accrochée à l'entrée filtre quelque chose : politique
    drop, ou au moins une règle."""
    for bloc in re.findall(r'chain [^{]+\{(.*?)\n\s*\}', sortie, re.S):
        if 'hook input' not in bloc:
            continue
        if 'policy drop' in bloc:
            return True
        regles = [l.strip() for l in bloc.splitlines() if l.strip() and not l.strip().startswith('type ')]
        if regles:
            return True
    return False


def iptables_filtre_entree(sortie):
    return bool(re.search(r'^-P INPUT (DROP|REJECT)', sortie, re.M) or re.search(r'^-A INPUT ', sortie, re.M))


def firewall_state():
    try:
        if IS_WIN:
            rc, out = run(POWERSHELL + ['(Get-NetFirewallProfile -ErrorAction Stop).Enabled -join ","'], 30)
            return pare_feu_windows(out) if rc == 0 else 'inconnu'
        if IS_MAC:
            rc, out = run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], 8, env=ENV_C)
            return pare_feu_macos(out) if rc == 0 else 'inconnu'
        lu = False
        if shutil.which('firewall-cmd'):
            lu = True
            if run(['firewall-cmd', '--state'], 8, env=ENV_C)[1].strip() == 'running':
                return 'actif'
        if shutil.which('ufw'):
            rc, out = run(['ufw', 'status'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if re.search(r'^Status:\s*active', out, re.M):
                    return 'actif'
        if shutil.which('nft'):
            rc, out = run(['nft', 'list', 'ruleset'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if nft_filtre_entree(out):
                    return 'actif'
        if shutil.which('iptables'):
            rc, out = run(['iptables', '-S', 'INPUT'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if iptables_filtre_entree(out):
                    return 'actif'
        return 'inactif' if lu else 'inconnu'
    except (OSError, ValueError):
        return 'inconnu'


def encryption_state():
    try:
        if IS_WIN:
            # ProtectionStatus est une énumération (On/Off), pas un texte traduit.
            rc, out = run(POWERSHELL + ['(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus'], 30)
            if rc != 0:
                return 'inconnu'
            return 'BitLocker actif' if out.strip() == 'On' else 'non chiffré'
        if IS_MAC:
            rc, out = run(['fdesetup', 'status'], 8, env=ENV_C)
            if rc != 0:
                return 'inconnu'
            return 'FileVault actif' if 'filevault is on' in out.lower() else 'non chiffré'
        rc, out = run(['lsblk', '-n', '-o', 'TYPE'], 8, env=ENV_C)
        if rc != 0:
            return 'inconnu'
        return 'LUKS actif' if 'crypt' in out.split() else 'non chiffré'
    except (OSError, ValueError):
        return 'inconnu'


# Nombre de mises à jour en attente au dernier constat : la liste complète
# n'est relevée qu'un rapport sur douze, le compte part à chaque rapport.
_MAJ_EN_ATTENTE = [0]


def collect(site, name='', relais=False):
    p = {
        'hostname': (name or socket.gethostname())[:80],
        'ip': local_ip(), 'os': os_label(), 'oskind': oskind(),
        'role': 'relais' if relais else 'poste', 'site': site,
        'cpu': int(psutil.cpu_percent(interval=1)), 'ram': int(psutil.virtual_memory().percent),
        'disk': disk_percent(), 'av': antivirus_state(), 'fw': firewall_state(), 'enc': encryption_state(),
        'patch': min(_MAJ_EN_ATTENTE[0], 999),
    }
    return p


def collect_inventory():
    inv = {
        'hostname': socket.gethostname(), 'os': os_label(), 'arch': platform.machine(),
        'kernel': platform.release(), 'cpu_cores': psutil.cpu_count(logical=False) or psutil.cpu_count() or 0,
        'cpu_threads': psutil.cpu_count() or 0, 'ram_total_gb': round(psutil.virtual_memory().total / 1024 ** 3, 1),
        'cpu_model': platform.processor() or '',
    }
    try:
        if IS_LINUX:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if line.lower().startswith('model name'):
                        inv['cpu_model'] = line.split(':', 1)[1].strip()
                        break
            for cle, chemin in (('vendor', 'sys_vendor'), ('model', 'product_name'), ('serial', 'product_serial')):
                try:
                    with open('/sys/class/dmi/id/' + chemin) as f:
                        inv[cle] = f.read().strip()
                except OSError:
                    pass
        elif IS_MAC:
            rc, out = run(['sysctl', '-n', 'machdep.cpu.brand_string'])
            if rc == 0:
                inv['cpu_model'] = out.strip()
            rc, out = run(['sysctl', '-n', 'hw.model'])
            if rc == 0:
                inv['model'] = out.strip()
            inv['vendor'] = 'Apple'
        elif IS_WIN:
            rc, out = run(['powershell', '-NoProfile', '-Command',
                           '$c=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS;'
                           '"$($c.Manufacturer)|$($c.Model)|$($b.SerialNumber)"'])
            if rc == 0 and '|' in out:
                v, m, s = (out.strip().split('|') + ['', '', ''])[:3]
                inv['vendor'], inv['model'], inv['serial'] = v, m, s
    except Exception:  # noqa: BLE001 — inventaire au mieux
        pass

    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({'device': part.device, 'mount': part.mountpoint, 'fs': part.fstype,
                          'total_gb': round(u.total / 1024 ** 3, 1), 'used_pct': int(u.percent)})
        except OSError:
            continue
    inv['disks'] = disks[:12]
    nics = []
    try:
        for nom, items in psutil.net_if_addrs().items():
            ip4 = next((a.address for a in items if a.family == socket.AF_INET), '')
            mac = next((a.address for a in items if getattr(a, 'family', None) == getattr(psutil, 'AF_LINK', -1)), '')
            if ip4 and not ip4.startswith('127.'):
                nics.append({'name': nom, 'ip': ip4, 'mac': mac})
    except (OSError, AttributeError):
        pass  # interfaces illisibles (droits, plateforme) : l'inventaire part sans elles
    inv['nics'] = nics[:8]
    return inv


def collect_software():
    apps = []
    try:
        if IS_WIN:
            import winreg
            racines = [(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                       (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
                       (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')]
            vus = set()
            for hive, chemin in racines:
                try:
                    key = winreg.OpenKey(hive, chemin)
                except OSError:
                    continue
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        nom = winreg.QueryValueEx(sub, 'DisplayName')[0]
                        if not nom or nom in vus:
                            continue
                        vus.add(nom)

                        def val(k):
                            try:
                                return str(winreg.QueryValueEx(sub, k)[0])
                            except OSError:
                                return ''
                        apps.append({'name': nom, 'version': val('DisplayVersion'), 'publisher': val('Publisher'), 'source': 'windows'})
                    except OSError:
                        continue
        elif IS_MAC:
            try:
                for nom in os.listdir('/Applications'):
                    if nom.endswith('.app'):
                        apps.append({'name': nom[:-4], 'version': '', 'publisher': '', 'source': 'app'})
            except OSError:
                pass
            rc, out = run(['brew', 'list', '--versions'], 25)
            if rc == 0:
                for line in out.splitlines():
                    p = line.split()
                    if p:
                        apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': '', 'source': 'brew'})
        else:
            rc, out = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Maintainer}\n'], 25)
            if rc == 0 and out.strip():
                for line in out.splitlines():
                    p = line.split('\t')
                    if p and p[0]:
                        apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': (p[2] if len(p) > 2 else '')[:60], 'source': 'dpkg'})
            else:
                rc, out = run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}\n'], 25)
                if rc == 0:
                    for line in out.splitlines():
                        p = line.split('\t')
                        if p and p[0]:
                            apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': '', 'source': 'rpm'})
    except Exception as e:  # noqa: BLE001 — un registre ou un gestionnaire en panne ne doit pas taire le reste
        print('[sentinel-agent] inventaire logiciel partiel :', e)
    apps.sort(key=lambda a: a['name'].lower())
    return apps[:3000]


def collect_updates():
    ups = []
    try:
        if IS_WIN:
            rc, out = run(['winget', 'upgrade', '--include-unknown'], 90)
            if rc == 0:
                for line in out.splitlines():
                    parts = [c for c in line.split('  ') if c.strip()]
                    if len(parts) >= 4 and not line.lower().startswith(('name', '---')):
                        ups.append({'name': parts[0].strip(), 'current': parts[2].strip(), 'available': parts[3].strip(), 'security': False, 'kind': 'Application'})
            ps = ('$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0");'
                  '$r.Updates | ForEach-Object { $_.Title + "|" + (($_.Categories | ForEach-Object {$_.Name}) -join ",") }')
            rc, out = run(['powershell', '-NoProfile', '-Command', ps], 120)
            if rc == 0:
                for line in out.splitlines():
                    if '|' in line:
                        titre, cats = line.split('|', 1)
                        ups.append({'name': titre.strip(), 'current': '', 'available': '', 'security': 'security' in cats.lower(), 'kind': 'Système'})
        elif IS_MAC:
            rc, out = run(['softwareupdate', '-l'], 120)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('* Label:'):
                    ups.append({'name': line.split(':', 1)[1].strip(), 'current': '', 'available': '', 'security': True, 'kind': 'Système'})
        else:
            run(['apt-get', 'update', '-qq'], 120)
            rc, out = run(['apt-get', '-s', 'upgrade'], 60)
            if rc == 0:
                for line in out.splitlines():
                    if line.startswith('Inst '):
                        p = line.split()
                        nom = p[1] if len(p) > 1 else ''
                        secu = 'security' in line.lower()
                        ups.append({'name': nom, 'current': '', 'available': (p[2].strip('()') if len(p) > 2 else ''), 'security': secu, 'kind': 'Système'})
    except Exception as e:  # noqa: BLE001 — une source en panne ne doit pas taire les autres
        print('[sentinel-agent] mises à jour partielles :', e)
    _MAJ_EN_ATTENTE[0] = len(ups)
    return ups[:600]


# ───────────────────────── tâches ─────────────────────────
def pkg_cmd(kind, paquet):
    """Commande gestionnaire de paquets — arguments en liste, paquet validé."""
    if not PAQUET.match(paquet):
        return None
    if IS_WIN:
        if kind == 'install':
            return ['winget', 'install', '-e', '--id', paquet, '--silent', '--accept-source-agreements', '--accept-package-agreements']
        return ['winget', 'uninstall', '-e', '--id', paquet, '--silent']
    if IS_MAC:
        return ['brew', 'install' if kind == 'install' else 'uninstall', paquet]
    return ['apt-get', 'install' if kind == 'install' else 'remove', '-y', paquet]


def maj_cmd(paquet):
    if paquet and not PAQUET.match(paquet):
        return None
    if IS_WIN:
        return ['winget', 'upgrade', '-e', '--id', paquet, '--silent', '--accept-package-agreements'] if paquet \
            else ['winget', 'upgrade', '--all', '--silent', '--accept-package-agreements']
    if IS_MAC:
        return ['brew', 'upgrade', paquet] if paquet else ['softwareupdate', '-i', '-a']
    return ['apt-get', 'install', '-y', '--only-upgrade', paquet] if paquet else ['apt-get', 'upgrade', '-y']


def shell_fixe(commande):
    """Commande libre : un shell FIXE avec la commande en unique argument (jamais
    shell=True, jamais de chaîne construite). Réservée côté serveur au rôle admin
    sous renfort."""
    return ['cmd.exe', '/c', commande] if IS_WIN else ['/bin/sh', '-c', commande]


def run_job(job, timeout):
    kind, payload = job.get('kind'), (job.get('payload') or '')
    if kind not in KINDS:
        return 1, 'type de tâche inconnu : %s' % kind
    if kind == 'inventory':
        return 0, 'inventaire régénéré'
    if kind == 'wol':
        return wol_send(payload)
    if kind == 'update':
        cmd = maj_cmd(payload.strip())
        return (1, 'nom de paquet refusé') if cmd is None else run(cmd, timeout)
    if kind in ('install', 'uninstall'):
        cmd = pkg_cmd(kind, payload.strip())
        return (1, 'nom de paquet refusé') if cmd is None else run(cmd, timeout)
    if kind == 'cmd':
        return run(shell_fixe(payload), timeout)
    return 1, 'type de tâche inconnu'


def wol_send(payload):
    mac = payload.split('|', 1)[0]
    bcast = payload.split('|', 1)[1] if '|' in payload else ''
    clean = mac.replace(':', '').replace('-', '').strip()
    if len(clean) != 12 or not re.match(r'^[0-9a-fA-F]{12}$', clean):
        return 1, 'adresse MAC invalide'
    if bcast and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', bcast):
        bcast = ''
    cibles = ['255.255.255.255'] + ([bcast] if bcast else [])
    try:
        pkt = b'\xff' * 6 + bytes.fromhex(clean) * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for dst in cibles:
                for port in (9, 7):
                    try:
                        s.sendto(pkt, (dst, port))
                    except OSError:
                        continue
        return 0, 'paquet magique émis vers %s (%s)' % (mac, ', '.join(cibles))
    except OSError as e:
        return 1, 'échec WoL : %s' % e


def poll_jobs(sess, base, headers, timeout):
    inventaire_a_refaire = False
    try:
        r = sess.get(base + '/api/agent/jobs', headers=headers, timeout=10)
        if r.status_code != 200:
            return False
        data = r.json()
        job_timeout = int(data.get('timeout', timeout))
    except (requests.RequestException, ValueError):
        return False
    for job in data.get('jobs', []):
        print('[sentinel-agent] tâche %s %s' % (job.get('id'), job.get('kind')))
        rc, out = run_job(job, job_timeout)
        if job.get('kind') in ('install', 'uninstall', 'inventory', 'update'):
            inventaire_a_refaire = True
        try:
            sess.post('%s/api/agent/jobs/%s/result' % (base, job['id']), json={'output': out[-SORTIE_MAX:], 'rc': rc}, headers=headers, timeout=15)
        except requests.RequestException as e:
            print('[sentinel-agent] résultat non transmis :', e)
    return inventaire_a_refaire


# ───────────────────────── configuration ─────────────────────────
def lire_config():
    for source in (CONFIG_FILE, os.environ.get('SENTINEL_CONFIG', '')):
        if source and os.path.exists(source):
            try:
                with open(source) as f:
                    c = json.load(f)
                if c.get('url') and c.get('token'):
                    return c
            except (OSError, ValueError):
                pass
    return None


def ecrire_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    tmp = CONFIG_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f)
    os.replace(tmp, CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def echanger_code(sess, url, code):
    r = sess.get(url.rstrip('/') + '/api/enroll/config', params={'code': code}, timeout=20)
    if r.status_code != 200:
        raise RuntimeError('code d\'inscription refusé (%s)' % r.status_code)
    return r.json()['token']


def self_install(url):
    exe_py = os.path.abspath(sys.argv[0])
    dest = os.path.join(CONFIG_DIR, 'sentinel-agent.py')
    if os.path.abspath(dest) != exe_py:
        import shutil
        shutil.copy2(exe_py, dest)
    py = sys.executable
    if IS_WIN:
        ps = ('$a=New-ScheduledTaskAction -Execute "%s" -Argument "%s";'
              '$t=New-ScheduledTaskTrigger -AtStartup;'
              '$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest;'
              '$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries '
              '-RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999;'
              'Register-ScheduledTask -TaskName "SentinelAgent" -Action $a -Trigger $t -Principal $p -Settings $s -Force' % (py, dest))
        return run(['powershell', '-NoProfile', '-Command', ps], 60)
    if IS_MAC:
        plist = '/Library/LaunchDaemons/fr.sentinel.agent.plist'
        with open(plist, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                    '<key>Label</key><string>fr.sentinel.agent</string>'
                    '<key>ProgramArguments</key><array><string>%s</string><string>%s</string></array>'
                    '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n' % (py, dest))
        os.chmod(plist, 0o644)
        run(['launchctl', 'unload', plist])
        return run(['launchctl', 'load', '-w', plist])
    unit = '/etc/systemd/system/sentinel-agent.service'
    with open(unit, 'w') as f:
        f.write('[Unit]\nDescription=Sentinel monitoring agent\nAfter=network-online.target\nWants=network-online.target\n\n'
                '[Service]\nType=simple\nExecStart=%s %s\nRestart=always\nRestartSec=15\n\n'
                '[Install]\nWantedBy=multi-user.target\n' % (py, dest))
    run(['systemctl', 'daemon-reload'])
    return run(['systemctl', 'enable', '--now', 'sentinel-agent'])


def bootstrap(a):
    url = os.environ.get('SENTINEL_URL', a.url or '')
    code = os.environ.get('SENTINEL_ENROLL_CODE', '')
    site = os.environ.get('SENTINEL_SITE', a.site or 'Agents')
    nom = os.environ.get('SENTINEL_NAME', a.name or '')
    relais = os.environ.get('SENTINEL_RELAY', '') in ('1', 'true', 'yes')
    if not url or not code:
        sys.exit('SENTINEL_URL et SENTINEL_ENROLL_CODE requis pour l\'inscription.')
    try:
        sess = session_http(url, pin=os.environ.get('SENTINEL_PIN'), ca=os.environ.get('SENTINEL_CA'))
    except ValueError as e:
        sys.exit('SENTINEL_PIN : %s' % e)
    print('→ Inscription auprès de %s' % url)
    try:
        token = echanger_code(sess, url, code)
    except (requests.RequestException, RuntimeError, ValueError) as e:
        sys.exit('inscription impossible : %s' % e)
    cfg = {'url': url.rstrip('/'), 'token': token, 'site': site, 'name': nom, 'relais': relais}
    if os.environ.get('SENTINEL_PIN'):
        cfg['pin'] = os.environ['SENTINEL_PIN']
    if os.environ.get('SENTINEL_CA'):
        cfg['ca'] = os.environ['SENTINEL_CA']
    ecrire_config(cfg)
    print('→ Vérification de la remontée')
    headers = {'X-Agent-Token': token}
    payload = collect(site, nom, relais)
    payload['inventory'] = collect_inventory()
    if not relais:
        payload['software'] = collect_software()
        payload['updates'] = collect_updates()
    try:
        r = sess.post(cfg['url'] + '/api/ingest', json=payload, headers=headers, timeout=60)
        if r.status_code != 200:
            sys.exit('la console a répondu %s' % r.status_code)
    except requests.RequestException as e:
        sys.exit('console injoignable : %s' % e)
    print('→ Installation du service')
    try:
        rc, out = self_install(cfg['url'])
    except PermissionError:
        sys.exit('droits administrateur requis (sudo, ou clic droit → administrateur).')
    if rc != 0:
        sys.exit('service non installé : %s' % out[:200])
    print('✓ Terminé — le poste apparaît dans la console.')


def boucle(cfg, a):
    base = cfg['url'].rstrip('/')
    sess = session_http(base, pin=cfg.get('pin'), ca=cfg.get('ca'))
    headers = {'X-Agent-Token': cfg['token'], 'Content-Type': 'application/json'}
    site, nom = cfg.get('site', 'Agents'), cfg.get('name', '')
    relais = cfg.get('relais', False)
    inv_tous = 12
    cycle = inv_tous
    while True:
        try:
            payload = collect(site, nom, relais)
            if cycle >= inv_tous:
                if relais:
                    inv = collect_inventory()
                    payload['inventory'] = {'hostname': inv.get('hostname'), 'nics': inv.get('nics', [])}
                else:
                    payload['inventory'] = collect_inventory()
                    payload['software'] = collect_software()
                    payload['updates'] = collect_updates()
                cycle = 0
            cycle += 1
            r = sess.post(base + '/api/ingest', json=payload, headers=headers, timeout=30)
            if r.status_code == 200:
                print('[sentinel-agent] ok  cpu=%s%% ram=%s%%' % (payload['cpu'], payload['ram']))
            elif r.status_code == 401:
                print('[sentinel-agent] 401 — jeton refusé ; réinscription nécessaire.')
            else:
                print('[sentinel-agent] serveur %s' % r.status_code)
        except requests.RequestException as e:
            print('[sentinel-agent] remontée échouée :', e)
        try:
            if poll_jobs(sess, base, headers, a.job_timeout):
                cycle = inv_tous
        except requests.RequestException as e:
            print('[sentinel-agent] tâches :', e)
        time.sleep(max(5, a.interval))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', default=os.environ.get('SENTINEL_URL'))
    p.add_argument('--site', default=os.environ.get('SENTINEL_SITE', 'Agents'))
    p.add_argument('--name', default=os.environ.get('SENTINEL_NAME', ''))
    p.add_argument('--interval', type=int, default=int(os.environ.get('SENTINEL_INTERVAL', '30')))
    p.add_argument('--job-timeout', dest='job_timeout', type=int, default=int(os.environ.get('SENTINEL_JOB_TIMEOUT', '120')))
    p.add_argument('--enroller', action='store_true', help='échanger le code, ranger le jeton, poser le service')
    p.add_argument('--once', action='store_true', help='une remontée puis quitter (auto-test)')
    a = p.parse_args()

    if a.enroller:
        bootstrap(a)
        return
    cfg = lire_config()
    if not cfg:
        sys.exit('Aucune configuration : lance d\'abord --enroller (SENTINEL_URL + SENTINEL_ENROLL_CODE).')
    if a.once:
        sess = session_http(cfg['url'], pin=cfg.get('pin'), ca=cfg.get('ca'))
        payload = collect(cfg.get('site', 'Agents'), cfg.get('name', ''), cfg.get('relais', False))
        r = sess.post(cfg['url'].rstrip('/') + '/api/ingest', json=payload, headers={'X-Agent-Token': cfg['token']}, timeout=45)
        sys.exit(0 if r.status_code == 200 else 'échec : le serveur a répondu %s' % r.status_code)
    boucle(cfg, a)


if __name__ == '__main__':
    main()
