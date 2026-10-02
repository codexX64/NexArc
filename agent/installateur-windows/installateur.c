/*
 * NEXARC - installateur Windows de l'agent.
 *
 * Un seul exécutable générique, compilé à la construction de l'image. NEXARC
 * lui colle en fin de fichier, à chaque téléchargement, l'adresse du script
 * d'installation (code d'inscription compris) :
 *
 *     [exécutable][adresse UTF-8][longueur, 4 octets LE]["NXRCINS1"]
 *
 * L'exécutable relit cette fin, vérifie l'adresse caractère par caractère
 * (rien qui puisse sortir des apostrophes de PowerShell), puis lance le même
 * script que la commande d'une ligne, avec le PowerShell du système désigné
 * par son chemin complet. Le manifeste demande l'élévation : l'agent se pose
 * en tâche SYSTEM. Rien d'autre n'est lu, écrit ni exécuté.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAGIE "NXRCINS1"
#define ADRESSE_MAX 2048

static int caractere_admis(unsigned char c) {
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return 1;
  return strchr(":/._~?&=%+-[]", c) != NULL && c != 0;
}

static void attendre(void) {
  printf("\nAppuie sur Entree pour fermer cette fenetre.");
  fflush(stdout);
  getchar();
}

static int echec(const char *message) {
  fprintf(stderr, "\nInstallation impossible : %s\n", message);
  attendre();
  return 1;
}

int main(void) {
  SetConsoleOutputCP(CP_UTF8);
  printf("NEXARC - installation de l'agent\n\n");

  wchar_t chemin[MAX_PATH * 4];
  DWORD n = GetModuleFileNameW(NULL, chemin, sizeof chemin / sizeof chemin[0]);
  if (n == 0 || n >= sizeof chemin / sizeof chemin[0]) return echec("chemin de l'installateur illisible.");

  HANDLE f = CreateFileW(chemin, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE) return echec("installateur illisible.");
  LARGE_INTEGER taille;
  if (!GetFileSizeEx(f, &taille) || taille.QuadPart < 12 + 12) { CloseHandle(f); return echec("installateur incomplet."); }

  unsigned char fin[12];
  DWORD lus = 0;
  LARGE_INTEGER pos; pos.QuadPart = taille.QuadPart - 12;
  if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN) || !ReadFile(f, fin, 12, &lus, NULL) || lus != 12) { CloseHandle(f); return echec("fin de l'installateur illisible."); }
  if (memcmp(fin + 4, MAGIE, 8) != 0) { CloseHandle(f); return echec("cet installateur ne porte aucune adresse : telecharge-le depuis NEXARC (Postes, Ajouter un poste)."); }
  DWORD longueur = (DWORD)fin[0] | ((DWORD)fin[1] << 8) | ((DWORD)fin[2] << 16) | ((DWORD)fin[3] << 24);
  if (longueur < 12 || longueur > ADRESSE_MAX || (LONGLONG)longueur > taille.QuadPart - 12) { CloseHandle(f); return echec("adresse de NEXARC invalide."); }

  char adresse[ADRESSE_MAX + 1];
  pos.QuadPart = taille.QuadPart - 12 - longueur;
  if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN) || !ReadFile(f, adresse, longueur, &lus, NULL) || lus != longueur) { CloseHandle(f); return echec("adresse de NEXARC illisible."); }
  CloseHandle(f);
  adresse[longueur] = 0;

  if (strncmp(adresse, "https://", 8) != 0 && strncmp(adresse, "http://", 7) != 0) return echec("adresse de NEXARC invalide.");
  for (DWORD i = 0; i < longueur; i++) if (!caractere_admis((unsigned char)adresse[i])) return echec("adresse de NEXARC invalide.");

  wchar_t systeme[MAX_PATH];
  UINT ls = GetSystemDirectoryW(systeme, MAX_PATH);
  if (ls == 0 || ls >= MAX_PATH - 40) return echec("dossier systeme introuvable.");
  wchar_t powershell[MAX_PATH];
  _snwprintf(powershell, MAX_PATH, L"%ls\\WindowsPowerShell\\v1.0\\powershell.exe", systeme);
  powershell[MAX_PATH - 1] = 0;

  /* TLS 1.2 au moins, même sur un .NET ancien ; puis le script d'installation. */
  static wchar_t ligne[ADRESSE_MAX + 512];
  int ecrits = _snwprintf(ligne, sizeof ligne / sizeof ligne[0],
    L"\"%ls\" -NoProfile -NoLogo -ExecutionPolicy Bypass -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm -UseBasicParsing '%hs' | iex\"",
    powershell, adresse);
  if (ecrits < 0) return echec("commande trop longue.");

  printf("NEXARC : %s\n\n", strtok(adresse, "?"));
  STARTUPINFOW si; PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof si); si.cb = sizeof si; ZeroMemory(&pi, sizeof pi);
  if (!CreateProcessW(powershell, ligne, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return echec("PowerShell n'a pas pu etre lance.");
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
  printf(code == 0 ? "\nAgent installe.\n" : "\nL'installation a echoue (code %lu) : le message ci-dessus dit pourquoi.\n", (unsigned long)code);
  attendre();
  return (int)code;
}
