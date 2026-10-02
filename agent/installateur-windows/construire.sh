#!/bin/sh
# Compile l'installateur Windows (MinGW-w64). Sortie déterministe : aucune
# date dans l’en-tête PE, chemins de construction retirés. Tout est lié
# statiquement : l’exécutable ne dépend que de DLL présentes sur tout Windows.
set -eu
cd "$(dirname "$0")"
x86_64-w64-mingw32-windres installateur.rc -O coff -o installateur.res
x86_64-w64-mingw32-gcc -O2 -s -Wall -Wextra -std=c11 \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -ffile-prefix-map="$(pwd)"=. \
  -Wl,--no-insert-timestamp -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va \
  -static -o installateur-sentinel.exe installateur.c installateur.res -lssp
rm -f installateur.res
