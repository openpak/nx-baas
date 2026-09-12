#!/usr/bin/env bash
# Dump every Program NCA in the 22.5.0 firmware to <out>/<name>/{exefs,main.elf,strings.txt}.
# The name comes from the NPDM; the title id from the NCA header.
set -u
FW=${FW:-$HOME/Downloads/Firmware.22.5.0}
OUT=${OUT:-$HOME/openpak-firmware-audit-22.5.0/all}
KEYS=${KEYS:-$HOME/openpak-firmware-audit-22.5.0/prod.keys}
NX2ELF=${NX2ELF:-$HOME/REPOS/nx2elf/build/nx2elf}

mkdir -p "$OUT"
: > "$OUT/inventory.tsv"

for nca in "$FW"/*.nca; do
  case "$nca" in *.cnmt.nca) continue;; esac
  base=$(basename "$nca" .nca)
  hdr=$(hactool -k "$KEYS" --intype=nca "$nca" 2>/dev/null | sed -n '1,40p')
  type=$(printf '%s\n' "$hdr" | awk -F': *' '/^Content Type:/{print $2; exit}')
  tid=$(printf '%s\n' "$hdr"  | awk -F': *' '/^Title ID:/{print $2; exit}')
  [ "$type" = "Program" ] || { printf '%s\t%s\t%s\tskip\n' "$base" "$tid" "$type" >> "$OUT/inventory.tsv"; continue; }

  tmp=$(mktemp -d)
  hactool -k "$KEYS" --intype=nca --exefsdir="$tmp/exefs" "$nca" >/dev/null 2>&1
  [ -f "$tmp/exefs/main" ] || { printf '%s\t%s\t%s\tno-main\n' "$base" "$tid" "$type" >> "$OUT/inventory.tsv"; rm -rf "$tmp"; continue; }

  # Name: the NPDM carries it, and it is the only human label in the package.
  name=$(hactool -k "$KEYS" --intype=npdm "$tmp/exefs/main.npdm" 2>/dev/null |
         awk -F': *' '/^(Title Name|Name):/{print $2; exit}')
  [ -n "${name:-}" ] || name=$tid
  name=$(printf '%s' "$name" | tr -cd 'A-Za-z0-9._-')
  [ -n "$name" ] || name=$tid
  # Collisions (two NCAs, same name) keep the title id as a suffix.
  d="$OUT/$name"; [ -e "$d" ] && d="$OUT/$name-$tid"
  mkdir -p "$d"
  mv "$tmp/exefs" "$d/exefs"
  if "$NX2ELF" "$d/exefs/main" --export-elf "$d/main.elf" >"$d/nx2elf.log" 2>&1 && [ -s "$d/main.elf" ]; then
    strings -t d -n 4 "$d/main.elf" > "$d/strings.txt"
    printf '%s\t%s\t%s\t%s\t%s\n' "$base" "$tid" "$type" "$name" "$(stat -c%s "$d/main.elf")" >> "$OUT/inventory.tsv"
    echo "ok   $tid $name"
  else
    printf '%s\t%s\t%s\t%s\tnx2elf-failed\n' "$base" "$tid" "$type" "$name" >> "$OUT/inventory.tsv"
    echo "FAIL $tid $name"
  fi
  rm -rf "$tmp"
done
echo "done: $(grep -c . "$OUT/inventory.tsv") rows"
