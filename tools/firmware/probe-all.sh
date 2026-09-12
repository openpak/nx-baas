#!/usr/bin/env bash
# Probe every dumped module for the things that decide whether a server answers
# it: hostnames, URL templates, JSON selectors, HTTP headers, NPNS topics and
# service ports. One file per facet under all/probe/, each line "<module> <hit>".
set -u
export LC_ALL=C
OUT=${OUT:-$HOME/openpak-firmware-audit-22.5.0/all}
P="$OUT/probe"; mkdir -p "$P"
for f in hosts urls paths headers topics ports agents errors; do : > "$P/$f.tsv"; done

while IFS=$'\t' read -r tid name; do
  s="$OUT/$tid/strings.txt"; [ -f "$s" ] || continue
  sed 's/^ *[0-9][0-9]* //' "$s" > /tmp/probe.$$

  grep -ohE '[A-Za-z0-9%*._-]+\.(nintendo|nintendowifi)\.(net|com|co\.jp)' /tmp/probe.$$ |
    sort -u | sed "s/^/$name\t/" >> "$P/hosts.tsv"
  grep -ohE 'https?://[^ ]+' /tmp/probe.$$ |
    grep -viE 'curl\.haxx|curl\.se|gnu\.org|openssl|w3\.org|ietf|rfc-editor|unicode\.org|sqlite\.org|json\.org|zlib|libpng|github\.com' |
    sort -u | sed "s/^/$name\t/" >> "$P/urls.tsv"
  grep -ohE '\$\.[][A-Za-z0-9_.*]+' /tmp/probe.$$ | sort -u | sed "s/^/$name\t/" >> "$P/paths.tsv"
  grep -ohE '^(X-[A-Za-z0-9-]+|Authorization|Content-Type|Accept|If-None-Match|If-Range|Range|User-Agent)[:.].*' /tmp/probe.$$ |
    sort -u | sed "s/^/$name\t/" >> "$P/headers.tsv"
  grep -ohE '\bc-[a-zA-Z0-9]+(\.[A-Za-z0-9]+)*' /tmp/probe.$$ | sort -u | sed "s/^/$name\t/" >> "$P/topics.tsv"
  # sm port names: short, lowercase, often with a ':' suffix form.
  grep -ohE '^[a-z][a-z0-9_]{1,6}:[a-z]{0,3}$' /tmp/probe.$$ | sort -u | sed "s/^/$name\t/" >> "$P/ports.tsv"
  grep -ohE '^(libcurl|Nintendo|NintendoSDK)[ (].*' /tmp/probe.$$ | sort -u | sed "s/^/$name\t/" >> "$P/agents.tsv"
  # A state machine names its own protocol in its error strings.
  grep -ohE '.{0,60}(expected, but|unexpected|must be|is not supported|invalid).{0,60}' /tmp/probe.$$ |
    grep -viE 'sqlite|jpeg|curl|ssl|zlib|json parse' | sort -u | sed "s/^/$name\t/" >> "$P/errors.tsv"
  rm -f /tmp/probe.$$
done < "$OUT/names.tsv"

wc -l "$P"/*.tsv
