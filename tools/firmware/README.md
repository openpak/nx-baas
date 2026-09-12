# Reading the 22.5.0 modules

What recovered the Penne handshake, the record protocol, the event payloads and
the invitation surface (`docs/firmware-22.5.0-followup-2026-09-12.md`,
`docs/penne-protocol.md`). Keeping it here so the next question costs an hour
rather than a day.

## Dump and probe everything first

```sh
./dump-all.sh    # every Program NCA in 22.5.0 -> ~/openpak-firmware-audit-22.5.0/all/, 75 modules
./probe-all.sh   # hosts, URLs, $. selectors, headers, topics, ports -> all/probe/*.tsv
```

That is the cheap first move for any new question: `grep <thing> all/probe/*.tsv`
answers "which module cares about this" before a single decompile. `all/<name>`
is a symlink to `all/<titleid>`, so `all/friends/strings.txt` works.

## Where the modules are

`~/openpak-firmware-audit-22.5.0/<module>/main.elf` — npns, friends, nim, ns,
account, am, shop, bcat, news and others, each with a `strings.txt`.

Two were added on 2026-09-12 and the recipe is worth keeping: the ProdKeys file
had `master_kek_source_*` / `mariko_master_kek_source_*` lines whose values are
34 hex digits, and hactool 1.4.0 aborts the whole keyset on the first one. Drop
those lines (`awk -F\' *= *\' \'NF==2 && length($2)!=34\'`) and it loads. Then
`hactool -k prod.keys --intype=nca --exefsdir=<d>/exefs <nca>` and
`~/REPOS/nx2elf/build/nx2elf <d>/exefs/main --export-elf <d>/main.elf`. These are local
research inputs, not repository assets, and nothing from them is copied into
OpenPak: what lands in the code is the observable contract (field names, types,
message shapes), never firmware code.

## The one piece of arithmetic

Ghidra loads these at **0x100000**. An ELF address `0xd9250` is Ghidra
`0x1d9250`. Every "NOFUNC" result means this was forgotten. `strings.txt`
offsets are **file offsets**, not addresses: subtract `.rodata`'s
(offset − address) delta, which `module.py` does for you.

## Finding what to look at

```sh
python3 find.py ~/openpak-firmware-audit-22.5.0/friends/main.elf '$.friend.presence.pf'
```

Prints the string's address and the instructions that reference it, in Ghidra
coordinates. `module.py` also gives you `scan_xrefs()` (ADRP/ADD, ADR and
literal-pool loads), `scan_calls()` (a BL call graph) and `disasm()`.

## Reading it

Ghidra is packaged (`/opt/ghidra`). Import once per module:

```sh
/opt/ghidra/support/analyzeHeadless <projdir> npnsproj \
  -import ~/openpak-firmware-audit-22.5.0/npns/main.elf
```

Then decompile whatever the addresses pointed at — `DecompAround.java` takes
addresses anywhere *inside* a function (not just its entry) and writes one `.c`
per function plus an index of callers:

```sh
/opt/ghidra/support/analyzeHeadless <projdir> npnsproj -process main.elf \
  -noanalysis -postScript DecompAround.java <outdir> 1d9730 1da2f0 \
  -scriptPath $PWD
```

`RefsTo.java` lists references to a data address, which is how a vtable gets
traced back to the class that installs it.

## The three moves that did most of the work

1. **A state machine announces itself through its error strings.** "HandoverResult
   expected, but …received" named the whole opening sequence; grep the module for
   `expected, but` before anything else.
2. **Vtables beat call graphs.** Parser and transport classes are reached
   indirectly, so `RefsTo` on the vtable address finds the constructor, and the
   entries are the callbacks whose strings are the field names.
3. **The console is a faster oracle than the disassembler** when a shape is
   ambiguous: log the bytes it sends, and vary what you send back. That is what
   `NX_PENNE_SYNC_PROBE` does.
