# Reading the 22.5.0 modules

What recovered the Penne handshake, the record protocol, the event payloads and
the invitation surface (`docs/firmware-22.5.0-followup-2026-09-12.md`,
`docs/penne-protocol.md`). Keeping it here so the next question costs an hour
rather than a day.

## Where the modules are

`~/openpak-firmware-audit-22.5.0/<module>/main.elf` — npns, friends, nim, ns,
account, am, shop and others, each with a `strings.txt`. These are local
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
