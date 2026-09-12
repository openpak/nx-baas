#!/usr/bin/env python3
"""Locate a string in a firmware module and list the code that references it.

    ./find.py <module.elf> '$.friend.presence.pf' 'c-friends'

Prints each match as a module address plus the instructions that materialise
it, so a Ghidra run can go straight to the right function. Address arithmetic:
Ghidra loads these modules at 0x100000, so a Ghidra address is what this prints
plus 0x100000 — that difference has cost more time than any other detail here.
"""
import sys
from module import Mod


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    m = Mod(sys.argv[1])
    xrefs = m.scan_xrefs()
    ro_addr, ro_off, ro_size = m.sections[".rodata"]
    blob = m.buf[ro_off:ro_off + ro_size]
    for needle in sys.argv[2:]:
        found = False
        start = 0
        while True:
            i = blob.find(needle.encode(), start)
            if i < 0:
                break
            start = i + 1
            addr = ro_addr + i
            refs = xrefs.get(addr, [])
            print(f"{needle!r} @ {addr:#x} (ghidra {addr + 0x100000:#x})"
                  f"  refs: {[hex(r + 0x100000) for r in refs] or 'none found'}")
            found = True
        if not found:
            print(f"{needle!r}: not present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
