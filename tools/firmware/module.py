import struct, bisect
from capstone import *
from capstone.arm64 import *

class Mod:
    def __init__(self, path):
        self.buf = open(path, "rb").read()
        e_shoff, = struct.unpack_from("<Q", self.buf, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", self.buf, 0x3a)
        secs = []
        for i in range(e_shnum):
            o = e_shoff + i*e_shentsize
            name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", self.buf, o)
            secs.append((name, typ, addr, off, size))
        strtab_off = secs[e_shstrndx][3]
        self.sections = {}
        for name, typ, addr, off, size in secs:
            end = self.buf.index(b"\0", strtab_off+name)
            nm = self.buf[strtab_off+name:end].decode()
            self.sections[nm] = (addr, off, size)
        self.text_addr, self.text_off, self.text_size = self.sections[".text"]
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def read(self, vaddr, n):
        for addr, off, size in self.sections.values():
            if addr <= vaddr < addr+size and off:
                return self.buf[off+(vaddr-addr): off+(vaddr-addr)+n]
        return b""

    def cstr(self, vaddr, maxlen=200):
        b = self.read(vaddr, maxlen)
        if not b: return ""
        end = b.find(b"\0")
        return b[:end if end >= 0 else maxlen].decode("utf-8", "replace")

    def disasm(self, vaddr, n):
        return list(self.md.disasm(self.read(vaddr, n*4), vaddr))

    def scan_xrefs(self):
        """ADRP+ADD / ADRP+LDR pairs -> materialized addresses."""
        code = self.buf[self.text_off:self.text_off+self.text_size]
        xrefs = {}   # target vaddr -> [code vaddr]
        pend = {}    # reg -> (page, adrp_addr)
        for ins in self.md.disasm(code, self.text_addr):
            if ins.id == ARM64_INS_ADRP:
                d = ins.operands
                pend[d[0].reg] = (d[1].imm, ins.address)
            elif ins.id == ARM64_INS_ADR and len(ins.operands) == 2 and ins.operands[1].type == ARM64_OP_IMM:
                xrefs.setdefault(ins.operands[1].imm, []).append(ins.address)
            elif ins.id == ARM64_INS_LDR and len(ins.operands) == 2 and ins.operands[1].type == ARM64_OP_IMM:
                # LDR literal: the pool slot holds the real target.
                import struct as _s
                raw = self.read(ins.operands[1].imm, 8)
                if len(raw) == 8:
                    xrefs.setdefault(_s.unpack("<Q", raw)[0], []).append(ins.address)
            elif ins.id in (ARM64_INS_ADD, ARM64_INS_LDR) and len(ins.operands) >= 2:
                ops = ins.operands
                if ins.id == ARM64_INS_ADD and ops[1].type == ARM64_OP_REG and ops[1].reg in pend and len(ops) == 3 and ops[2].type == ARM64_OP_IMM:
                    page, _ = pend[ops[1].reg]
                    tgt = page + ops[2].imm
                    xrefs.setdefault(tgt, []).append(ins.address)
                    if ops[0].reg != ops[1].reg: pend.pop(ops[1].reg, None)
                elif ins.id == ARM64_INS_LDR and ops[1].type == ARM64_OP_MEM and ops[1].mem.base in pend:
                    page, _ = pend[ops[1].mem.base]
                    tgt = page + ops[1].mem.disp
                    xrefs.setdefault(tgt, []).append(ins.address)
        return xrefs

def scan_calls(m):
    """BL targets -> callers; and a sorted list of function starts (BL targets + prologues)."""
    from capstone.arm64 import ARM64_INS_BL
    code = m.buf[m.text_off:m.text_off+m.text_size]
    callers = {}
    for ins in m.md.disasm(code, m.text_addr):
        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == 2:  # IMM
            callers.setdefault(ins.operands[0].imm, []).append(ins.address)
    return callers
