#!/usr/bin/env python3
"""Strip SHF_RO_AFTER_INIT from the .bss section of frida-agent.ko.

The prelinked Rust/GumJS/libc object carries a .bss marked SHF_RO_AFTER_INIT
(0x00200000).  The kernel's layout_sections() then places .bss into the
ro_after_init region (text -> rodata -> bss -> data) and module_enable_ro()'s
frob_ro_after_init() flips it read-only, so the worker thread writing the kfifo
statics in .bss faults with "write to read-only memory" as soon as it races the
post-init frob.  Clearing the flag makes .bss a normal writable-data section.
"""

import struct
import sys

SHF_RO_AFTER_INIT = 0x00200000


def patch(path):
    with open(path, "rb") as f:
        data = bytearray(f.read())

    if data[:4] != b"\x7fELF":
        print(f"ERROR: {path} is not ELF", file=sys.stderr)
        return False

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    shstr_h = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_h + 0x18)[0]
    shstr_size = struct.unpack_from("<Q", data, shstr_h + 0x20)[0]
    shstr = bytes(data[shstr_off:shstr_off + shstr_size])

    def sname(off):
        e = shstr.find(b"\0", off)
        return shstr[off:e].decode(errors="replace")

    changed = 0
    for i in range(e_shnum):
        h = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, h)[0]
        flags = struct.unpack_from("<Q", data, h + 8)[0]
        nm = sname(name_off)
        if nm == ".bss" and (flags & SHF_RO_AFTER_INIT):
            flags &= ~SHF_RO_AFTER_INIT
            struct.pack_into("<Q", data, h + 8, flags)
            changed += 1

    if changed == 0:
        print(f"NOTE: {path} .bss already lacks SHF_RO_AFTER_INIT",
              file=sys.stderr)

    with open(path, "wb") as f:
        f.write(data)

    print(f"patched {path}: cleared SHF_RO_AFTER_INIT from .bss "
          f"({changed} section(s))")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: strip-bss-roafter.py <frida-agent.ko>", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
