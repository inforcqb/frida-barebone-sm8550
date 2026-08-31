#!/usr/bin/env python3
"""Inject -mbranch-protection=bti into frida releng's arm64 soft-float flags.

arm64 kernels built with CONFIG_ARM64_BTI_KERNEL fault any indirect branch
(blr) whose target does not start with a `bti` instruction.  Frida's stock
none-arm64-softfloat SDK (picolibc + compiler-rt) and the frida-gum devkit
(glib/gum/gumjs) are compiled without it, so the prebuilt frida-agent.ko
panics with "Oops - BTI" as soon as GumJS calls into the libc/glib through a
function pointer (e.g. malloc via g_hash_table_new_full).

frida releng already handles the x86_64 analogue (CONFIG_X86_KERNEL_IBT) with
`-fcf-protection=branch`; arm64 just never got the matching flag.  This patch
adds it to ARCH_SOFTFLOAT_FLAGS_UNIX["arm64"], which flows into `common_flags`
and therefore into every C/C++ object in the SDK and devkit builds.
"""

import sys


TARGET_OLD = """        "-mabi=aapcs-soft",
        "-mgeneral-regs-only",
        "-ffixed-x18",
        "-fno-pic",
"""

TARGET_NEW = """        "-mabi=aapcs-soft",
        "-mgeneral-regs-only",
        "-ffixed-x18",
        "-fno-pic",
        "-mbranch-protection=bti",
"""


def patch(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()

    if TARGET_OLD not in text:
        print(f"ERROR: expected soft-float arm64 block not found in {path}",
              file=sys.stderr)
        return False

    patched = text.replace(TARGET_OLD, TARGET_NEW, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(patched)
    print(f"patched {path}: added -mbranch-protection=bti to arm64 soft-float flags")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-bti-env.py <env_generic.py> [...]", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
