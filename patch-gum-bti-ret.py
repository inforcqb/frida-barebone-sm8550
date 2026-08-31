#!/usr/bin/env python3
"""Route Gum's arm64 `br` through `ret` to dodge BTI on Linux kernels.

On an arm64 kernel with CONFIG_ARM64_BTI_KERNEL=y, an indirect `br xN`
(branch-register) faults with "Oops - BTI" unless the target begins with a
`bti` landing-pad.  frida-gum's GumArm64Writer never emits landing-pads for
the trampolines/thunks it generates at runtime, so Interceptor.attach() of a
kernel function panics the kernel the moment the redirect's `br` reaches the
trampoline.

Upstream frida-gum already applies exactly this trick in one spot (#731/#735:
guminterceptor-arm64.c gum_emit_epilog uses `ret` instead of `br` when
HAVE_PTRAUTH is unset), because `ret xN` performs the same unconditional jump
as `br xN` but is exempt from the BTI check (BTI only inspects BR/BLR).
We generalise it here: when pointer authentication is not supported (Linux
kernels; HAVE_PTRAUTH is Darwin-only), make put_br_reg()/put_br_reg_no_auth()
emit `ret xN` instead of `br xN`.  This single change covers every indirect
branch Gum generates — the Interceptor trampolines/thunks, the deflector
dispatchers in gumcodeallocator.c, the relocator's rewritten b/cbz/tbz, the
writer's far put_branch_address, and Stalker — instead of patching ~25 call
sites one by one and missing some.

On Darwin arm64e (ptrauth_support == GUM_PTRAUTH_SUPPORTED) the original
behaviour is preserved, since `ret` there implies PAC authentication and the
jump targets are not signed.
"""

import sys


PATCH_BR_OLD = """gum_arm64_writer_put_br_reg (GumArm64Writer * self,
                             arm64_reg reg)
{
  return gum_arm64_writer_put_br_reg_with_extra (self, reg,
      (self->ptrauth_support == GUM_PTRAUTH_SUPPORTED) ? 0x81f : 0);
}"""

PATCH_BR_NEW = """gum_arm64_writer_put_br_reg (GumArm64Writer * self,
                             arm64_reg reg)
{
  if (self->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    return gum_arm64_writer_put_br_reg_with_extra (self, reg, 0x81f);

  return gum_arm64_writer_put_ret_reg (self, reg);
}"""

PATCH_BR_NOAUTH_OLD = """gum_arm64_writer_put_br_reg_no_auth (GumArm64Writer * self,
                                     arm64_reg reg)
{
  return gum_arm64_writer_put_br_reg_with_extra (self, reg, 0);
}"""

PATCH_BR_NOAUTH_NEW = """gum_arm64_writer_put_br_reg_no_auth (GumArm64Writer * self,
                                     arm64_reg reg)
{
  if (self->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    return gum_arm64_writer_put_br_reg_with_extra (self, reg, 0);

  return gum_arm64_writer_put_ret_reg (self, reg);
}"""


def patch(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()

    changed = 0
    for old, new in ((PATCH_BR_OLD, PATCH_BR_NEW),
                     (PATCH_BR_NOAUTH_OLD, PATCH_BR_NOAUTH_NEW)):
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
        else:
            print(f"ERROR: block not found in {path}:\n{old}", file=sys.stderr)
            return False

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"patched {path}: put_br_reg/put_br_reg_no_auth now use ret "
          f"when ptrauth is unsupported ({changed} blocks)")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-gum-bti-ret.py <gumarm64writer.c>", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
