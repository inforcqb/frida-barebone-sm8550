#!/usr/bin/env python3
"""Make frida-gum call glib_init()/gobject_init() unconditionally.

A Linux kernel module never runs ELF .init_array constructors, so the GObject
type system must be initialised by explicit calls.  frida-gum only makes those
calls behind HAVE_FRIDA_GLIB, which meson sets after a `cc.has_function` probe
whose bare-metal link step fails — silently leaving the type system NULL and
panicking in g_type_from_name() (NULL deref at g_hash_table_lookup+0x18).

We keep the other HAVE_FRIDA_GLIB-gated code (g_thread_set_callbacks,
g_platform_audit_set_fd_callbacks, g_mem_set_vtable) untouched, because
g_platform_audit_set_fd_callbacks is absent from the 17.17.0 glib SDK and would
cause a link failure.  glib_init() is idempotent, so calling it from both
gum_init_embedded() and gum_do_init() is harmless.
"""

import sys


PATCH_DO_INIT_OLD = """#ifdef HAVE_FRIDA_GLIB
  glib_init ();
  gobject_init ();
#endif"""

PATCH_DO_INIT_NEW = """  glib_init ();
  gobject_init ();"""

PATCH_EMBEDDED_OLD = """#ifdef HAVE_FRIDA_GLIB
  glib_init ();
#endif"""

PATCH_EMBEDDED_NEW = """  glib_init ();"""


def patch(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()

    changed = 0
    for old, new in ((PATCH_DO_INIT_OLD, PATCH_DO_INIT_NEW),
                     (PATCH_EMBEDDED_OLD, PATCH_EMBEDDED_NEW)):
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
        else:
            print(f"ERROR: block not found in {path}:\n{old}", file=sys.stderr)
            return False

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"patched {path}: glib_init/gobject_init now unconditional ({changed} blocks)")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-gum-init.py <gum.c>", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
