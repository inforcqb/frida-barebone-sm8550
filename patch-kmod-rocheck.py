#!/usr/bin/env python3
"""Add a pre-write RO probe to frida-kmod.c so a read-only .data/.bss page
is reported and the write is skipped instead of panicking the kernel.

The probe walks the page table through init_mm (resolved at runtime via the
kallsyms_lookup_name shim, so it works under ksud insmod).  On the write path
into the kfifo statics we check the PTE RDONLY bit first: if RO we print the
address and abort the operation, otherwise proceed.

This turns the previous "write to read-only memory" panic into an observable
log line, letting us see WHEN the page got flipped RO without rebooting.
"""

import sys


# Anchor 1a: declare frida_init_mm next to the other resolved-symbol pointers.
GLOBALS_ANCHOR = """static typeof (&set_memory_nx) frida_set_memory_nx_impl;"""

GLOBALS_NEW = """static typeof (&set_memory_nx) frida_set_memory_nx_impl;
static struct mm_struct * frida_init_mm;"""


# Anchor 1b: insert the RO probe right before the frida_kmod_make_data_writable()
# helper that patch-kmod-rw.py inserted.
MAKE_RW_ANCHOR = """/* KernelSU LKM (and this hardened kernel) leaves the module's .data/.bss
 * read-only, and Gum's code protection can flip them back to read-only again
 * later.  Re-mark the pages holding frida-kmod.c's writable statics RW before
 * touching them.  __nocfi: set_memory_rw() is a kprobe-resolved pointer whose
 * type carries no CFI hash. */
"""

MAKE_RW_PROBE = """/* KernelSU LKM (and this hardened kernel) leaves the module's .data/.bss
 * read-only, and Gum's code protection can flip them back to read-only again
 * later.  Re-mark the pages holding frida-kmod.c's writable statics RW before
 * touching them.  __nocfi: set_memory_rw() is a kprobe-resolved pointer whose
 * type carries no CFI hash. */
static int
frida_page_is_ro (unsigned long addr)
{
  pgd_t * pgd;
  p4d_t * p4d;
  pud_t * pud;
  pmd_t * pmd;
  pte_t * pte;

  if (frida_init_mm == NULL)
    return -1;

  pgd = frida_init_mm->pgd + pgd_index (addr);
  if (pgd_none (*pgd) || pgd_bad (*pgd))
    return -1;
  p4d = p4d_offset (pgd, addr);
  if (p4d_none (*p4d) || p4d_bad (*p4d))
    return -1;
  pud = pud_offset (p4d, addr);
  if (pud_none (*pud) || pud_bad (*pud))
    return -1;
  pmd = pmd_offset (pud, addr);
  if (pmd_none (*pmd) || pmd_bad (*pmd))
    return -1;
  pte = pte_offset_kernel (pmd, addr);
  if (pte == NULL)
    return -1;

  return (pte_val (*pte) >> 7) & 1;
}
"""


# Anchor 2: resolve init_mm inside frida_resolve_kallsyms(), after the
# set_memory_* lookups.
RESOLVE_ANCHOR = """  frida_set_memory_ro_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_ro");
  frida_set_memory_rw_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_rw");
  frida_set_memory_x_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_x");
  frida_set_memory_nx_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_nx");
}"""

RESOLVE_NEW = """  frida_set_memory_ro_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_ro");
  frida_set_memory_rw_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_rw");
  frida_set_memory_x_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_x");
  frida_set_memory_nx_impl = (void *) frida_kallsyms_lookup_name_impl ("set_memory_nx");

  frida_init_mm = (struct mm_struct *) frida_kallsyms_lookup_name_impl ("init_mm");
}"""


# Anchor 3: report RO state right after make_data_writable() runs its
# set_memory_rw(), inside frida_kmod_link_open before kfifo_alloc.
LINK_OPEN_ANCHOR = """  frida_kmod_make_data_writable ();

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);"""

LINK_OPEN_NEW = """  frida_kmod_make_data_writable ();

  if (frida_page_is_ro ((unsigned long) &frida_to_client) != 0)
    {
      printk (KERN_ERR "frida: ABORT link_open: frida_to_client page is RO\\n");
      return -EROFS;
    }

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);"""


def patch(path):
    with open(path, encoding="utf-8", newline="") as f:
        text = f.read()

    # Normalise CRLF -> LF so anchors match regardless of how this .py or the
    # target file was saved.
    text = text.replace("\r\n", "\n")

    changed = 0
    for old, new in ((GLOBALS_ANCHOR, GLOBALS_NEW),
                     (MAKE_RW_ANCHOR, MAKE_RW_PROBE),
                     (RESOLVE_ANCHOR, RESOLVE_NEW),
                     (LINK_OPEN_ANCHOR, LINK_OPEN_NEW)):
        old = old.replace("\r\n", "\n")
        new = new.replace("\r\n", "\n")
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
        else:
            print(f"ERROR: anchor not found in {path}:\n{old[:80]}...",
                  file=sys.stderr)
            return False

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    print(f"patched {path}: added frida_page_is_ro probe + pre-write RO check "
          f"({changed} anchors)")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-kmod-rocheck.py <frida-kmod.c>", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
