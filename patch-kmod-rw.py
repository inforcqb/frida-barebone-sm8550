#!/usr/bin/env python3
"""Re-mark frida-kmod.c's .data/.bss writable after the module loads.

On this device (KernelSU LKM + a hardened OnePlus GKI build with
CONFIG_STRICT_MODULE_RWX), the module's writable tail is left read-only once
init_module returns, and the kernel's set_memory_rw() is wrapped by an Android
vendor hook (trace_android_vh_set_memory_rw) that OnePlus uses to veto the
flip.  The agent's worker thread keeps writing to frida-kmod.c statics after
that point (kfifo, miscdevice, waitqueue, ...), which panics with "Unable to
handle kernel write to read-only memory" inside __kfifo_alloc/__kfifo_out.

So instead of set_memory_rw(), resolve the unwrapped change_memory_common()
(CONFIG_KALLSYMS_ALL exposes it) and call it directly with PTE_WRITE /
PTE_EXEC masks, bypassing the vendor hook.  The symbol addresses of the
module's writable statics delimit the range to flip.
"""

import sys


OLD = """int
frida_kmod_link_open (void)
{
  int res;

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
"""

NEW = """/* KernelSU LKM (and this hardened kernel) leave the module's .data/.bss
 * read-only once init_module returns, but the worker thread keeps writing to
 * frida-kmod.c's statics (kfifo, miscdevice, waitqueue, ...) long after that.
 * Re-mark the pages holding them RW before touching them.
 * __nocfi: the resolved change_memory_common() pointer has no CFI hash. */
static void __nocfi
frida_kmod_make_data_writable (void)
{
  /* int change_memory_common(unsigned long addr, int numpages,
   *                          pgprot_t set_mask, pgprot_t clear_mask);
   * pgprot_t is a single u64 on arm64, so it passes as an unsigned long. */
  static int (*change_memory_common_impl) (unsigned long, int,
                                           unsigned long, unsigned long);
  unsigned long start, end;

  if (frida_kallsyms_lookup_name_impl == NULL)
    return;

  if (change_memory_common_impl == NULL)
    change_memory_common_impl =
        (void *) frida_kallsyms_lookup_name_impl ("change_memory_common");

  if (change_memory_common_impl == NULL)
    {
      printk (KERN_WARNING "frida: change_memory_common unavailable\\n");
      return;
    }

  /* frida-kmod.c's writable statics live in .data (frida_dev, the link mutex,
   * waitqueues, ...) and in .bss (the two kfifos and the kprobe-resolved
   * pointers).  frida_dev is the lowest and
   * frida_kallsyms_on_each_symbol_impl the highest; mark that span RW. */
  start = (unsigned long) &frida_dev;
  end = (unsigned long) &frida_kallsyms_on_each_symbol_impl;
  if (end < start)
    {
      unsigned long t = start;
      start = end;
      end = t;
    }
  start &= PAGE_MASK;
  end = PAGE_ALIGN (end);

  printk (KERN_INFO "frida: making 0x%lx..0x%lx writable (%lu pages)\\n",
          start, end, (end - start) >> PAGE_SHIFT);
  /* PTE_WRITE (AP[2]) = bit 55, PTE_EXEC/UXN = bit 54.  Setting WRITE and
   * clearing UXN yields a read-write, non-executable mapping. */
  change_memory_common_impl (start, (int) ((end - start) >> PAGE_SHIFT),
                             1UL << 55, 1UL << 54);
}

int
frida_kmod_link_open (void)
{
  int res;

  frida_kmod_make_data_writable ();

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
"""


def patch(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()

    if OLD not in text:
        print(f"ERROR: frida_kmod_link_open block not found in {path}",
              file=sys.stderr)
        return False

    text = text.replace(OLD, NEW, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"patched {path}: added frida_kmod_make_data_writable()")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-kmod-rw.py <frida-kmod.c>", file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
