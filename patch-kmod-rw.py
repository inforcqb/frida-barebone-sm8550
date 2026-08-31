#!/usr/bin/env python3
"""Re-mark frida-kmod.c's .data/.bss writable after the module loads.

On this device (KernelSU LKM + a hardened OnePlus GKI build with
CONFIG_STRICT_MODULE_RWX), the module's writable tail is left read-only once
init_module returns.  The agent's worker thread keeps writing to frida-kmod.c
statics after that point (kfifo, miscdevice, waitqueue, ...), which panics with
"Unable to handle kernel write to read-only memory" inside __kfifo_alloc.

frida-kmod.c already resolves set_memory_rw() via kprobe in
frida_resolve_kallsyms(); use it to flip the pages holding the module's writable
statics back to RW right before the first post-init write to them.

We use the symbol addresses directly instead of core_layout.ro_size /
ro_after_init_size: on this kernel the latter is 0 (no .data..ro_after_init
section), and ro_size turned out not to cover the tail reliably either.
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
 * __nocfi: set_memory_rw() is a kprobe-resolved pointer, whose type does not
 * carry a CFI hash, so the indirect call must bypass CFI. */
static void __nocfi
frida_kmod_make_data_writable (void)
{
  unsigned long start, end;

  if (frida_set_memory_rw_impl == NULL)
    {
      printk (KERN_WARNING "frida: set_memory_rw unavailable\\n");
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
  frida_set_memory_rw_impl (start, (end - start) >> PAGE_SHIFT);
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
