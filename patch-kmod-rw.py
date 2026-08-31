#!/usr/bin/env python3
"""Re-mark frida-kmod.c's .data/.bss writable after the module loads.

On this device (KernelSU LKM + a hardened OnePlus GKI build with
CONFIG_STRICT_MODULE_RWX), the module's writable tail is left read-only once
init_module returns.  The agent's worker thread keeps writing to frida-kmod.c
statics after that point (kfifo, miscdevice, waitqueue, ...), which panics with
"Unable to handle kernel write to read-only memory" inside __kfifo_alloc.

frida-kmod.c already resolves set_memory_rw() via kprobe in
frida_resolve_kallsyms(); use it to flip the core layout's data/bss tail back to
RW right before the first post-init write to it.
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
 * Re-mark the writable tail of the core layout RW before touching it. */
static void
frida_kmod_make_data_writable (void)
{
  void *core_base;
  unsigned int core_size, ro_after_init_size;

  if (frida_set_memory_rw_impl == NULL)
    return;

  core_base = THIS_MODULE->core_layout.base;
  core_size = THIS_MODULE->core_layout.size;
  ro_after_init_size = THIS_MODULE->core_layout.ro_after_init_size;

  frida_set_memory_rw_impl ((unsigned long) core_base + ro_after_init_size,
                            (core_size - ro_after_init_size + PAGE_SIZE - 1) >> PAGE_SHIFT);
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
