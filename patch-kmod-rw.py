#!/usr/bin/env python3
"""Re-mark frida-kmod.c's .data/.bss writable before every write to them.

On this device (KernelSU LKM + a hardened OnePlus GKI build with
CONFIG_STRICT_MODULE_RWX), the module's .data/.bss is left read-only once
init_module returns, and -- even after set_memory_rw() flips it back -- the
pages get flipped to read-only again (an Android vendor hook on
set_memory_ro/set_memory_rw re-applies the policy whenever Gum's interceptor
protects code).  The worker thread keeps writing frida-kmod.c statics long
after that (kfifo, miscdevice, waitqueue, mutex, atomic, ...), which panics
with "Unable to handle kernel write to read-only memory" in __kfifo_alloc /
__kfifo_out.

So re-flip the pages with set_memory_rw() (reliable here -- kfifo_alloc
succeeded once it ran) at the top of every entry point that writes those
statics.  The span is delimited by the symbol addresses of frida_dev (.data)
and frida_kallsyms_on_each_symbol_impl (.bss).
"""

import sys


# Insert the helper + the link_open call.  This is the primary anchor.
LINK_OPEN_OLD = """int
frida_kmod_link_open (void)
{
  int res;

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
"""

LINK_OPEN_NEW = """/* KernelSU LKM (and this hardened kernel) leaves the module's .data/.bss
 * read-only, and Gum's code protection can flip them back to read-only again
 * later.  Re-mark the pages holding frida-kmod.c's writable statics RW before
 * touching them.  __nocfi: set_memory_rw() is a kprobe-resolved pointer whose
 * type carries no CFI hash. */
static void __nocfi
frida_kmod_make_data_writable (void)
{
  unsigned long start, end;

  if (frida_set_memory_rw_impl == NULL)
    return;

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

  frida_set_memory_rw_impl (start, (int) ((end - start) >> PAGE_SHIFT));
}

int
frida_kmod_link_open (void)
{
  int res;

  frida_kmod_make_data_writable ();

  res = kfifo_alloc (&frida_to_client, FRIDA_LINK_CAPACITY, GFP_KERNEL);
"""

# Every other entry point that writes a static gets a call right after its
# local declarations.  Anchored on the exact decl + first statement.
CALL_INSERTS = [
    (
        """frida_kmod_link_send (const void * data,
                      size_t size)
{
  unsigned int written;
""",
        """frida_kmod_link_send (const void * data,
                      size_t size)
{
  unsigned int written;

  frida_kmod_make_data_writable ();
""",
    ),
    (
        """frida_kmod_link_recv (void * data,
                      size_t size)
{
  unsigned int n;
""",
        """frida_kmod_link_recv (void * data,
                      size_t size)
{
  unsigned int n;

  frida_kmod_make_data_writable ();
""",
    ),
    (
        """frida_kmod_link_close (void)
{
  if (!frida_link_registered)
""",
        """frida_kmod_link_close (void)
{
  frida_kmod_make_data_writable ();

  if (!frida_link_registered)
""",
    ),
    (
        """frida_dev_open (struct inode * inode,
                struct file * file)
{
  if (atomic_cmpxchg (&frida_client_count, 0, 1) != 0)
""",
        """frida_dev_open (struct inode * inode,
                struct file * file)
{
  frida_kmod_make_data_writable ();

  if (atomic_cmpxchg (&frida_client_count, 0, 1) != 0)
""",
    ),
    (
        """frida_dev_release (struct inode * inode,
                   struct file * file)
{
  mutex_lock (&frida_link_mutex);
""",
        """frida_dev_release (struct inode * inode,
                   struct file * file)
{
  frida_kmod_make_data_writable ();

  mutex_lock (&frida_link_mutex);
""",
    ),
    (
        """  unsigned int copied;
  int res;

  while (kfifo_is_empty (&frida_to_client))
""",
        """  unsigned int copied;
  int res;

  frida_kmod_make_data_writable ();

  while (kfifo_is_empty (&frida_to_client))
""",
    ),
    (
        """  unsigned int copied;
  int res;

  mutex_lock (&frida_link_mutex);
  res = kfifo_from_user (&frida_from_client, buffer, size, &copied);
""",
        """  unsigned int copied;
  int res;

  frida_kmod_make_data_writable ();

  mutex_lock (&frida_link_mutex);
  res = kfifo_from_user (&frida_from_client, buffer, size, &copied);
""",
    ),
    (
        """  __poll_t events = EPOLLOUT | EPOLLWRNORM;

  poll_wait (file, &frida_readable_wq, wait);
""",
        """  __poll_t events = EPOLLOUT | EPOLLWRNORM;

  frida_kmod_make_data_writable ();

  poll_wait (file, &frida_readable_wq, wait);
""",
    ),
]


def patch(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()

    if LINK_OPEN_OLD not in text:
        print(f"ERROR: frida_kmod_link_open block not found in {path}",
              file=sys.stderr)
        return False
    text = text.replace(LINK_OPEN_OLD, LINK_OPEN_NEW, 1)

    missed = []
    for old, new in CALL_INSERTS:
        if old not in text:
            missed.append(old.splitlines()[0])
            continue
        text = text.replace(old, new, 1)

    if missed:
        print(f"WARNING: {len(missed)} insert anchors not found in {path}:",
              file=sys.stderr)
        for m in missed:
            print(f"  - {m}", file=sys.stderr)

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"patched {path}: frida_kmod_make_data_writable() + call sites")
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
