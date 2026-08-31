// SPDX-License-Identifier: GPL-2.0
/*
 * panic_capture.c - capture kernel die/panic info to a file.
 *
 * Registers a die notifier (Oops/BUG: has pt_regs) and a panic notifier
 * (panic: has the message).  On a crash it appends the trap string, the
 * PC/LR/SP + first 8 GPRs, %pS symbols and the panic message to
 * /data/local/tmp/panic_dump.txt, so a kernel panic that kills the device
 * (no pstore) can still be diagnosed after reboot.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>

#define DUMP_PATH "/data/local/tmp/panic_dump.txt"

static struct file *dump_file;
static unsigned long die_count;

static void dump_write(const char *s, long len)
{
    loff_t pos = 0;

    if (dump_file && !IS_ERR(dump_file))
        kernel_write(dump_file, s, len, &pos);
}

static int die_handler(struct notifier_block *nb, unsigned long val, void *arg)
{
    struct die_args *args = arg;
    struct pt_regs *regs = args ? args->regs : NULL;
    char buf[1536];
    int n = 0;

    (void)nb;
    die_count++;

    n += scnprintf(buf + n, sizeof(buf) - n,
                   "\n=== die #%lu (val=0x%lx) comm=%s pid=%d ===\n",
                   die_count, val, current->comm, current->pid);
    n += scnprintf(buf + n, sizeof(buf) - n, "trap: %s\n",
                   args && args->str ? args->str : "(null)");

    if (regs) {
        int i;

        n += scnprintf(buf + n, sizeof(buf) - n,
                       "pc=%pS  lr=%pS  sp=0x%016llx\n",
                       (void *)regs->pc, (void *)regs->regs[30],
                       (unsigned long long)regs->sp);
        n += scnprintf(buf + n, sizeof(buf) - n,
                       "pc=0x%016llx lr=0x%016llx\n",
                       (unsigned long long)regs->pc,
                       (unsigned long long)regs->regs[30]);
        for (i = 0; i < 8; i++)
            n += scnprintf(buf + n, sizeof(buf) - n,
                           "x%-2d=0x%016llx\n", i,
                           (unsigned long long)regs->regs[i]);
    }

    dump_write(buf, n);
    if (dump_file && !IS_ERR(dump_file))
        vfs_fsync(dump_file, 0);

    return NOTIFY_DONE;
}

static int panic_handler(struct notifier_block *nb, unsigned long val,
                         void *buf)
{
    char line[512];
    int n;

    (void)nb;
    (void)val;
    n = scnprintf(line, sizeof(line),
                  "\n=== PANIC comm=%s pid=%d ===\n%s\n",
                  current->comm, current->pid, (const char *)buf);
    dump_write(line, n);
    if (dump_file && !IS_ERR(dump_file))
        vfs_fsync(dump_file, 0);
    return NOTIFY_DONE;
}

static struct notifier_block die_nb = {
    .notifier_call = die_handler,
};
static struct notifier_block panic_nb = {
    .notifier_call = panic_handler,
};

static int __init panic_capture_init(void)
{
    dump_file = filp_open(DUMP_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (IS_ERR(dump_file)) {
        pr_err("panic_capture: cannot open %s (err %ld)\n", DUMP_PATH,
               PTR_ERR(dump_file));
        dump_file = NULL;
    } else {
        pr_info("panic_capture: dump file %s opened\n", DUMP_PATH);
    }

    register_die_notifier(&die_nb);
    atomic_notifier_chain_register(&panic_notifier_list, &panic_nb);
    pr_info("panic_capture: installed (die + panic notifiers)\n");
    return 0;
}

static void __exit panic_capture_exit(void)
{
    atomic_notifier_chain_unregister(&panic_notifier_list, &panic_nb);
    unregister_die_notifier(&die_nb);
    if (dump_file && !IS_ERR(dump_file))
        filp_close(dump_file, NULL);
    pr_info("panic_capture: removed\n");
}

module_init(panic_capture_init);
module_exit(panic_capture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("capture kernel die/panic info to a file");
