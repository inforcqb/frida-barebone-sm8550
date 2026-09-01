// SPDX-License-Identifier: GPL-2.0
/*
 * rwtest.c — probe module .data/.bss read-only state on this kernel.
 *
 * Load with `ksud insmod rwtest.ko` (kallsyms access) and read dmesg.  No
 * writes to the probed statics, so nothing panics: we only read the PTE
 * RDONLY bit (arm64 AP[2] == bit 7) and report set_memory_* return values.
 *
 * Mirrors frida-kmod.c's make_data_writable(): resolve unexported symbols via
 * kprobe, then set_memory_rw() over base+text_size .. base+size.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("probe module data/bss RO state");

static int data_var = 0x11223344;   /* .data */
static int bss_var;                  /* .bss */

static int (*p_set_memory_rw)(unsigned long, int);
static int (*p_set_memory_ro)(unsigned long, int);
static int (*p_set_memory_nx)(unsigned long, int);

static void *resolve_unexported(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    void *addr;

    if (register_kprobe(&kp) < 0)
        return NULL;
    addr = kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/* arm64 PTE_RDONLY is AP[2] == bit 7. */
static int page_is_ro(unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset_k(addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -1;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -1;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return -1;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -1;
    pte = pte_offset_kernel(pmd, addr);
    if (pte == NULL)
        return -1;

    return (pte_val(*pte) >> 7) & 1;
}

static int __init rwtest_init(void)
{
    unsigned long data_addr = (unsigned long)&data_var;
    unsigned long bss_addr = (unsigned long)&bss_var;
    struct module_layout *cl = &THIS_MODULE->core_layout;
    unsigned long start, end;
    int ret;

    pr_info("rwtest: base=%px size=0x%x text=0x%x ro=0x%x ro_after=0x%x\n",
        cl->base, cl->size, cl->text_size, cl->ro_size,
        cl->ro_after_init_size);
    pr_info("rwtest: data=%px ro=%d  bss=%px ro=%d\n",
        (void *)data_addr, page_is_ro(data_addr),
        (void *)bss_addr, page_is_ro(bss_addr));

    p_set_memory_rw = resolve_unexported("set_memory_rw");
    p_set_memory_ro = resolve_unexported("set_memory_ro");
    p_set_memory_nx = resolve_unexported("set_memory_nx");
    pr_info("rwtest: rw=%px ro=%px nx=%px\n",
        p_set_memory_rw, p_set_memory_ro, p_set_memory_nx);

    /* Reproduce make_data_writable(): set_memory_rw over non-text region. */
    start = (unsigned long)cl->base + cl->text_size;
    end = (unsigned long)cl->base + cl->size;
    start &= PAGE_MASK;
    end = PAGE_ALIGN(end);

    if (p_set_memory_rw) {
        ret = p_set_memory_rw(start, (int)((end - start) >> PAGE_SHIFT));
        pr_info("rwtest: set_memory_rw(0x%lx..0x%lx) ret=%d\n", start, end, ret);
    } else {
        pr_info("rwtest: set_memory_rw NOT resolved\n");
    }
    pr_info("rwtest: after rw: data ro=%d  bss ro=%d\n",
        page_is_ro(data_addr), page_is_ro(bss_addr));

    /* Reproduce protect(): set_memory_ro on the data page, then re-check. */
    if (p_set_memory_ro) {
        ret = p_set_memory_ro((unsigned long)data_addr & PAGE_MASK, 1);
        pr_info("rwtest: set_memory_ro(data page) ret=%d  data ro=%d\n",
            ret, page_is_ro(data_addr));
    }

    /* Re-apply rw and confirm once more (the frida protect() recovery path). */
    if (p_set_memory_rw) {
        ret = p_set_memory_rw(start, (int)((end - start) >> PAGE_SHIFT));
        pr_info("rwtest: set_memory_rw #2 ret=%d  data ro=%d  bss ro=%d\n",
            ret, page_is_ro(data_addr), page_is_ro(bss_addr));
    }

    return 0;
}

static void __exit rwtest_exit(void)
{
    pr_info("rwtest: exit\n");
}

module_init(rwtest_init);
module_exit(rwtest_exit);
