// SPDX-License-Identifier: GPL-2.0
/*
 * rwtest.c — probe module .data/.bss read-only state.
 *
 * Load with `ksud insmod rwtest.ko`: ksud resolves the unexported symbols
 * below via kallsyms at load time (same as kp_rmap_guard), so we reference
 * init_mm / set_memory_* directly instead of going through kprobe (which
 * fails for blacklisted symbols like init_mm).
 *
 * We only READ the PTE RDONLY bit (arm64 AP[2] == bit 7), so a read-only
 * page never faults.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("probe module data/bss RO state");

static int data_var = 0x11223344;   /* .data */
static int bss_var;                  /* .bss */

/* Unexported; ksud insmod resolves these via kallsyms. */
extern struct mm_struct init_mm;
extern int set_memory_rw(unsigned long addr, int numpages);
extern int set_memory_ro(unsigned long addr, int numpages);
extern int set_memory_nx(unsigned long addr, int numpages);

/* arm64 PTE_RDONLY is AP[2] == bit 7. */
static int page_is_ro(unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = init_mm.pgd + pgd_index(addr);
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
    pr_info("rwtest: init_mm=%px rw=%px ro=%px nx=%px\n",
        &init_mm, set_memory_rw, set_memory_ro, set_memory_nx);

    pr_info("rwtest: data=%px ro=%d  bss=%px ro=%d\n",
        (void *)data_addr, page_is_ro(data_addr),
        (void *)bss_addr, page_is_ro(bss_addr));

    /* Reproduce make_data_writable(): set_memory_rw over non-text region. */
    start = (unsigned long)cl->base + cl->text_size;
    end = (unsigned long)cl->base + cl->size;
    start &= PAGE_MASK;
    end = PAGE_ALIGN(end);

    ret = set_memory_rw(start, (int)((end - start) >> PAGE_SHIFT));
    pr_info("rwtest: set_memory_rw(0x%lx..0x%lx) ret=%d\n", start, end, ret);
    pr_info("rwtest: after rw: data ro=%d  bss ro=%d\n",
        page_is_ro(data_addr), page_is_ro(bss_addr));

    /* Reproduce protect(): set_memory_ro on the data page, then re-check. */
    ret = set_memory_ro((unsigned long)data_addr & PAGE_MASK, 1);
    pr_info("rwtest: set_memory_ro(data page) ret=%d  data ro=%d\n",
        ret, page_is_ro(data_addr));

    /* Re-apply rw and confirm once more (the frida protect() recovery path). */
    ret = set_memory_rw(start, (int)((end - start) >> PAGE_SHIFT));
    pr_info("rwtest: set_memory_rw #2 ret=%d  data ro=%d  bss ro=%d\n",
        ret, page_is_ro(data_addr), page_is_ro(bss_addr));

    return 0;
}

static void __exit rwtest_exit(void)
{
    pr_info("rwtest: exit\n");
}

module_init(rwtest_init);
module_exit(rwtest_exit);
