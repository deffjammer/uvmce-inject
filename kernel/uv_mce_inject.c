/*
 *  Copyright (c) 2007 - 2010 Silicon Graphics, Inc.
 *  All rights reserved.
 *
 *  Derek L. Fults <dfults@sgi.com
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/bootmem.h>              /* max_low_pfn                  */
#include <linux/version.h>
#include <linux/ioctl.h>                                                   
#include <linux/io.h>                                                   
#include <asm/pgtable.h>
#include <asm/delay.h>
#include <asm/page_types.h>
#include <asm/uv/uv.h>
#include <asm/uv/uv_hub.h>
#include <asm/uv/uv_mmrs.h>

#include "../include/uvmce.h" 

//BMC:r001i01b> mmr harp0.0 0x2d0b00 0x8000000100100000
//BMC:r001i01b> mmr harp0.0 0x605d8  0x100
#define UV_MMR_SCRATCH_1      0x2d0b00 
#define UV_MMR_SMI_SCRATCH_2  0x605d8 
#define UV_MMR_SMI_WALK_3     0x100 
#define POISON_BIT            0x8000000000000000
MODULE_LICENSE("GPL");
MODULE_INFO(supported, "external");

#define UVMCE_NAME "uvmce"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int uvmce_ioctl(struct inode *, struct file *, unsigned int , unsigned long );
#else
static long uvmce_ioctl(struct file *, unsigned int , unsigned long );
#endif
static int mce_mmap(struct file *, struct vm_area_struct *);

static struct file_operations uvmce_fops = {
    .owner = THIS_MODULE,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
    .ioctl = uvmce_ioctl,
#else
    .unlocked_ioctl = uvmce_ioctl,
#endif
    .mmap = mce_mmap,

};


spinlock_t              uvmce_lock; 

/* The register structure for /dev/ex_misc */
static struct miscdevice uvmce_miscdev = {
	MISC_DYNAMIC_MINOR,
	UVMCE_NAME,
	&uvmce_fops,
};


/**
 * uv_mmtimer_mmap - maps the clock's registers into userspace
 * @file: file structure for the device
 * @vma: VMA to map the registers into
 *
 * Calls remap_pfn_range() to map the clock's registers into
 * the calling process' address space.
 */
static int mce_mmap(struct file *file, struct vm_area_struct *vma)
{
#if 0
        unsigned long uv_mmtimer_addr;

        if (vma->vm_end - vma->vm_start != PAGE_SIZE)
                return -EINVAL;

        if (vma->vm_flags & VM_WRITE)
                return -EPERM;

        if (PAGE_SIZE > (1 << 16))
                return -ENOSYS;

        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

        uv_mmtimer_addr = UV_LOCAL_MMR_BASE | UVH_RTC;
        uv_mmtimer_addr &= ~(PAGE_SIZE - 1);
        uv_mmtimer_addr &= 0xfffffffffffffffUL;

        if (remap_pfn_range(vma, vma->vm_start, uv_mmtimer_addr >> PAGE_SHIFT,
                                        PAGE_SIZE, vma->vm_page_prot)) {
                printk(KERN_ERR "remap_pfn_range failed in uv_mmtimer_mmap\n");
                return -EAGAIN;
        }
#endif 
        return 0;
}


static bool low_pfn(unsigned long pfn)
{
        return 1;
        //return pfn < max_low_pfn;
}

int uvmce_inject_ume_at_addr(unsigned long address, unsigned long length, int cpu)
{
	int ret = 0;
	unsigned long phys_addr, poisoned_b_addr;
 	unsigned long read_m;
  	int pnode, node;  
	pgd_t *base = __va(read_cr3());
        pgd_t *pgd = &base[pgd_index(address)];
        pmd_t *pmd;
        pte_t *pte;

	//pgd ->L3 pud->L2 pmd-> L1 pte
	pnode = uv_blade_to_pnode(uv_cpu_to_blade_id(cpu));
	node = cpu_to_node(cpu);
	printk("cpu %d, pnode %d, node %d\n", cpu,pnode, node);
	printk("user addr 0x%lx\n", address);

        pmd = pmd_offset(pud_offset(pgd, address), address);
        printk(KERN_CONT "*pde = 0x%0*Lx\n", (int)(sizeof(*pmd) * 2), (u64)pmd_val(*pmd));
        printk(KERN_CONT "*pde = %#018llx\n", (unsigned long long)pmd_val(*pmd));

        /*
         * We must not directly access the pte in the highpte
         * case if the page table is located in highmem.
         * And let's rather not kmap-atomic the pte, just in case
         * it's allocated already:
         */
        if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd))
                goto out;

        pte = pte_offset_kernel(pmd, address);
        printk("Proc: %s\nphys: %#018llx\n", current->comm,
				(PHYSICAL_PAGE_MASK & (long long)pmd_val(*pmd)));
 	printk("*pte = 0x%0*Lx\n", (int)(sizeof(*pte) * 2), (u64)pte_val(*pte));
	
	phys_addr = PHYSICAL_PAGE_MASK & (long long)pte_val(*pte);
	printk ("Physical \t%#018lx \n",phys_addr); 

	phys_addr |= (1UL <<63);
	poisoned_b_addr = phys_addr | (1UL <<63);
	printk ("Poison PB  \t%#018lx \n",poisoned_b_addr ); 

	read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH_1);
	printk ("READ1 MMR  \t%#018lx \n",read_m ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH_1, poisoned_b_addr);
        read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH_1);
	printk ("READ2 MMR  \t%#018lx \n",read_m ); 
	uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);

out:
	
	return ret;
} 
struct poison_st_t {
	//struct page *s_page;
	unsigned long vaddr;
};
struct poison_st_t *ps_addr[1]; 
#if 1
unsigned long uvmce_inject_ume(void)
{

  	int pnode, node;  
	int cpu = 10;
	unsigned long phys_addr, poisoned_b_addr;
 	unsigned long read_m;
	struct poison_st_t *poison_st;
	unsigned long ret_addr;
	size_t dsize;

 	pnode = uv_blade_to_pnode(uv_cpu_to_blade_id(cpu));
	node = cpu_to_node(cpu);
	printk("cpu %d, pnode %d, node %d\n", cpu,pnode, node);
 	dsize = (sizeof(struct poison_st_t) * (sizeof(unsigned long)));
        poison_st = kmalloc_node(dsize, GFP_KERNEL, node);

	printk ("Virt Alcd \t%#lx \n", (unsigned long)poison_st); 
	//memset(poison_st, 0, dsize);
	poison_st->vaddr = 0x00000001;
	//printk ("Std vaddr \t%#lx \n", poison_st->vaddr); 

	phys_addr = virt_to_phys(poison_st);
	ret_addr = phys_addr;
	printk ("Physical \t%#018lx \n",phys_addr); 

	phys_addr |= (1UL <<63);
	poisoned_b_addr = phys_addr | (1UL <<63);
	printk ("Poison PB  \t%#018lx \n",poisoned_b_addr ); 

	read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH_1);
	printk ("READ1 MMR  \t%#018lx \n",read_m ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH_1, poisoned_b_addr);
        read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH_1);
	printk ("READ2 MMR  \t%#018lx \n",read_m ); 
	uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);

	mb();
	poison_st->vaddr = 0x00000004;
	printk ("Std vaddr \t%#lx \n", poison_st->vaddr); 
	memset(poison_st, 0, dsize);
	mb();
	
	kfree(poison_st);
	return ret_addr;

}
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int uvmce_ioctl(struct inode *i, struct file *f, unsigned int cmd, unsigned long arg)
#else
static long uvmce_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
#endif
{
        struct err_inj_data eid;
	int ret = 0; 

	switch (cmd)
	{
		case UVMCE_INJECT_UME:
		    printk("UVMCE_INJECT_UME\n");
		    eid.addr = uvmce_inject_ume();
		    ret = copy_to_user((unsigned long *)arg, &eid, sizeof(struct err_inj_data));
		    break;
		case UVMCE_INJECT_UME_AT_ADDR:
		    printk("UVMCE_INJECT_UME_AT_ADDR\n");
		    ret = copy_from_user(&eid, (unsigned long *)arg, sizeof(struct err_inj_data));
		    uvmce_inject_ume_at_addr(eid.addr, eid.length, eid.cpu);
		    break;
		default:
		    return -EINVAL;
	}
	 
	    return ret;
}


int 
uvmce_init(void)
{
	int res;

	/* Create the /dev/uvmce entry */
	if ((res = misc_register(&uvmce_miscdev)) < 0) {
		printk(KERN_ERR "%s: failed to register device, %d\n",
			UVMCE_NAME, res);
		return res;
	}

	printk(KERN_INFO "init\n");
	return 0;
}
void
uvmce_exit(void)
{
	misc_deregister(&uvmce_miscdev);
	printk(KERN_INFO "exit\n");
}

module_init(uvmce_init);
module_exit(uvmce_exit);
