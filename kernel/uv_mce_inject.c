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
#include <linux/version.h>
#include <linux/ioctl.h>                                                   
#include <linux/io.h>                                                   
#include <asm/pgtable.h>
#include <asm/delay.h>
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

static struct file_operations uvmce_fops = {
    .owner = THIS_MODULE,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
    .ioctl = uvmce_ioctl
#else
    .unlocked_ioctl = uvmce_ioctl
#endif
};


spinlock_t              uvmce_lock; 

/* The register structure for /dev/ex_misc */
static struct miscdevice uvmce_miscdev = {
	MISC_DYNAMIC_MINOR,
	UVMCE_NAME,
	&uvmce_fops,
};

int uvmce_inject_ume_at_addr(unsigned long addr, unsigned long length)
{

#if 0
        //ulong bits;
 	//u64 type;
        //int bitcount;
        ulong mask;
        int ret = 0;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        unsigned long physaddr;
	
	//pgd ->L3 pud->L2 pmd-> L1 pte

        pgd = pgd_offset(current->mm, addr);
        if(!pgd_present(*pgd)) {
                printk("ERR_INJ: pgd not found for va %lx\n", addr);
                return -EINVAL;
        }

        pmd = pmd_offset(pgd, addr);

        if (!pmd_present(*pmd)) {
                printk("ERR_INJ: pmd not found for va %lx\n", addr);
                return -EINVAL;
        }

        pte = pte_offset_kernel(pmd, addr);
        if (!pte_present(*pte)) {
                printk("ERR_INJ: pte not found for va %lx\n", addr);
                return -EINVAL;
        }
        physaddr = page_address(pte_page(*pte)) + (addr & (PAGE_SIZE-1));
        printk("ERR_INJ:  addr = %lx, paddr = 0x%016lx *pte = %lx\n",
                       addr,physaddr,  *(u64 *)pte);

	printk ("Physical \t%#018lx \n",virt_to_phys(physaddr)); 
//printk("ERR_INJ: type = %d, addr = %lx, bits = %lx, paddr = 0x%016lx *pte = %lx\n",
         //               type, addr, bits, (u64) ia64_tpa(physaddr),
          //              *(u64 *)pte);

	return ret;
#endif
	return 0;
} 
#if 1
int uvmce_inject_ume(void)
{
  	int pnode, nid, bid=0;
        unsigned long flags;
	unsigned long *poison_memory;
	unsigned long pm;
 	unsigned long read_m;
	//unsigned long bus;
        //int pnode = uv_blade_to_pnode(gru->gs_blade_id);

	pnode = uv_blade_to_pnode(bid);

	poison_memory = kmalloc(0x10, GFP_KERNEL);
	printk ("Virt Alcd \t%#lx \n", (unsigned long)poison_memory); 
	pm = virt_to_phys(poison_memory);
	printk ("Physical \t%#018lx \n",pm); 
	//pm = pm >> PAGE_SHIFT;
	//printk ("Phys shift \t%#018lx \n",pm); 

	pm |= (1UL <<63);
	printk ("Poison PB  \t%#018lx \n",pm ); 

        spin_lock_irqsave(&uvmce_lock, flags);
       	read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ1 MMR  \t%#018lx \n",read_m ); 

 	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH_1, pm);

       	read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ2 MMR  \t%#018lx \n",read_m ); 

        uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);

        spin_unlock_irqrestore(&uvmce_lock, flags);

	read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ3 MMR  \t%#018lx \n",read_m ); 


	//mb();
//	memset(poison_memory, 1, 0x10);
	//mb();
	//kfree(poison_memory);

	return 0;

}
#endif
#if 0
int uvmce_inject_ume(void)
{

  	int pnode, nid, i, bid=1;
//	int order = get_order(sizeof(struct_page));
	unsigned long *virt_addr, phys_addr;
	struct page *page;
 	unsigned long read_m;

   	pnode = uv_blade_to_pnode(bid);
        nid = uv_blade_to_memory_nid(bid);/* -1 if no memory on blade */
        page = alloc_pages_node(nid, GFP_KERNEL,0);
	virt_addr = page_address(page);
	printk ("Virt Alcd \t%#lx \n", virt_addr); 
	phys_addr = virt_to_phys(virt_addr);
	printk ("Physical \t%#018lx \n",phys_addr); 

//	memset(page, 0, sizeof(struct page));

	phys_addr |= (1UL <<63);
	read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ1 MMR  \t%#018lx \n",read_m ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH_1, phys_addr);
        read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ2 MMR  \t%#018lx \n",read_m ); 

	uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);

	read_m = uv_read_local_mmr(UV_MMR_SCRATCH_1);
	printk ("READ3 MMR  \t%#018lx \n",read_m ); 


	//free_pages(page, 0);

	return 0;

}
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int uvmce_ioctl(struct inode *i, struct file *f, unsigned int cmd, unsigned long arg)
#else
static long uvmce_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
#endif
{
        struct err_inj_data eid;
	int ret = -1; 

	switch (cmd)
	{
		case UVMCE_INJECT_UME:
		    printk("UVMCE_INJECT_UME\n");
		    uvmce_inject_ume();
		    break;
		case UVMCE_INJECT_UME_AT_ADDR:
		    printk("UVMCE_INJECT_UME_AT_ADDR\n");
		    ret = copy_from_user(&eid, (unsigned long *)arg, sizeof(struct err_inj_data));
		    uvmce_inject_ume_at_addr(eid.addr, eid.length);
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
