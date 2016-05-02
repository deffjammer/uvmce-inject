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
#include <linux/version.h>
#include <linux/nsproxy.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <asm/page.h>
#include <asm/uaccess.h>


#include "../include/numatools.h"
#include "../include/uvmce.h" 

//BMC:r001i01b> mmr harp0.0 0x2d0b00 0x8000000100100000
//BMC:r001i01b> mmr harp0.0 0x605d8  0x100
#define UV_MMR_SCRATCH14      0x2d0b00 
#define UV_MMR_SMI_SCRATCH_2  0x605d8 
#define UV_MMR_SMI_WALK_3     0x100 
#define UCE_BITS              0x8000000000000000
#define CE_BITS              0x4000000000000000
#define PS_UCE_BITS           0x7000000000000000

#define SMM_EXT_REQUEST_INJECT_MEM_CE           0x00
#define SMM_EXT_REQUEST_INJECT_MEM_UCE          0x80
#define SMM_EXT_REQUEST_BIOS_TRIGGER_MEM_CE     0x40
#define SMM_EXT_REQUEST_BIOS_TRIGGER_MEM_UCE    0xC0
#define SMM_EXT_REQUEST_INJECT_PATROL_SCRUB_CE  0x60
#define SMM_EXT_REQUEST_INJECT_PATROL_SCRUB_UCE 0x70

MODULE_LICENSE("GPL");
MODULE_INFO(supported, "external");

#define UVMCE_NAME "uvmce"

static int last_pnode = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int uvmce_ioctl(struct inode *, struct file *, unsigned int , unsigned long );
#else
static long uvmce_ioctl(struct file *, unsigned int , unsigned long );
#endif

static struct file_operations uvmce_fops = {
    .owner = THIS_MODULE,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
    .ioctl = uvmce_ioctl,
#else
    .unlocked_ioctl = uvmce_ioctl,
#endif

};


spinlock_t              uvmce_lock; 

/* The register structure for /dev/ex_misc */
static struct miscdevice uvmce_miscdev = {
	MISC_DYNAMIC_MINOR,
	UVMCE_NAME,
	&uvmce_fops,
};
unsigned long uvmce_inject_uce_at_addr(unsigned long phys_addr, int pnode )
{
	unsigned long poisoned_b_addr=-1;
  	//int pnode, node;  
	//pnode = uv_blade_to_pnode(uv_cpu_to_blade_id(cpu));

	//node = cpu_to_node(cpu);
        printk(KERN_INFO "Proc: %s\n", current->comm);
	printk(KERN_INFO "Physical Addr:  %#018lx on node %d\n", phys_addr, pnode);

	poisoned_b_addr = phys_addr | (1UL <<63);
	printk (KERN_INFO "UCE Bit set:    %#018lx \n",poisoned_b_addr ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH14, poisoned_b_addr);
	mb();
	
	printk (KERN_INFO "MMR SCRATCH14:  %#018lx \n",uv_read_global_mmr64(pnode, UV_MMR_SCRATCH14)); 

	uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);
	mb();
	last_pnode=pnode;
	
	return poisoned_b_addr;
} 
unsigned long uvmce_inject_correctable_at_addr(unsigned long phys_addr, int pnode )
{
	unsigned long poisoned_b_addr=-1;
  	//int pnode, node;  
	//pnode = uv_blade_to_pnode(uv_cpu_to_blade_id(cpu));

	//node = cpu_to_node(cpu);
        printk(KERN_INFO "Proc: %s\n", current->comm);
	printk(KERN_INFO "Physical Addr:  %#018lx on node %d\n", phys_addr, pnode);

	poisoned_b_addr = phys_addr | CE_BITS; 
	printk (KERN_INFO "CE Bit set:    %#018lx \n",poisoned_b_addr ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH14, poisoned_b_addr);
	mb();
	
	printk (KERN_INFO "MMR SCRATCH14:  %#018lx \n",uv_read_global_mmr64(pnode, UV_MMR_SCRATCH14)); 

	uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);
	mb();
	last_pnode=pnode;
	
	return poisoned_b_addr;

}unsigned long uvmce_patrol_scrub_uce_inject(unsigned long phys_addr, int pnode )
{
	unsigned long poisoned_b_addr=-1;
  	//int pnode, node;  
	//pnode = uv_blade_to_pnode(uv_cpu_to_blade_id(cpu));

	//node = cpu_to_node(cpu);
        printk(KERN_INFO "Proc: %s\n", current->comm);
	printk(KERN_INFO "Physical Addr:  %#018lx on node %d\n", phys_addr, pnode);

	poisoned_b_addr = phys_addr | PS_UCE_BITS; 
	printk (KERN_INFO "PS UCE Bit set:   %#018lx \n",poisoned_b_addr ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH14, poisoned_b_addr);
	mb();
	
	printk (KERN_INFO "MMR SCRATCH14:  %#018lx \n",uv_read_global_mmr64(pnode, UV_MMR_SCRATCH14)); 

	//uv_write_global_mmr64(pnode, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);
	mb();
	last_pnode=pnode;
	
	return poisoned_b_addr;
}
unsigned long poll_mmr_scratch(void)
{
 	unsigned long read_m;
	read_m = uv_read_global_mmr64(last_pnode, UV_MMR_SCRATCH14);
	printk (KERN_INFO "POLL SCRATCH14: %#018lx \n",read_m ); 
	return read_m;
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

	read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH14);
	printk ("READ1 MMR SCRATCH14  \t%#018lx \n",read_m ); 

	uv_write_global_mmr64(pnode, UV_MMR_SCRATCH14, poisoned_b_addr);
        read_m = uv_read_global_mmr64(pnode, UV_MMR_SCRATCH14);
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
static int uvmce_ioctl(struct inode *i, struct file *f, unsigned int cmd, unsigned long data)
#else
static long uvmce_ioctl(struct file *f, unsigned int cmd, unsigned long data)
#endif
{
        struct err_inj_data eid;
	unsigned long mmr_status;
	int ret = 0; 

	switch (cmd)
	{
		case UVMCE_INJECT_UME:
		    eid.addr = uvmce_inject_ume();
		    ret = copy_to_user((unsigned long *)data, &eid, sizeof(struct err_inj_data));
		    break;
		case UVMCE_INJECT_UCE_AT_ADDR:
                    ret = copy_from_user(&eid, (unsigned long *)data, sizeof(struct err_inj_data));
                    eid.addr = uvmce_inject_uce_at_addr(eid.addr, eid.cpu);
                    ret = copy_to_user((unsigned long *)data, &eid, sizeof(struct err_inj_data));
		    break;
		case UVMCE_PATROL_SCRUB_UCE:
                    ret = copy_from_user(&eid, (unsigned long *)data, sizeof(struct err_inj_data));
                    eid.addr = uvmce_patrol_scrub_uce_inject(eid.addr, eid.cpu);
                    ret = copy_to_user((unsigned long *)data, &eid, sizeof(struct err_inj_data));
		    break;
		case UVMCE_INJECT_CE_AT_ADDR:
                    ret = copy_from_user(&eid, (unsigned long *)data, sizeof(struct err_inj_data));
                    eid.addr = uvmce_inject_correctable_at_addr(eid.addr, eid.cpu);
                    ret = copy_to_user((unsigned long *)data, &eid, sizeof(struct err_inj_data));
		    break;
		case UVMCE_DLOOK:
		    dlook_get_task_map_info((void *) data);
		    break;
		case UVMCE_POLL_SCRATCH14:
		    mmr_status = poll_mmr_scratch();
		    ret = copy_to_user((unsigned long *)data, &mmr_status, sizeof(unsigned long));
		    break;
		default:
		    return -EINVAL;
	}
	 
	    return ret;
}


int 
uvmce_init(void)
{
	int ret;

	/* Create the /dev/uvmce entry */
	if ((ret = misc_register(&uvmce_miscdev)) < 0) {
		printk(KERN_ERR "%s: failed to register device, %d\n",
			UVMCE_NAME, ret);
		return ret;
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

#define is_pte_uc(p)		(pte_val(p) & _PAGE_PCD)
#define nasid_to_cnodeid(n)	n
#define dlook_pfn_to_nid(a)	(pfn_valid(a) ? pfn_to_nid(a) : -1)
#define dlook_pfn_to_pnid(a)	(pfn_valid(a) ? pfn_to_nid(a) : -1)


static page_desc_t *add_pd_hole(page_desc_t *pd, unsigned long bytes, unsigned long *gbytes)
{
	page_desc_t desc = NULL_DESC;

	*gbytes += bytes;
	desc.flags = PD_HOLE;
	desc.pte = bytes;
	*pd = desc;
	return ++pd;
}

/*
 * Convert the memory address part of pteval to the address or
 * node descriptor that is returned to the user.
 */
static inline page_desc_t pteval_to_desc(pte_t pteval, unsigned int flags)
{
	page_desc_t desc = NULL_DESC;
	struct page *page;
	long pfn;

	if (pte_none(pteval))
		return desc;

	desc.flags = flags;
	if (pte_present(pteval)) {
		pfn = pte_pfn(pteval);
		desc.pte = pte_val(pteval);
		desc.pnid = dlook_pfn_to_pnid(pfn);
		desc.nid = dlook_pfn_to_nid(pfn);
		desc.flags |= PD_RAM;
		if (pte_write(pteval))
			desc.flags |= PD_RW;
		if (pte_dirty(pteval))
			desc.flags |= PD_DIRTY;
		if (is_pte_uc(pteval))
			desc.flags |= PD_MA_UC;
		if (pfn_valid(pte_pfn(pteval))) {
			page = pte_page(pteval);
			if (PageReserved(page))
				desc.flags |= PD_RESERVED;
			if (page_count(page) > 1)
				desc.flags |= PD_SHARED;
		}

	} else {
		desc.flags = PD_SWAPPED;
	}
	return desc;
}

static page_desc_t *
dlook_huge_pmd(page_desc_t * pd, page_desc_t * pdend, pmd_t * pmd, unsigned long start,
		unsigned long end, unsigned long *gbytes)
{
	*pd++ = pteval_to_desc(*(pte_t *)pmd, PD_HP_2MB);
	*gbytes += 2 * 1024 * 1024;

	return pd;
}

static page_desc_t *
dlook_huge_pud(page_desc_t * pd, page_desc_t * pdend, pud_t * pud, unsigned long start,
		unsigned long end, unsigned long *gbytes)
{
	*pd++ = pteval_to_desc(*(pte_t *)pud, PD_HP_1GB);
	*gbytes += 1UL * 1024 * 1024 * 1024;

	return pd;
}

/*
 * dlook_pte_range
 *
 * Scan a L1 page table and return info about pages in the requested vaddr range.
 *
 *   Input:
 *	pd	Pointer to next page_descriptor array entry for returning page information
 *	pdend	Points to end of pd buffer array.
 *	pmd	Start of pmd that contains the <start> vaddr
 *	start	Start of vaddr range
 *	size	Size of vaddr range
 *
 *   Returns:
 *	pdend if scan terminated because page_descriptor buffer is full.
 *		OR
 *	pointer to last entry used+1 if scan reached end of range
 *
 *
 */

static page_desc_t *
dlook_pte_range(page_desc_t * pd, page_desc_t * pdend, pmd_t * pmd, unsigned long start,
		unsigned long end, unsigned long *gbytes)
{
	pte_t *pte;

	pte = pte_offset_map(pmd, start);

	/*
	 * If L1 page table is missing, zero out the pd entries & return a
	 * pointer that corresponds to pdend OR the end of the request range,
	 * whichever comes first.
	 */
	if (pmd_none(*pmd))
		return add_pd_hole(pd, end - start, gbytes);

	/*
	 * Return information about each page in the range.
	 */
	do {
		*pd++ = pteval_to_desc(*pte++, 0);
		start += PAGE_SIZE;
		*gbytes += PAGE_SIZE;
	} while (start < end && pd < pdend);

	return pd;
}

/*
 * dlook_pmd_range
 *
 * Scan a L2 page table and return info about each page in the requested vaddr range.
 *
 *   Input:
 *	pd	Pointer to next page_descriptor array entry for returning page information
 *	pdend	Points to end of pd buffer array.
 *	pud	Start of pud that contains the <start> vaddr
 *	start	Start of vaddr range
 *	size	Size of vaddr range
 *
 *   Returns:
 *	pdend if scan terminated because page_descriptor buffer is full.
 *		OR
 *	pointer to last entry used+1 if scan reached end of range
 */
static page_desc_t *
dlook_pmd_range(page_desc_t * pd, page_desc_t * pdend, pud_t * pud, unsigned long start,
		unsigned long end, unsigned long *gbytes)
{
	unsigned long next;
	pmd_t *pmd;

	/*
	 * If L2 page table is missing, zero out the pd entries & return a
	 * pointer that corresponds to pdend OR the end of the request range,
	 * whichever comes first.
	 */
	if (pud_none(*pud))
		return add_pd_hole(pd, end - start, gbytes);

	pmd = pmd_offset(pud, start);
	do {
		next = pmd_addr_end(start, end);
		if (unlikely(pmd_large(*pmd)))
			pd = dlook_huge_pmd(pd, pdend, pmd++, start, next, gbytes);
		else
			pd = dlook_pte_range(pd, pdend, pmd++, start, next, gbytes);
		start = next;
	} while (start < end && pd < pdend);

	return pd;
}


/*
 * dlook_pud_range
 *
 * Scan an L3 page table and return info about each page in the requested vaddr range.
 *
 *   Input:
 *	pd	Pointer to next page_descriptor array entry for returning page information
 *	pdend	Points to end of pd buffer array.
 *	pgd	Start of pgd that contains the <start> vaddr
 *	start	Start of vaddr range
 *	size	Size of vaddr range
 *
 *   Returns:
 *	pdend if scan terminated because page_descriptor buffer is full.
 *		OR
 *	pointer to last entry used+1 if scan reached end of range
 */
static page_desc_t *
dlook_pud_range(page_desc_t * pd, page_desc_t * pdend, pgd_t * pgd, unsigned long start,
		unsigned long end, unsigned long *gbytes)
{
	pud_t *pud;
	unsigned long next;

	if (pgd_none(*pgd))
		return add_pd_hole(pd, end - start, gbytes);

	pud = pud_offset(pgd, start);
	do {
		next = pud_addr_end(start, end);
		if (unlikely(pud_large(*pud)))
			pd = dlook_huge_pud(pd, pdend, pud++, start, next, gbytes);
		else
			pd = dlook_pmd_range(pd, pdend, pud++, start, next, gbytes);
		start = next;
	} while (start < end && pd < pdend);

	return pd;
}


/*
 * dlook_get_task_map_info
 *
 * Process the user request to obtain data about pages in an address space.
 */
int
dlook_get_task_map_info(void *data)
{
	int err = 0;
	struct dlook_get_map_info req;
	page_desc_t *pdbuf, *pd, *pdend;
	struct task_struct *task;
	struct mm_struct *mm = 0;
	struct vm_area_struct *vma;
	pgd_t *pgd;
	unsigned long start, end, next, count, gbytes;

	if (copy_from_user(&req, data, sizeof (req)))
		return -EFAULT;

	start = req.start_vaddr;
	end = req.end_vaddr;

	//printk ("Virt Start: \t%#018lx End: \t%#018lx\n",req.start_vaddr, req.end_vaddr); 
	if ((pdbuf = (page_desc_t *) __get_free_page(GFP_KERNEL)) == NULL) {
		err = -ENOMEM;
		goto done;
	}
	pdend = pdbuf + (PAGE_SIZE / sizeof (page_desc_t));

	rcu_read_lock();
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
	task = pid_task(find_pid_ns(req.pid, current->nsproxy->pid_ns_for_children), PIDTYPE_PID);
#else
	task = pid_task(find_pid_ns(req.pid, current->nsproxy->pid_ns), PIDTYPE_PID);
#endif
	if (task) {
		task_lock(task);
		mm = task->mm;
		if (mm)
			atomic_inc(&mm->mm_users);
		task_unlock(task);
	} else {
		err = -ESRCH;
	}
	rcu_read_unlock();
	if (!mm)
		goto done;

	vma = find_vma(mm, start);
	while (!err && start < end) {
		pd = pdbuf;
		down_read(&mm->mmap_sem);
		pgd = pgd_offset(mm, start);

		while (start < end && pd < pdend) {
			gbytes = 0;
			next = pgd_addr_end(start, end);
			pd = dlook_pud_range(pd, pdend, pgd++, start, next, &gbytes);
			start += gbytes;
		}
		up_read(&mm->mmap_sem);

		count = pd - pdbuf;
		if (copy_to_user(req.pd, pdbuf, count * sizeof (*pd)))
			err = -EFAULT;
		req.pd += count;
	}
	mmput(mm);

done:
	free_page((unsigned long) pdbuf);
	//printk("Done: copy to user..Virt Start: \t%#018lx End: \t%#018lx\n",req.start_vaddr, req.end_vaddr); 
	if (copy_to_user(data, &req, sizeof (req)))
		  err = -EFAULT;
	return err;
}

module_init(uvmce_init);
module_exit(uvmce_exit);
