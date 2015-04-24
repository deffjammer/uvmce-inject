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
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/ioctl.h>                                                   
#include <linux/io.h>                                                   
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
//    .open = my_open,
//    .release = my_close,
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


int uvmce_inject_ume(void)
{
        unsigned long flags;
	unsigned long *poison_memory;
	unsigned long pm;
	//unsigned long bus;
        //int pnode = uv_blade_to_pnode(gru->gs_blade_id);
	poison_memory = kmalloc(4096, GFP_USER);
	printk ("Virt Alcd \t%#lx \n", poison_memory); 
	pm = virt_to_phys(poison_memory);
	printk ("Physical \t%#018lx \n",pm); 
	//pm = pm >> PAGE_SHIFT;
	//printk ("Phys shift \t%#018lx \n",pm); 

	pm |= (1UL <<63);
	printk ("Poison PB  \t%#018lx \n",pm ); 

	//Same thing
	//bus = virt_to_bus(poison_memory);
	//printk ("Bus addr %#018lx \n", bus);
        spin_lock_irqsave(&uvmce_lock, flags);
        uv_write_global_mmr64(0 /*pnode*/, UV_MMR_SCRATCH_1, pm);
        uv_write_global_mmr64(0 /*pnode*/, UV_MMR_SMI_SCRATCH_2, UV_MMR_SMI_WALK_3);

        spin_unlock_irqrestore(&uvmce_lock, flags);
	memset(&poison_memory, 0, sizeof(unsigned long));
	kfree(poison_memory);
	return 0;

}


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int uvmce_ioctl(struct inode *i, struct file *f, unsigned int cmd, unsigned long arg)
#else
static long uvmce_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
#endif
{
 
    switch (cmd)
    {
        case UVMCE_INJECT_UME:
	    printk("UVMCE_INJECT_UME\n");
	    uvmce_inject_ume();
            break;
#if 0
        case QUERY_GET_VARIABLES:
            q.status = status;
            q.dignity = dignity;
            q.ego = ego;
            if (copy_to_user((query_arg_t *)arg, &q, sizeof(query_arg_t)))
            {
                return -EACCES;
            }
            break;
        case QUERY_SET_VARIABLES:
            if (copy_from_user(&q, (query_arg_t *)arg, sizeof(query_arg_t)))
            {
                return -EACCES;
            }
            status = q.status;
            dignity = q.dignity;
            ego = q.ego;
            break;
#endif
        default:
            return -EINVAL;
    }
 
    return 0;
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
