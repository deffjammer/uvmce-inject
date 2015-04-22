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
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <asm/ioctl.h>                                                   
 
#define SCMD_MAGIC 's'                                                   
 
#define SCMD_IOCGETD  _IOR(SCMD_MAGIC, 1 , char *) //get driver data     
#define SCMD_IOCSETD  _IOW(SCMD_MAGIC, 2 , char *) //set driver data     
#define SCMD_IOCXCHD  _IOWR(SCMD_MAGIC,3 , char *) //exchange driver data
 

MODULE_LICENSE("GPL");
MODULE_INFO(supported, "external");

#define UVMCE_NAME "uvmce"
int uvmce_ioctl(struct inode *, struct file *, unsigned int , unsigned long );

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


/* The register structure for /dev/ex_misc */
static struct miscdevice uvmce_miscdev = {
	MISC_DYNAMIC_MINOR,
	UVMCE_NAME,
	&uvmce_fops,
};


int
uvmce_ioctl(struct inode *inode, struct file *file,	
		 unsigned int ioctl_num, unsigned long ioctl_param)
{
	int error = 0;


	return error;
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
