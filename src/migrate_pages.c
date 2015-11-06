/*
 * gcc -I../include/ uncorrected_memory_error.c -o  uce -lnuma
 * insmod ../kernel/uv_mce_inject.ko
 * ./uce -d <size of mmap>
 *
 * 1 - write SCRATCH14 to inject the error.
 * 2 - wait for SCRATCH14[63:56] == 0xac
 * 3 - write (or read) data from the injected address 
 * 
 */



#define _GNU_SOURCE 1
#include <sched.h>
#include <stdio.h>                                
#include <stdlib.h>                                
#include <fcntl.h>                                
#include <unistd.h>                               
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <numaif.h>
#include <linux/ioctl.h>
#include "uvmce.h"                           
#include "numatools.h"                           

#define INVALID_NODE -1
#define UVMCE_DEVICE "/dev/uvmce"                   
#define SOFTOFFLINE  "/sys/devices/system/memory/soft_offline_page"
#define HARDOFFLINE  "/sys/devices/system/memory/hard_offline_page"

extern struct bitmask *numa_allocate_nodemask(void);
extern int numa_bitmask_equal(struct bitmask *, struct bitmask *);
extern void process_pagemap_vtop_array(page_desc_t *, page_desc_t *, page_desc_t *,
		   	     unsigned long, unsigned long, unsigned long,
		             unsigned int, unsigned long, unsigned long long  []);
 
//static int 	show_pnodes = 0;
static int 	delay = 0;
static int 	manual = 0;
static int      uvmce_fd;
/*   Virt		Physical                      PTE
 * [7ffff7fb4000] -> 0x005e4b72e000 on pnode   1    0x8000005e4b72e067  MEMORY|RW|DIRTY|SHARED
 */
char *buf;

struct bitmask {
        unsigned long size; /* number of bits in the map */
        unsigned long *maskp;
};


void help(){
	printf("ume [Hdm:c <cpu>  <size>]\n" \
		"-d	: Waits before memset so process map can be examined \n" \
		"-m	: Won't inject poison addr from kernel. \n"   \
		"-c	: Cpu used by kernel modeuls to determine pnode \n"      \
		"-H	: Disables HugePages\n");
}



/*
 * soft page offlining for UCEs
 */
int
soft_offline_page(unsigned long long addr)
{
	char page[32];
    	struct stat retire_stat;
    	char *filename;
	int soft_offline_fd;	

	if (!addr)
		return -1;

	filename = SOFTOFFLINE;
	if (stat(filename, &retire_stat) < 0) {
		printf("soft_offline_page: stat error on %s: %s\n", filename, strerror(errno));
	    	return -1;
	}
	if (!S_ISREG(retire_stat.st_mode) || !(S_IWUSR&retire_stat.st_mode)) {
	    	printf("soft_offline_page: %s is not char special file or no write access.\n", filename);
	    	return -1;
	}
	if ((soft_offline_fd = open(filename, O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR)) < 0) {
	    	printf("soft_offline_page: open error on %s: %s.\n", filename, strerror(errno));
	    	return -1;
	}
	
	sprintf(page,"0x%llx\n", addr);
	printf("Soft Offline Page: %s", page);
	write(soft_offline_fd, page, strlen(page));

	close(soft_offline_fd);

	return 0;
}
/*
 * hard page offlining for UCEs
 */
int
hard_offline_page(unsigned long long addr)
{
	char page[32];
    	struct stat retire_stat;
    	char *filename;
	int hard_offline_fd;	

	if (!addr)
		return -1;

	filename = HARDOFFLINE;
	if (stat(filename, &retire_stat) < 0) {
		printf("hard_offline_page: stat error on %s: %s\n", filename, strerror(errno));
	    	return -1;
	}
	if (!S_ISREG(retire_stat.st_mode) || !(S_IWUSR&retire_stat.st_mode)) {
	    	printf("hard_offline_page: %s is not char special file or no write access.\n", filename);
	    	return -1;
	}
	if ((hard_offline_fd = open(filename, O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR)) < 0) {
	    	printf("hard_offline_page: open error on %s: %s.\n", filename, strerror(errno));
	    	return -1;
	}
	
	sprintf(page,"0x%llx\n", addr);
	printf("Hard Offline Page: %s", page);
	write(hard_offline_fd, page, strlen(page));

	close(hard_offline_fd);
	
	return 0;
}


int main (int argc, char** argv) {                                     
	int   c;
	long length;
	int cpu = 2;
	int disableHuge = 0;
	int madvisePoison = 0;
	int madviseSoftOffline = 0;
 	struct bitmask *nodes, *gnodes;
	int gpolicy, policy = MPOL_DEFAULT;
	int n;
        static page_desc_t      *pdbegin=NULL;
        static size_t           pdcount=0;
        unsigned long           addrend, pages, paddr = 0;
        page_desc_t             *pd=NULL, *pdend=NULL;
        struct dlook_get_map_info req;
        unsigned int            pagesize = getpagesize();
	int 			softoffline=0;
	unsigned long long  vtop_l[1024];
	
	nodes  = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();

	length = memsize("4k");

  	while ((c = getopt (argc, argv, "dHPMm:c:")) != -1){
	    switch (c) {
	        case 'c':
                        cpu = atoi(optarg);
                        break;
	        case 'm':
                        length = memsize(optarg);
                        break;
                case 'd':
                        delay=1;
                        break;
                case 'H':
                        disableHuge=1;
                        break;
		case 'P':
                        madvisePoison=1;
                        break;

                case 'M':
                        manual=1;
                        break;
		case 'h':
		default :
			help();
			break;
		}
	}

	cpu_process_setaffinity(getpid(), cpu);

	buf = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind((void *)buf, length, policy, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise((void *)buf, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise((void *)buf, length,MADV_HWPOISON);

	if (madviseSoftOffline)
		madvise((void *)buf, length,MADV_SOFT_OFFLINE);

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, (void *)buf, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }

        addrend = ((unsigned long)buf)+length;        
        pages = (addrend-((unsigned long)buf))/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid = getpid();
        req.start_vaddr = (unsigned long)buf;
        req.end_vaddr = addrend;
        req.pd = pdbegin;

	/*Fault in Pages */
	fault_pages((void *)buf, length);

	/* Get mmap phys_addrs */
	if ((uvmce_fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
		exit (1);                                     
	}                                               
	    
	if (ioctl(uvmce_fd, UVMCE_DLOOK, &req ) < 0){        
		printf("Failed to INJECT_UCE\n");
		exit(1);                                      
	}                                               

	process_pagemap_vtop_array(pd, pdbegin, pdend, pages, (unsigned long)buf,
		     addrend, pagesize, paddr, vtop_l);

	printf("\n\tstart_vaddr\t %p length\t 0x%lx\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		 (void *)buf , length, addrend, pages);

	for (n=0; n<pages; n++){
		softoffline ?
		soft_offline_page((unsigned long long)vtop_l[n]) :
		hard_offline_page((unsigned long long)vtop_l[n]);
	}
	close(uvmce_fd);                                      
	return 0;                                       
}
