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



#define _GNU_SOURCE
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <numaif.h>
#include <linux/ioctl.h>
#include "../include/uvmce.h"                           
#include "../include/numatools.h"                           

#define min(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a < _b ? _a : _b; })
#define max(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

#define INVALID_NODE -1
#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
#define UCE_INJECT_SUCCESS 0xAC00000000000000

extern struct bitmask *numa_allocate_nodemask(void);

static int      show_phys=1;
static int      show_holes=1;
static int      show_libs=0;
static int      show_pnodes=1;
static int      show_ptes =1;
static int      fd;
static int 	delay = 0;
static int 	manual = 0;
static int 	pd_total= 0;
//	                 Physical                      PTE
// [7ffff7fb4000] -> 0x005e4b72e000 on pnode   1    0x8000005e4b72e067  MEMORY|RW|DIRTY|SHARED

struct err_inj_data eid;

int buf[PAGE_SIZE] __attribute__ ((aligned(128)));

struct vaddr_info {
	void		*vaddr;
};

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
static int injected=0;


volatile unsigned int *injectedAddress = NULL;
void inject_uce(page_desc_t      *pd,
		page_desc_t      *pdbegin,
		page_desc_t      *pdend,
		unsigned long    pages,
		unsigned long    addr,
		unsigned long    addrend,
		unsigned int     pagesize,
		unsigned long    mattr,
		unsigned long    nodeid,
		unsigned long    paddr,
		char             *pte_str,
		unsigned long    nodeid_start,
		unsigned long    mattr_start,
		unsigned long    addr_start)
{
        int count = 0;
	eid.cpu = sched_getcpu();

        for (pd=pdbegin, pdend=pd+pages; pd<pdend && addr < addrend; pd++, addr += pagesize) {
		if (pd->flags & PD_HOLE) {
			pagesize = pd->pte;
			mattr = 0;
			nodeid = -1;
		} else {
			nodeid = get_pnodeid(*pd);
			paddr = get_paddr(*pd);
			if (nodeid == INVALID_NODE)
				nodeid = 0;

			mattr = get_memory_attr(*pd);
			pagesize = get_pagesize(*pd);
			if (mattr && paddr) {
				if ((pd_total / 2) == count){
				sprintf(pte_str, "  0x%016lx  ", pd->pte);
				printf("\t[%012lx] -> 0x%012lx on %s %3s  %s%s\n",
						addr, paddr, idstr(), nodestr(nodeid),
						pte_str, get_memory_attr_str(nodeid, mattr));
				injectedAddress = (unsigned int *)addr;
				eid.addr = paddr;
				eid.cpu = nodeid;
				break;//only allow once for now
				}
			}
		}
		count++;
	} 
	if (delay){
		printf("Enter char to inject..");
		getchar();
	}	
	if(!manual){
	if (ioctl(fd,UVMCE_PATROL_SCRUB_UCE, &eid ) < 0){        
                printf("Failed to INJECT_PATROL_SCRUB_UCE\n");
                exit(1);
	}
	}

}

int main (int argc, char** argv) {                                     
	int  ret, c;
	long length;
	int cpu = 2;
	int disableHuge = 0;
	int madvisePoison = 0;
	int poll_exit=0;
 	struct bitmask *nodes, *gnodes;
	static char optstr[] = "kudHPmc:";
	int gpolicy, policy = MPOL_DEFAULT;
	int i, repeat = 5;
	struct vaddr_info *vaddrs;
	unsigned long  flush_bytes;
	void *vaddrmin = (void *)-1UL, *vaddrmax = NULL;

        static page_desc_t      *pdbegin=NULL;
        static size_t           pdcount=0;
        unsigned long           addr, mattr, addrend, pages, count, nodeid, paddr = 0;
        unsigned long           addr_start=0, nodeid_start=-1, mattr_start=-1;
        char                    *endp;
        page_desc_t             *pd, *pdend;
        struct dlook_get_map_info req;
        unsigned int            pagesize = getpagesize();
        char                    pte_str[20];

	nodes  = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();


        while (argv[1] && argv[1][0] == '-') {
        	switch (argv[1][1]) {
                case 'k': // Need to add this option. Causes crash from kernel fault
                	//ioctlcmd = UVMCE_INJECT_UME;
                	break;
                case 'c':
                        cpu = atoi(optarg);
                        break;
                case 'd':
                        delay=1;
                        break;
                case 'H':
                        disableHuge=1;
                        break;
		case 'p':
			poll_exit=1;
                        break;
		case 'P':
                        madvisePoison=1;
                        break;

                case 'm':
                        manual=1;
                        break;
		case 'h':
		default :
			help();
			break;
		}
		argv++;
	}
	if (!argv[1]) 
		length = memsize("100k");
	else
        	length = memsize(argv[1]);

	addr =(unsigned long)mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind((void *)addr, length, policy, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise((void *)addr, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise((void *)addr, length,MADV_HWPOISON );

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, (void *)addr, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }

	strcpy(pte_str, "");

        addrend = addr+length;        
        pages = (addrend-addr)/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid = getpid();
        req.start_vaddr = addr;
        req.end_vaddr = addrend;
        req.pd = pdbegin;

	//cpu_process_affinity(getpid(), eid.cpu);

	/*Fault in Pages */
	if( !poll_exit)
		hog((void *)addr, length);

	/* Get mmap phys_addrs */
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
		exit (1);                                     
	}                                               
	    
	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		printf("Failed to INJECT_UME\n");
		exit(1);                                      
	}                                               

	if (poll_exit){
		printf("SCRATCH14 0x%lx\n", poll_mmr_scratch14(fd));
		goto out;
	}

	process_map(pd,pdbegin, pdend, pages, addr, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, mattr_start, addr_start);

	printf("\n\tstart_vaddr\t 0x%016lx length\t 0x%x\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		 addr , length, addrend, pages);


	inject_uce(pd,pdbegin, pdend, pages, addr, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, mattr_start, addr_start);

	if (poll_mmr_scratch14(fd) & UCE_INJECT_SUCCESS){
		printf("BIOS Read of UCE Failed. Retry?\n");
	}
	
	if (delay){
		printf("Enter char to memset..");
		getchar();
	}

out:
	close(fd);                                      
	return 0;                                       
}
