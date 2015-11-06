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
extern int numa_bitmask_equal(struct bitmask *, struct bitmask *);
extern void process_map(page_desc_t *, 
			page_desc_t *, 
			page_desc_t *,
			unsigned long, unsigned long, unsigned long,
			unsigned int,  unsigned long, unsigned long,
			unsigned long, unsigned long, unsigned long,
			unsigned long);

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

volatile unsigned int *injectedAddress = NULL;
void inject_scrub_uce(page_desc_t      *pd,
		page_desc_t      *pdbegin,
		page_desc_t      *pdend,
		unsigned long    pages,
		unsigned long    addr,
		unsigned long    addrend,
		unsigned int     pagesize,
		unsigned long    mattr,
		unsigned long    nodeid,
		unsigned long    paddr,
		unsigned long    nodeid_start,
		unsigned long    mattr_start,
		unsigned long    addr_start)
{
        int count = 0;

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
				//sprintf(pte_str, "  0x%016lx  ", pd->pte);
				//printf("\t[%012lx] -> 0x%012lx on %s %3s  %s%s\n",
				//		addr, paddr, idstr(), nodestr(nodeid),
				//		pte_str, get_memory_attr_str(nodeid, mattr));
				injectedAddress = (unsigned int *)addr;
				eid.addr   = paddr;
				eid.nodeid = nodeid;
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
	int c;
	long length;
	int cpu = 2;
	int disableHuge = 0;
	int madvisePoison = 0;
 	struct bitmask *nodes, *gnodes;
	int gpolicy, policy = MPOL_DEFAULT;
        static page_desc_t      *pdbegin=NULL;
        static size_t           pdcount=0;
        unsigned long           vaddr, mattr=0, addrend=0, pages=0, nodeid=0, paddr=0;
        unsigned long           addr_start=0, nodeid_start=-1, mattr_start=-1;
        page_desc_t             *pd=NULL, *pdend=NULL;
        struct dlook_get_map_info req;
        unsigned int            pagesize = getpagesize();

	nodes  = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();

	length = memsize("100k");

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

	vaddr =(unsigned long)mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind((void *)vaddr, length, policy, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise((void *)vaddr, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise((void *)vaddr, length,MADV_HWPOISON );

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, (void *)vaddr, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }

        addrend = vaddr+length;        
        pages = (addrend-vaddr)/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid         = getpid();
        req.start_vaddr = vaddr;
        req.end_vaddr   = addrend;
        req.pd          = pdbegin;

	cpu_process_setaffinity(getpid(), cpu);

	/*Fault in Pages */
	fault_pages((void *)vaddr, length);

	/* Get mmap phys_addrs */
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
		exit (1);                                     
	}                                               
	    
	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		printf("Failed to INJECT_UME\n");
		exit(1);                                      
	}                                               


	process_map(pd,pdbegin, pdend, pages, vaddr, addrend, pagesize, mattr,
		    nodeid, paddr, nodeid_start, mattr_start, addr_start);

	printf("\n\tstart_vaddr\t 0x%016lx length\t 0x%lx\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		 vaddr , length, addrend, pages);


	inject_scrub_uce(pd,pdbegin, pdend, pages, vaddr, addrend, pagesize, mattr,
		    nodeid, paddr, nodeid_start, mattr_start, addr_start);

	if (poll_mmr_scratch14(fd) != UCE_INJECT_SUCCESS){
		printf("BIOS Read of UCE Failed. Retry? This probably needs fixing\n");
	}
	
	if (delay){
		printf("Enter char to cont..");
		getchar();
	}

	close(fd);                                      
	return 0;                                       
}
