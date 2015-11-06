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

#define min(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a < _b ? _a : _b; })
#define max(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

#define INVALID_NODE -1
#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
#define UCE_INJECT_SUCCESS 0xAC00000000000000

extern struct bitmask *numa_allocate_nodemask(void);
extern void process_map(page_desc_t *, 
			page_desc_t *, 
			page_desc_t *,
			unsigned long, unsigned long, unsigned long,
			unsigned int,  unsigned long, unsigned long,
			unsigned long, unsigned long, unsigned long,
			unsigned long);

extern int numa_bitmask_equal(struct bitmask *, struct bitmask *);
 
static int      fd;
static int 	show_pnodes = 0;
static int 	delay = 0;
static int 	manual = 0;
/*   Virt		Physical                      PTE
 * [7ffff7fb4000] -> 0x005e4b72e000 on pnode   1    0x8000005e4b72e067  MEMORY|RW|DIRTY|SHARED
 */

char *databuf;
struct bitmask {
        unsigned long size; /* number of bits in the map */
        unsigned long *maskp;
};


void help(){
	printf("ume [HdM:c <cpu>]\n" \
		"-d	: Waits before memset so process map can be examined \n" \
		"-M	: Won't inject poison addr from kernel. \n"   \
		"-c	: Cpu used by kernel modeuls to determine pnode \n"      \
		"-H	: Disables HugePages\n");
}

/*volatile?
 * static?
 */
char *injecteddata = NULL;
void consume_it(void *map, long length)
{

	/* read/consume data by printing it out
	 * Doing Both causes crash.  One or the other
	 //dead = *injectedAddress;
	 */
	printf("dead data:%x\n",*injecteddata);
}
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
		unsigned long    nodeid_start,
		unsigned long    mattr_start,
		unsigned long    addr_start)
{
	struct err_inj_data eid;
        int    count = 0;

        for (pd=pdbegin, pdend=pd+pages; pd<pdend && addr < addrend; pd++, addr += pagesize) {
		nodeid   = get_pnodeid(*pd);
		paddr    = get_paddr(*pd);
		pagesize = get_pagesize(*pd);
		printf("\t[%012lx] -> 0x%012lx on %ld\n", addr, paddr, nodeid);
		/* Setting value at memory location  for recovery
 		 * before injecting.
 		 */
        	memset((void *)addr, 'A', pagesize);
		injecteddata = (char *)addr;
		printf("Data:%x\n",*injecteddata);
		eid.addr = paddr;
		eid.nodeid = nodeid;
		count++;
		break; //Fix this to allow more than one injection
	} 
	if (delay){
		printf("Enter char to inject..");
		getchar();
	}	
	if(!manual){
		if (ioctl(fd, UVMCE_INJECT_UCE_AT_ADDR, &eid ) < 0){        
			printf("Failed to INJECT_UCE\n");
			close(fd);
			exit(1);
		}
	}

}
unsigned long long uv_vtop(unsigned long r_vaddr)
{
        unsigned long           mattr, addrend, pages, nodeid, paddr = 0;
        static page_desc_t      *pdbegin = NULL;
	static int 		pagesize;
        static size_t           pdcount=0;
        page_desc_t             *pd, *pdend;
        char                    pte_str[20];
        struct 	dlook_get_map_info req;

	pagesize = getpagesize();
        addrend  = r_vaddr + pagesize;
        pages    = (addrend-r_vaddr)/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid         = getpid();
        req.start_vaddr = r_vaddr;
        req.end_vaddr   = addrend;
        req.pd          = pdbegin;

	strcpy(pte_str, "");

	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		exit(1);                                      
	} 
        for (pd=pdbegin, pdend=pd+pages; pd<pdend && r_vaddr < addrend; pd++, r_vaddr += pagesize) {
			nodeid   = get_pnodeid(*pd);
			paddr    = get_paddr(*pd);
			mattr    = get_memory_attr(*pd);
			pagesize = get_pagesize(*pd);
			sprintf(pte_str, "  0x%016lx  ", pd->pte);
			printf("\t[%012lx] -> 0x%012lx on %s %3s  %s%s\n",
				r_vaddr, paddr, idstr(), nodestr(nodeid),
				pte_str, get_memory_attr_str(nodeid, mattr));
	}

	return paddr;
} 

/*
 * Older glibc headers don't have the si_addr_lsb field in the siginfo_t
 *  structure ... ugly hack to get it
 */
struct morebits {
        void    *addr;
	short   lsb;
};                                                                          

/*
	sig will be SIGBUS
	si->si_trapno == 18 (MCE_VECTOR)
	si->si_code BUS_MCEERR_AO or BUS_MCEERR_AR
	si->si_addr is virtual address affected
	si->si_addr_lsb describes range affected (12 means 4KB)
	v points to a ucontext_t structure - contains "ip" and other registers
	 ideas for code flow 
	Look at affected address range [si->si_addr, si->si_addr + (1<<si->si_addr_lsb))
	If it isn't a range we can fix - application must cleanup as best it can and
	exit

	if (si->si_code == BUS_MCEERR_AO) {
		log that we saw an error
		return; // error won't affect us now
	}
	app_cleanup();
	exit(FAIL);

	Range is good - can we replace the lost data?
	allocate page and map at lost address
	mmap(si->si_addr, size, PROT*, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
	Fill in lost data
	memcpy(si->si_addr, backup_location, size)
	Full recovery - return to re-execute instruction that faulted return;
	Range is good, but no backup for this data
	Walk data structures cleanup point
*/

/*
 * "Recover" from the error by allocating a new page and mapping
 * it at the same virtual address as the page we lost. Fill with
 * the same (trivial) contents.
 */
void memory_error_recover(int sig, siginfo_t *si, void *v)
{
        struct morebits *m = (struct morebits *)&si->si_addr;
        char               *newbuf;
	static int 	   psize;
	unsigned long long phys;

	psize = getpagesize();

        printf("memory_error_recover: sig=%d si=%p v=%p\n", sig, si, v);
        printf("Platform memory error at 0x%p\n", si->si_addr);
        printf("addr = %p lsb=%d\n", m->addr, m->lsb);
        newbuf = mmap((void *)m->addr, psize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

        if ((char *)newbuf == MAP_FAILED) {
                fprintf(stderr, "Can't get a single page of memory!\n");
                exit(1);
        }
        if (newbuf != m->addr) {
                fprintf(stderr, "Could not allocate at original virtual address\n");
                exit(1);
        }
        databuf = newbuf;
	//printf("newbuf data:%x\n", *newbuf);
        //memcpy(databuf, si->si_addr,  psize); //Fails cuz No data at recovered vaddr
	//memcpy(si->si_addr, backup_location, size)// Use backup
        memset((void *)databuf, 'A', psize); //Just filling in data
	//printf("recovered data:%x\n", *databuf);
        phys = uv_vtop((unsigned long long)m->addr);
        printf("Recovery allocated new page at physical 0x%016llx\n", phys);

	exit(1);
}

struct sigaction recover_act = {
        .sa_sigaction = memory_error_recover,
        .sa_flags = SA_SIGINFO,
};
int main (int argc, char **argv) {                                     
	int  c;
	unsigned long length;
	int cpu = 2;
	int disableHuge = 0;
	int madvisePoison = 0;
	int poll_exit=0;
 	struct bitmask *nodes, *gnodes;
	int gpolicy, policy = MPOL_DEFAULT;
	extern char *optarg;	
        static page_desc_t      *pdbegin=NULL;
        static size_t           pdcount=0;
        unsigned long           mattr=0, addrend=0, pages=0, nodeid=0, paddr=0;
        unsigned long           addr_start=0, nodeid_start=-1, mattr_start=-1;
	page_desc_t             *pd=NULL, *pdend=NULL;
        struct dlook_get_map_info req;
        unsigned int            pagesize = getpagesize();
	//unsigned long long  vtop_l[1024];

	nodes  = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();

	length = memsize("100k");

  	while ((c = getopt (argc, argv, "dHpPMm:c:")) != -1){
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
		case 'p':
			poll_exit=1;
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

	databuf = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind((void *)databuf, length, policy, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise((void *)databuf, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise((void *)databuf, length,MADV_HWPOISON );

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, (void *)databuf, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }

        addrend = ((unsigned long)databuf)+length;        
        pages = (addrend-((unsigned long)databuf))/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid = getpid();
        req.start_vaddr = (unsigned long)databuf;
        req.end_vaddr = addrend;
        req.pd = pdbegin;

	cpu_process_setaffinity(req.pid, cpu);
	sigaction(SIGBUS, &recover_act, NULL);

	/*Fault in Pages */
	if(!poll_exit)
		fault_pages((void *)databuf, length);

	/* Get mmap phys_addrs */
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
		exit (1);                                     
	}                                               
	    
	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		printf("Failed to INJECT_UCE\n");
		exit(1);                                      
	}                                               

	if (poll_exit){
		printf("SCRATCH14 0x%lx\n", poll_mmr_scratch14(fd));
		goto out;
	}

	process_map(pd, pdbegin, pdend, 
		    pages, (unsigned long)databuf, addrend, 
		    pagesize, mattr, nodeid, 
		    paddr, nodeid_start, mattr_start, addr_start);

	printf("\n\tstart_vaddr\t %p length\t 0x%lx\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		 (void *)databuf , length, addrend, pages);

	inject_uce(pd,pdbegin, pdend, pages, (unsigned long)databuf, addrend, pagesize, mattr,
		    nodeid, paddr, nodeid_start, mattr_start, addr_start);

	if (poll_mmr_scratch14(fd) != UCE_INJECT_SUCCESS){
		printf("BIOS Read of UCE Failed. Retry?\n");
	}
	if (delay){
		printf("Enter char to consume bad memory..");
		getchar();
	}

	consume_it((void *)databuf, length);

out:
	close(fd);                                      
	return 0;                                       
}
