/*
 *  Combined Tool to inject different types of memory errors
 *  - Uncorrected Memory Error
 *  - Correctable Memory Error
 *  - Patrol Scrub Error
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
#include <getopt.h>
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
#define PAGE_SIZE (1 << 12)
#define UCE_INJECT_SUCCESS 0xac

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
/*   Virt		Physical                      PTE
 * [7ffff7fb4000] -> 0x005e4b72e000 on pnode   1    0x8000005e4b72e067  MEMORY|RW|DIRTY|SHARED
 */
struct err_inj_data eid;
char *buf;

struct bitmask {
        unsigned long size; /* number of bits in the map */
        unsigned long *maskp;
};


void help(){
	printf("einj hc:e: <cpu> \n" \
		"--cpu:c\t	: Cpu used by kernel modules to determine pnode \n"      \
		"--errortype:c	: Type of error to inject.\n"      \
		"		 1 = Uncorrected Memory Error\n"      \
		"		 2 = Correctable Memory Error\n"      \
		"		 3 = Patrol Scrub Uncorrected Memory Error\n"      \
		"	         Default is 1, Uncorrected Memory Error\n"      \
		"Flags		:\n" \
		"--delay	: Waits before memset so process map can be examined \n" \
		"--manual	: Won't inject poison addr from kernel. \n"   \
		"--disableHuge	: Disables HugePages\n");
	exit(1);
}

/*volatile?
 * static?
 */
char *injecteddata = NULL;
void consume_it(void *map, long length)
{

	/* read/consume data by printing it out
	 * Doing Both causes crash.  One or the other
	 unsigned int dead;
	 dead = *injectedAddress;
	 */
	printf("dead data:%x\n",*injecteddata);
}

static int injected=0;
void uv_inject(page_desc_t      *pd,
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
		unsigned long    addr_start,
		int              mce_opt)
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
				/* Setting value at memory location  for recovery
 				 * before injecting.
 				 */
        			memset((void *)addr, 'A', pagesize);
				injecteddata = (char *)addr;
				printf("Data:%x\n",*injecteddata);
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
	if (ioctl(fd, mce_opt, &eid ) < 0){        
                printf("Failed to INJECT_UCE\n");
                exit(1);
	}
	}
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
        char    *newbuf;
	static int psize;
	unsigned long long      phys;

	psize = getpagesize();

        printf("recover: sig=%d si=%p v=%p\n", sig, si, v);
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
        buf = newbuf;
	//printf("newbuf data:%x\n", *newbuf);
        //memcpy(buf, si->si_addr,  psize); //Fails cuz No data at recovered vaddr
	//memcpy(si->si_addr, backup_location, size)// Use backup
        memset((void *)buf, 'A', psize); //Just filling in data
	printf("recovered data:%x\n", *buf);
        phys = uv_vtop((unsigned long long)m->addr);
        printf("Recovery allocated new page at physical 0x%016llx\n", phys);

	exit(1);
}
unsigned long get_etype(int opt)
{

	switch(opt) {
	case 1:
		return UVMCE_INJECT_UCE_AT_ADDR;
	case 2:
		return UVMCE_INJECT_CE_AT_ADDR;
	case 3:
		return UVMCE_PATROL_SCRUB_UCE;
	default:
		return UVMCE_INJECT_UCE_AT_ADDR;
	}

}

struct sigaction recover_act = {
        .sa_sigaction = memory_error_recover,
        .sa_flags = SA_SIGINFO,
};
int main (int argc, char** argv) {                                     
	int  ret, c;
	int i, repeat = 5;
	int cpu = 2;
	static int errortype = 1;
	static int verbose = 1;
	static int disableHuge = 0;
	static int madvisePoison = 0;
	static int poll_exit=0;
	static long length;
 	struct bitmask *nodes, *gnodes;
	int gpolicy;
	unsigned long error_opt;

	void *vaddrmin = (void *)-1UL, *vaddrmax = NULL;

        static size_t           pdcount=0;
        unsigned long           mattr, addrend, pages, count, nodeid, paddr = 0;
        unsigned long           addr_start=0, nodeid_start=-1, mattr_start=-1;
        unsigned int            pagesize = getpagesize();
        char                    pte_str[20];

        struct dlook_get_map_info req;
        static page_desc_t        *pdbegin=NULL;
        page_desc_t               *pd, *pdend;

	length = memsize("100k");
	nodes  = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();

	while (1)
	{
		static struct option long_options[] =
		{
		  {"verbose",       no_argument,       &verbose, 1},
		  {"delay",         no_argument,       &delay, 1},
		  {"disableHuge",   no_argument,       &disableHuge, 1},
		  {"poll",          no_argument,       &poll_exit, 1},
		  {"madvisePoison", no_argument,       &madvisePoison, 1},
		  {"manual",        no_argument,       &manual, 1},
		  {"cpu",           required_argument, 0, 'c'},
		  {"errortype",     required_argument, 0, 'e'},
		  {"help",          no_argument,       0, 'h'},
		  {"length",        required_argument, 0, 'l'}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "hc:e:l:",
			       long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
		break;

		switch (c)
		{
			case 'c':
			  printf ("option -c with value `%s'\n", optarg);
                          cpu = atoi(optarg);
			  break;
			case 'e':
			  printf ("option -e with value `%s'\n", optarg);
                          errortype = atoi(optarg);
			  break;
			case 'h':
			  help();
			case 'l':
			  /* Not exposed */
			  printf ("option -l with value `%s'\n", optarg);
			  length = memsize("optarg");
			  break;
			case '?':
			  /* getopt_long already printed an error message. */
			  exit(-1);
		}
	}

	cpu_process_setaffinity(getpid(), cpu);

	error_opt = get_etype(errortype);

	buf = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind((void *)buf, length,  MPOL_DEFAULT, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise((void *)buf, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise((void *)buf, length,MADV_HWPOISON );

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, (void *)buf, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }

	strcpy(pte_str, "");
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

	sigaction(SIGBUS, &recover_act, NULL);

	/*Fault in Pages */
	if(!poll_exit)
		hog((void *)buf, length);

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

	process_map(pd,pdbegin, pdend, pages, buf, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, mattr_start, addr_start);

	printf("\n\tstart_vaddr\t 0x%016lx length\t 0x%x\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		 buf , length, addrend, pages);


	uv_inject(pd,pdbegin, pdend, pages, (unsigned long)buf, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, 
		    mattr_start, addr_start, error_opt);

	if (poll_mmr_scratch14(fd) & UCE_INJECT_SUCCESS){
		printf("BIOS Read of UCE Failed. Retry?\n");
	}
	
	if (delay){
		printf("Enter char to consume bad memory..");
		getchar();
	}

	consume_it((void *)buf, length);

out:
	close(fd);                                      
	return 0;                                       
}
