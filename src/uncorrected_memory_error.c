/*
 * gcc -I../include/ uncorrected_memory_error.c -o  ume -lnuma
 * insmod ../kernel/uv_mce_inject.ko
 * numactl -m<node> ./ume
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
#include <numaif.h>
#include <linux/ioctl.h>
#include "uvmce.h"                           
#include "numatools.h"                           

#define min(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a < _b ? _a : _b; })
#define max(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

#define INVALID_NODE -1
#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
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

int cpu_process_setaffinity(pid_t pid, int cpu)
{
        cpu_set_t * cpus;
        int ncpus;
        int size;

        ncpus = sysconf(_SC_NPROCESSORS_CONF);

        if (cpu > (ncpus-1)) {
                return -1;
        }

        cpus = CPU_ALLOC(ncpus);
        size = CPU_ALLOC_SIZE(ncpus);

        CPU_ZERO_S(size, cpus);
        CPU_SET_S(cpu, ncpus, cpus);

        printf("cpu_process_affinity pid %d, cpu %d\n",pid,cpu);
        if (sched_setaffinity(pid, size, cpus)) {
                perror("sched_setaffinity");
                CPU_FREE(cpus);
                return -1;
        }

        CPU_FREE(cpus);
        return 0;
}
enum {
        UNIT = 10*1024*1024,
};

long memsize(char *s)
{
        char *end;
        long llength = strtoul(s,&end,0);
        switch (toupper(*end)) {
        case 'G': llength *= 1024;  /*FALL THROUGH*/
        case 'M': llength *= 1024;  /*FALL THROUGH*/
        case 'K': llength *= 1024; break;
        }
        return llength;
}  

void hog(void *map, long length)
{
        long i;

        for (i = 0;  i < length; i += UNIT) {
                long left = length - i;
                if (left > UNIT)
                        left = UNIT;
                putchar('.');
                fflush(stdout);
                memset(map + i, 0xff, left);
        }
        putchar('\n');
}

static char*
get_memory_attr_str(int nodeid, int mattr)
{
        static char     buf[64];
        buf[0] = '\0';

        if (mattr == 0) {
                strcat(buf, " (no pages)");
        } else if (mattr & PD_SWAPPED) {
                 strcat(buf, "SWAPPED");
        } else if (mattr & PD_RAM) {
                strcat(buf, "MEMORY");
                if (mattr & PD_RW) strcat(buf, "|RW");
                if (mattr & PD_DIRTY) strcat(buf, "|DIRTY");
                if (mattr & PD_SHARED) strcat(buf, "|SHARED");
                if (mattr & PD_RESERVED) strcat(buf, "|RESERVED");
                if (mattr & PD_MA_UC) strcat(buf, "|UC");
                if (mattr & (PD_HP_2MB | PD_HP_1GB)) strcat(buf, "|HUGEPAGE");
        } else {
                strcat(buf, "???");
        }
        return buf;
}

#define idstr() (show_pnodes ? "pnode" : "node ")

static char *nodestr(long nodeid)
{
        static char str[16];
        static char dash[] = "-";

        if (nodeid < 0)
                return dash;
        sprintf(str, "%3ld", nodeid);
        return str;
}


static void
print_memory_block(long addr, long addrend, long count, long nodeid, long mattr)
{
        const char *pagestr[] = {"page  ", "pages ", "hpage ", "hpages"};
        int ix;

        ix = (mattr & (PD_HP_2MB | PD_HP_1GB)) ? 2 : 0;
        if (count > 1)
                ix++;

        if (mattr == 0 && show_holes == 0)
                return;

        printf("\t[%016lx-%016lx]\t%8ld %s", addr, addrend, count, pagestr[ix]);
        if (mattr & PD_SWAPPED)
                printf("              %s\n", get_memory_attr_str(nodeid, mattr));
        else if (mattr)
                printf(" on %s %3s  %s\n", idstr(), nodestr(nodeid), get_memory_attr_str(nodeid, mattr));
        else
                printf(" hole\n");
}
#if 1
static void process_map(page_desc_t      *pd,
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
	printf("pdbegin %p addrend %p pages %ld \n",  pd, addrend, pages);
        for (pd=pdbegin, pdend=pd+pages; pd<pdend && addr < addrend; pd++, addr += pagesize) {
		if (pd->flags & PD_HOLE) {
			pagesize = pd->pte;
			mattr = 0;
			nodeid = -1;
		} else {
			if (show_pnodes)
				nodeid = get_pnodeid(*pd);
			else
				nodeid = get_nodeid(*pd);
			paddr = get_paddr(*pd);
			//printf("pd %p, addr 0x%012lx phys_addr 0x%012lx\n",  pd, addr, paddr );
			if (nodeid == INVALID_NODE) {
				nodeid = 0;
			}
			mattr = get_memory_attr(*pd);
			pagesize = get_pagesize(*pd);
		}
		if (show_phys) {
			if (mattr && paddr) {
				if (show_ptes)
					sprintf(pte_str, "  0x%016lx  ", pd->pte);
				printf("\t[%012lx] -> 0x%012lx on %s %3s  %s%s\n",
					addr, paddr, idstr(), nodestr(nodeid),
					pte_str, get_memory_attr_str(nodeid, mattr));
			}
		} else if (nodeid != nodeid_start || mattr != mattr_start) {
			if (count)
				print_memory_block(addr_start, addr, count,
						   nodeid_start, mattr_start);
			nodeid_start = nodeid;
			mattr_start = mattr;
			addr_start = addr;
			count = 0;
		}
		count++;
	}
	pd_total = count;
}
#endif
static int injected=0;
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

	//printf("pdbegin %p addr %p addrend %p pages %ld\n",  pd, addr, addrend, pages);
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
	if (ioctl(fd, UVMCE_INJECT_UME_AT_ADDR, &eid ) < 0){        
                printf("Failed to INJECT_UME\n");
                exit(1);
	}
	}

}

void poll_mmr_scratch14()
{
	unsigned long mmr_status;

	if (ioctl(fd, UVMCE_POLL_SCRATCH14, &mmr_status ) < 0){        
                printf("Failed to INJECT_UME\n");
                exit(1);
	}
}
int main (int argc, char** argv) {                                     
	int  ret, c;
	long length;
	int cpu = 2;
	int disableHuge = 0;
	int madvisePoison = 0;
 	struct bitmask *nodes, *gnodes;
	static char optstr[] = "kudHPmc:";
	int gpolicy, policy = MPOL_DEFAULT;
	int i, repeat = 5;
        //int ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;
        int ioctlcmd = UVMCE_DLOOK;
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

	nodes = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();


        while (argv[1] && argv[1][0] == '-') {
        	switch (argv[1][1]) {
                case 'k':
                	ioctlcmd = UVMCE_INJECT_UME;
                	break;
                case 'u':
                	ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;
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
		length = memsize("10m");
	else
        	length = memsize(argv[1]);

	addr = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (mbind(addr, length, policy, nodes->maskp, nodes->size, 0) < 0){
                perror("mbind error\n");
        } 
	/* Disable Hugepages */
	if (disableHuge)
		madvise(addr, length, MADV_NOHUGEPAGE);

	if (madvisePoison)
		madvise(addr, length,MADV_HWPOISON );

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, addr, MPOL_F_ADDR) < 0)
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
	//Fault in Pages
	hog(addr, length);

	/* Get mmap phys_addrs */
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
		exit (1);                                     
	}                                               
	    
	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		printf("Failed to INJECT_UME\n");
		exit(1);                                      
	}                                               

	process_map(pd,pdbegin, pdend, pages, addr, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, mattr_start, addr_start);
	printf("\n\tcpu %d\n\tstart_vaddr\t 0x%016lx length\t 0x%x\n\tend_vaddr\t 0x%016lx pages\t %ld\n", 
		cpu, addr , length, addrend, pages);


	inject_uce(pd,pdbegin, pdend, pages, addr, addrend, pagesize, mattr,
		    nodeid, paddr, pte_str, nodeid_start, mattr_start, addr_start);

	
	if (delay){
		printf("Enter char to memset..");
		getchar();
	}

	for (i = 0; i < repeat; i++) {
		hog(addr, length);
	}
	poll_mmr_scratch14();

	if (delay) {
		printf("Enter char to exit..");
		getchar();
	}

	close(fd);                                      
	return 0;                                       
}
