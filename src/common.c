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
#include <linux/mempolicy.h>
#include <linux/ioctl.h>
#include "uvmce.h"                           
#include "numatools.h"                           

#define min(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a < _b ? _a : _b; })
#define max(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

#define INVALID_NODE -1
#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
#define UCE_INJECT_SUCCESS 0xAC00000000000000

int      show_phys=1;
int      show_holes=1;
int      show_libs=0;
int      show_pnodes=1;
int      show_ptes =1;
int      fd;
int 	delay = 0;
int 	manual = 0;
int 	pd_total= 0;
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

char* get_memory_attr_str(int nodeid, int mattr)
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


char *nodestr(long nodeid)
{
        static char str[16];
        static char dash[] = "-";

        if (nodeid < 0)
                return dash;
        sprintf(str, "%3ld", nodeid);
        return str;
}


void print_memory_block(long addr, long addrend, long count, long nodeid, long mattr)
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
void process_map(page_desc_t      *pd,
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

unsigned long poll_mmr_scratch14(int fd)
{
	unsigned long mmr_status;

	if (ioctl(fd, UVMCE_POLL_SCRATCH14, &mmr_status ) < 0){
                printf("Poll IOCTL Failed\n");
	}

 	//printf( "POLL mmr_status 0x%016lx\n", mmr_status);	
 	return mmr_status;	

}
unsigned long long uv_vtop(unsigned long r_vaddr)
{
        unsigned long           mattr, addrend, pages, count, nodeid, paddr = 0;
        unsigned long           addr_start=0, nodeid_start=-1, mattr_start=-1;
        char                    *endp;
        static page_desc_t      *pdbegin = NULL;
	static int 		pagesize;
        static size_t           pdcount=0;
        page_desc_t             *pd, *pdend;
        struct dlook_get_map_info req;
        char                    pte_str[20];

	pagesize = getpagesize();
        addrend = r_vaddr + pagesize;
        pages = (addrend-r_vaddr)/pagesize;

        if (pages > pdcount) {
                pdbegin = realloc(pdbegin, sizeof(page_desc_t)*pages);
                pdcount = pages;
        }

        req.pid = getpid();
        req.start_vaddr = r_vaddr;
        req.end_vaddr = addrend;
        req.pd = pdbegin;

	strcpy(pte_str, "");

	if (ioctl(fd, UVMCE_DLOOK, &req ) < 0){        
		exit(1);                                      
	} 
        count = 0;
        for (pd=pdbegin, pdend=pd+pages; pd<pdend && r_vaddr < addrend; pd++, r_vaddr += pagesize) {
		if (pd->flags & PD_HOLE) {
			pagesize = pd->pte;
			mattr = 0;
			nodeid = -1;
		} else {
			nodeid = get_pnodeid(*pd);
			paddr = get_paddr(*pd);
			if (nodeid == INVALID_NODE) {
				nodeid = 0;
			}
			mattr = get_memory_attr(*pd);
			pagesize = get_pagesize(*pd);
		}
		if (mattr && paddr) {
			sprintf(pte_str, "  0x%016lx  ", pd->pte);
			printf("\t[%012lx] -> 0x%012lx on %s %3s  %s%s\n",
				r_vaddr, paddr, idstr(), nodestr(nodeid),
				pte_str, get_memory_attr_str(nodeid, mattr));
		}
		count++;
	}
	pd_total = count;

	return paddr;
} 

/*
 * get information about address from /proc/{pid}/pagemap
 */

unsigned long long vtop(unsigned long long addr, int proc_id)
{
	unsigned long  pinfo;
	int 	pagesize = 0x1000;
	int fd;
	char	pagemapname[64];
	long offset;
	
	offset = addr / pagesize * (sizeof pinfo);
	
	/* sprintf(pagemapname, "/proc/%d/pagemap", getpid()); */
	sprintf(pagemapname, "/proc/%d/pagemap",proc_id);

	fd = open(pagemapname, O_RDONLY);
	if (fd == -1) {
		perror(pagemapname);
		exit(1);
	}
	if (pread(fd, &pinfo, sizeof pinfo, offset) != sizeof pinfo) {
		perror(pagemapname);
		exit(1);
	}
	close(fd);
	if ((pinfo & (1ull << 63)) == 0) {
		printf("page not present\n");
		exit(1);
	}
	return ((pinfo & 0x007fffffffffffffull) << 12) + (addr & (pagesize - 1));
}


