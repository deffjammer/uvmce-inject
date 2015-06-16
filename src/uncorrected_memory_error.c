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

#define min(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a < _b ? _a : _b; })
#define max(a,b)        ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })


#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
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
	printf("Options:\n");
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

long length;
long memsize(char *s)
{
        char *end;
        long length = strtoul(s,&end,0);
        switch (toupper(*end)) {
        case 'G': length *= 1024;  /*FALL THROUGH*/
        case 'M': length *= 1024;  /*FALL THROUGH*/
        case 'K': length *= 1024; break;
        }
        return length;
}  

void hog(void *map)
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

int main (int argc, char** argv) {                                     
	int fd, ret, c;
	int delay = 0;
	void *map;
 	struct bitmask *nodes, *gnodes;
	static char optstr[] = "kudc:";
	unsigned long addr;
	int gpolicy, policy = MPOL_DEFAULT;
	int i, repeat = 10;
        int ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;
	struct vaddr_info *vaddrs;
	unsigned long  flush_bytes;
	void *vaddrmin = (void *)-1UL, *vaddrmax = NULL;

	nodes = numa_allocate_nodemask();
	gnodes = numa_allocate_nodemask();

	eid.cpu = sched_getcpu();

        while ((c = getopt(argc, argv, optstr)) != EOF)
                switch (c) {
                case 'k':
                	ioctlcmd = UVMCE_INJECT_UME;
                	break;
                case 'u':
                	ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;
                	break;
                case 'c':
                        eid.cpu = atoi(optarg);
                        break;
                case 'd':
                        delay=1;
                        break;
		case 'h':
		default :
			help();
			break;
	}
	length = memsize("100m");
	map = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
        if (mbind(map, length, policy, nodes->maskp, nodes->size, 0) < 0){
                printf("mbind error\n");
        } 
	/* Fault in addresses so lookup in kernel works */
	hog(map);
	eid.addr = map;
	printf("cpu %d, vaddr %p length %ld\n", eid.cpu, eid.addr, length);

	//cpu_process_affinity(getpid(), eid.cpu);
	//sleep(2);
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	}                                               
	
            
	if (ioctl(fd, ioctlcmd, &eid ) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}                                               

    	gpolicy = -1;
        if (get_mempolicy(&gpolicy, gnodes->maskp, gnodes->size, map, MPOL_F_ADDR) < 0)
                perror("get_mempolicy");
        if (!numa_bitmask_equal(gnodes, nodes)) {
                printf("nodes differ %lx, %lx!\n", gnodes->maskp[0], nodes->maskp[0]);
        }


	printf("return eid.addr \t%#018lx \n", eid.addr);
	if (delay){
		printf("Enter char to memset..");
		getchar();
	}
	
	for (i = 0; i < repeat; i++) {
		hog(map);
	}

	if (delay) {
		printf("Enter char to exit..");
		getchar();
	}

	close(fd);                                      
	return 0;                                       
}
