/*
 * gcc -I../include/ uncorrected_memory_error.c -o  ume
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



void help(){
	printf("Options:\n");
}

int cpu_process_affinity(pid_t pid, int cpu)
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


 
int main (int argc, char** argv) {                                     
	int fd, ret, c;
	static char optstr[] = "kuc:";
	unsigned long addr;
	int i, num_tmp_segs=1;
        int ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;
	struct vaddr_info *vaddrs;
	unsigned long  flush_bytes;
	void *vaddrmin = (void *)-1UL, *vaddrmax = NULL;

	eid.cpu =1;

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
		case 'h':
		default :
			help();
			break;
	}

	//cpu_process_affinity(getpid(), eid.cpu);
	//sleep(2);

	vaddrs = malloc(num_tmp_segs * sizeof(struct vaddr_info));
	for (i = 0; i < num_tmp_segs; i++) {
		vaddrs[i].vaddr = malloc(PAGE_SIZE);
		//vaddrmin = min(vaddrmin, vaddrs[i].vaddr);
		//vaddrmax = max(vaddrmax, vaddrs[i].vaddr);
	}
	//flush_bytes = (vaddrmax - vaddrmin) + PAGE_SIZE;
	//printf("vaddrmin %p, vaddrmax %p, bytes 0x%lx\n", vaddrmin, vaddrmax, flush_bytes);
	printf("vaddrs 0x%lx\n", vaddrs);
        eid.length = PAGE_SIZE;
   	eid.addr = (unsigned long)vaddrs[0].vaddr;
	for (i = 0; i < num_tmp_segs; i++) {
		memset(vaddrs[i].vaddr, 2, PAGE_SIZE);
	}
#if 0
  	buf[0] = 0;
        eid.faultit = 0;
        eid.length = 3;
   	eid.addr = (ulong)buf;
	//falut in pages
        for (i = 0; i < (PAGE_SIZE > 8); i++) {
        	if (buf[i]) {
                        printf("buf[%d] = %x\n", i, buf[i]);
                }
	}
#endif
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	}                                               
	
            
	if ((ret = ioctl(fd, ioctlcmd, &eid )) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}                                               

	printf("return eid.addr \t%#018lx \n", eid.addr);
	printf("Enter char to memset..");
	getchar();
	for (i = 0; i < num_tmp_segs; i++) {
		memset(vaddrs[i].vaddr, 1, PAGE_SIZE);
	}
#if 0
	//Access pages again to trigger fault?
        for (i = 0; i < (PAGE_SIZE > 8); i++) {
		printf("i %d, page_size %d\n", i, PAGE_SIZE);
        	if (buf[i]) {
                        printf("buf[%d] = %x\n", i, buf[i]);
                }
         }
#endif
	printf("Enter char to free..");
	getchar();
	for (i = 0; i < num_tmp_segs; i++) {
		free (vaddrs[i].vaddr);
	}
	free(vaddrs);
	close(fd);                                      
	return 0;                                       
}
