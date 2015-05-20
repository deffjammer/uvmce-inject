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

#define UVMCE_DEVICE "/dev/uvmce"                   
#define PAGE_SIZE (1 << 12)
struct err_inj_data eid;

int buf[PAGE_SIZE] __attribute__ ((aligned(128)));


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
	int fd, ret, c, ume_test = 1;
	static char optstr[] = "kuc:";
	unsigned long addr;
	int i;
        int ioctlcmd = UVMCE_INJECT_UME_AT_ADDR;

	eid.cpu = 1;

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

	cpu_process_affinity(getpid(), eid.cpu);

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
	sleep(2);

	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	}                                               
	
            
	if ((ret = ioctl(fd, ioctlcmd, &eid )) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}                                               

	printf("return eid.addr 0x%lx\n", eid.addr);

	//Access pages again to trigger fault?
        for (i = 0; i < (PAGE_SIZE > 8); i++) {
        	if (buf[i]) {
                        printf("buf[%d] = %x\n", i, buf[i]);
                }
         }

        sleep(2);


	close(fd);                                      
	return 0;                                       
}
