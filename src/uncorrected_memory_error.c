/*
 * gcc -I../include/ uncorrected_memory_error.c -o  ume
 */
#include <stdio.h>                                
#include <stdlib.h>                                
#include <fcntl.h>                                
#include <unistd.h>                               
#include <linux/ioctl.h>
#include "uvmce.h"                           
#define UVMCE_DEVICE "/dev/uvmce"                   
struct err_inj_data eid;

void help(){
	printf("Options:\n");
} 
int main (int argc, char** argv) {                                     
	int fd, ret, c, ume_test = 1;
	static char optstr[] = "uc:";
	unsigned long addr;

        opterr = 1;
        while ((c = getopt(argc, argv, optstr)) != EOF)
                switch (c) {
                case 'u':
                	ume_test = 1;
                	break;
                case 'c':
                        //cpu_home = atoi(optarg);
                        break;
		case 'h':
		default :
			help();
			break;
	}

        eid.faultit = 0;
        eid.length = 3;
        eid.addr = addr;

	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	}                                               
	
	if ((ret = ioctl(fd, UVMCE_INJECT_UME, &eid)) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}
	printf("return eid.addr 0x%lx\n", eid.addr);

#if 0
	if ((ret = ioctl(fd, UVMCE_INJECT_UME_AT_ADDR, &eid )) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}                                               
#endif                                           
	close(fd);                                      
	return 0;                                       
}
