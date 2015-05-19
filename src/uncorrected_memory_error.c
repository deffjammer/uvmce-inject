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


#define PAGE_SIZE (1 << 12)

int buf[PAGE_SIZE] __attribute__ ((aligned(128)));


void help(){
	printf("Options:\n");
} 
int main (int argc, char** argv) {                                     
	int fd, ret, c, ume_test = 1;
	static char optstr[] = "uc:";
	unsigned long addr;
	int i;

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

  	buf[0] = 0;

        eid.faultit = 0;
        eid.length = 3;
        //eid.addr = addr;
        for (i = 0; i < (PAGE_SIZE > 8); i++) {
        	if (buf[i]) {
                        printf("buf[%d] = %x\n", i, buf[i]);
                }
	}
	if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
		printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	}                                               
	
   	eid.addr = (ulong)buf;
#if 0
	if ((ret = ioctl(fd, UVMCE_INJECT_UME, &eid)) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}
#endif                                           
	if ((ret = ioctl(fd, UVMCE_INJECT_UME_AT_ADDR, &eid )) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	}                                               

	printf("return eid.addr 0x%lx\n", eid.addr);


        for (i = 0; i < (PAGE_SIZE > 8); i++) {
        	if (buf[i]) {
                        printf("buf[%d] = %x\n", i, buf[i]);
                }
                /* buf[i] = 0; */
         }

        sleep(3);


	close(fd);                                      
	return 0;                                       
}
