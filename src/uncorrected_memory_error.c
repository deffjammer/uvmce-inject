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
 
int main () {                                     
	  int fd;                                         
	  int ret;                                        
	  int i;                                          
	 
	  if ((fd = open(UVMCE_DEVICE, O_RDWR)) < 0) {                 
	  	printf("Failed to open: %s\n", UVMCE_DEVICE);  
	  	exit (1);                                     
	  }                                               
	  if ((ret = ioctl(fd, UVMCE_INJECT_UME )) < 0){        
	    	printf("Failed to INJECT_UME\n");
	    	exit(1);                                      
	  }                                               
                                              
	  close(fd);                                      
	  return 0;                                       
}
