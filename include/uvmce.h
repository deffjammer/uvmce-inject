#ifndef __UVMCE_H__
#define __UVMCE_H__

/*
 *  _IO    an ioctl with no parameters
 *  _IOW   an ioctl with write parameters (copy_from_user)
 *  _IOR   an ioctl with read parameters  (copy_to_user)
 *  _IOWR  an ioctl with both write and read parameters.
 */

#define UVMCE_MAGIC 's'                                                   
 
#define UVMCE_INJECT_UME          _IO(UVMCE_MAGIC, 1 ) 
#define UVMCE_INJECT_UME_AT_ADDR  _IOW(UVMCE_MAGIC, 2 , char *)

struct err_inj_data {
        unsigned long addr;
        unsigned long length;
        int faultit;
        unsigned int flags;
};                              


#endif /* __UVMCE_H__ */

