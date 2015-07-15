#ifndef __UVMCE_H__
#define __UVMCE_H__

/*
 *  _IO    an ioctl with no parameters
 *  _IOW   an ioctl with write parameters (copy_from_user)
 *  _IOR   an ioctl with read parameters  (copy_to_user)
 *  _IOWR  an ioctl with both write and read parameters.
 */

#define UVMCE_MAGIC 's'                                                   
 
//#define UVMCE_INJECT_UME          _IO(UVMCE_MAGIC, 1 ) 
#define UVMCE_INJECT_UME          _IOR(UVMCE_MAGIC, 1 , char* ) 
#define UVMCE_INJECT_UME_AT_ADDR  _IOW(UVMCE_MAGIC, 2 , char *)
#define UVMCE_DLOOK               _IOW(UVMCE_MAGIC, 3 , char *)
#define UVMCE_POLL_SCRATCH14      _IOW(UVMCE_MAGIC, 4 , char *)
#if 0
typedef struct {
        unsigned long   pte;            /* physical address of page */
        signed short    nid;            /* node id (logical) */
        signed short    pnid;           /* physical node id */
        unsigned int    flags;          /* page attribute flags */
} page_desc_t;



struct dlook_get_map_info {
        pid_t           pid;
        size_t          start_vaddr;
        size_t          end_vaddr;
        page_desc_t     *pd;
};              
#endif 

struct err_inj_data {
	pid_t pid;
        unsigned long addr;
        unsigned long length;
        int cpu;
        int faultit;
        unsigned int flags;
};                              


#endif /* __UVMCE_H__ */

