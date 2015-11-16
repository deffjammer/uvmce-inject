#ifndef __UVMCE_H__
#define __UVMCE_H__

/*
 *  _IO    an ioctl with no parameters
 *  _IOW   an ioctl with write parameters (copy_from_user)
 *  _IOR   an ioctl with read parameters  (copy_to_user)
 *  _IOWR  an ioctl with both write and read parameters.
 */

#define UVMCE_MAGIC 's'                                                   
 
#define UVMCE_INJECT_UME          _IOR(UVMCE_MAGIC, 1 , char* ) 
#define UVMCE_INJECT_UCE_AT_ADDR  _IOW(UVMCE_MAGIC, 2 , char *)
#define UVMCE_PATROL_SCRUB_UCE    _IOW(UVMCE_MAGIC, 3 , char *)
#define UVMCE_DLOOK               _IOW(UVMCE_MAGIC, 4 , char *)
#define UVMCE_POLL_SCRATCH14      _IOW(UVMCE_MAGIC, 5 , char *)

#define idstr() (show_pnodes ? "pnode" : "node ")

struct err_inj_data {
	pid_t pid;
        unsigned long addr;
        unsigned long length;
        int cpu;
        int nodeid;
        unsigned int flags;
};                              

/*
 * Older glibc headers don't have the si_addr_lsb field in the siginfo_t
 *  structure ... ugly hack to get it
 */
struct morebits {
        void    *addr;
	short   lsb;
};  
char* get_memory_attr_str(int , int );
long memsize(char *);

unsigned long long uv_vtop(unsigned long, int);
int cpu_process_setaffinity(pid_t, int);
void fault_pages(void *, long );

unsigned long poll_mmr_scratch14(int);
char *nodestr(long );

#endif /* __UVMCE_H__ */


