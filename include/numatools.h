/*
 *  Copyright (c) 2004-2008 Silicon Graphics, Inc.
 *  All rights reserved.
 *
 *    Jack Steiner <steiner@sgi.com>
 *    Erik Jacobson <erikj@sgi.com>
 */

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */


/*
 * This file contains definitions shared by the numatools loadable kernel
 * module, and by the numatools commands/libraries that use the module.
 *
 * This is NOT an external API or user interface.
 */



#ifndef __NUMATOOLS_H_
#define __NUMATOOLS_H_

#ifndef __KERNEL__
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#endif

/* These definitions are used with the NUMA /proc/numatools IOCTL interface */

#define NUMATOOLS_BASE	"numatools"
#define PROC_NUMATOOLS	"/proc/" NUMATOOLS_BASE
#define NUMA_IOCTL_NUM	'A'

/* no-op */
#define NOOP			_IOWR(NUMA_IOCTL_NUM, 0, void *)

/* Create a new affinity aggregate. */
#define DPLACE_CREATE		_IOWR(NUMA_IOCTL_NUM, 1, void *)

/* Get process mem map info. */
#define DLOOK_GET_TASK_MAP_INFO	_IOWR(NUMA_IOCTL_NUM, 2, void *)

/* Get dplace system info. */
#define DPLACE_GET_SYSTEM_LOAD	_IOWR(NUMA_IOCTL_NUM, 4, void *)

/* Get dplace cpus allowed. */
#define DPLACE_GET_CPUS_ALLOWED	_IOWR(NUMA_IOCTL_NUM, 5, void *)

/* Free the buffer cache */
#define FREE_BUFFER_CACHE	_IOWR(NUMA_IOCTL_NUM, 6, void *)

/* Get info about running jobs */
#define DPLACE_GET_JOB_INFO	_IOWR(NUMA_IOCTL_NUM, 7, void *)

/* libdplace ioctl */
#define DPLACE_IOCTL		_IOWR(NUMA_IOCTL_NUM, 8, void *)

/* test if NUMA support is available */
#define DPLACE_TEST_NUMA	_IOWR(NUMA_IOCTL_NUM, 9, void *)

/* Get process shared (RSS) mapping info */
#define DLOOK_GET_MAP_SUM_INFO	_IOWR(NUMA_IOCTL_NUM,10, void *)

/* Get reattach an orphan task after an exec following a system() call */
#define DPLACE_REATTACH_ORPHAN	_IOWR(NUMA_IOCTL_NUM,11, void *)

#define NAMESIZE	16		/* maximum length of a process name. */
					/* should match size from sched.h */

#ifndef __KERNEL__   /* Function only needed for user commands */
/* paggctl:
 *
 * The paggctl function does pagg ioctl operations using /proc/dplace
 *
 * Note that this replaces the old system call method.
 *
 */

static int paggctl(unsigned int ioctl_num, void *data) __attribute__ ((unused));
static int paggctl(unsigned int ioctl_num, void *data) {
	static int fd;
	int rc;

	fd = open(PROC_NUMATOOLS, 0);
	if (fd < 0) {
		printf("Can't open proc file %s\n", PROC_NUMATOOLS);
		return -1;
	}

	rc = ioctl(fd, ioctl_num, data);
	if (rc < 0) {
		close(fd);
		return -errno;
	}

	close(fd);
	return rc;
}

#endif /* __KERNEL__ */


/*
 * Define the request block that is passed to paggctl to create a new process
 * aggregate to manage process placement.
 */
struct cpulist {
	unsigned short		count;		/* actual array size */
	unsigned short		nextcpu;	/* next cpu index for if no load balance */
	short			cpu[1];		/* dynamic array of cpu nums */
};
#define CPULIST_SIZE(n)		(sizeof(struct cpulist) + sizeof(short)*((n)-1))

struct cpurellist {
	unsigned short		start;		/* starting value */
	unsigned short		end;		/* ending value */
	struct cpu_rel		*list;		/* per-cpu creating threads */
};

/* attach an array of this structure (sized by the oncpu list) to
   the cpurellist structure */
struct cpu_rel {
	unsigned short		cpu;		/* thread created from this */
	unsigned short		start;		/* next cpu number to use */
};

struct namelist {
	unsigned short		count;		/* actual array size */
	char			name[1][NAMESIZE]; /* dynamic array of names */
};
#define NAMELIST_SIZE(n)	(sizeof(struct namelist) + NAMESIZE*((n)-1))


struct placement_desc {
	struct namelist		*namelist;	/* name list of processes to be placed */
	struct namelist		*parentlist;	/* parent list of processes to be placed */
	struct cpulist		*oncpulist;	/* on only processes that fork/exec on these cpus */
	struct cpulist		*cpulist;	/* cpus for placement */
	struct cpurellist	*cpurellist;	/* cpu relative for placement */
	unsigned long		skip_count;	/* skip placement on first n processes */
	unsigned long		no_place;	/* mask for skipping placement */
	unsigned long		options;	/* misc flags */
	unsigned short		textrep;	/* bitmask of replication options (SO_xxx)*/
	/* ---- kernel use only ---- */
	unsigned long		no_place_count;	/* index into no_place bitarray */
	short			nextcpu;	/* used for roundrobin cpu placement if no cpulist */
};

#define REQBLK_MAGIC 893823   /* for dplace/module sanity check */
struct dplace_create_reqblk {
	int			magic;		/* dplace/module sanity */
	unsigned short		count;		/* actual array size */
	char			placefile;	/* using placement file */
	char			no_pagg;	/* unused since it's never pagg anymore */
	long			unused1;
	long			unused2;
	int			cpu;		/* OUT: cpu assigned to new task */
	char			name[NAMESIZE];	/* process name that will be exec'd */
	struct placement_desc	pd[1];		/* dynamic array of placement_desc */
};
#define CREATE_SIZE(n)		(sizeof(struct dplace_create_reqblk) + sizeof(struct placement_desc)*((n)-1))

/* Flags for placement_desc options */
#define	NOLOADBALANCE	0x00000001		/* Dont load balance. Use cpus in exact order in array */
#define FORCEPLACE	0x00000002		/* force current process to be placed (override name check) */
#define ONETIME		0x00000004		/* at end of exact placement, cancel entry */
#define CANCELED	0x00000008		/* Ignore entry */
#define EXECPLACE	0x00000010		/* PD is for EXEC placement */
#define FORKPLACE	0x00000020		/* PD is for FORK placement */
#define THREADPLACE	0x00000040		/* PD is for THREAD placement */
#define FIRSTPLACE	0x00000080		/* PD is for placement of first task*/

/* Flags for replication options */
#define	TRO_APP		0x0001
#define TRO_DSO		0x0002
#define	TRO_APP_RW	0x0004
#define TRO_DSO_RW	0x0008
#define TRO_THREADS	0x8000

#define TRO_NULL	0
#define TRO_REQUIRED	(TRO_APP | TRO_DSO | TRO_APP_RW | TRO_DSO_RW)	/* One of these bits must be set if rep_options is not TRO_NONE */

/*
 * Define the request block that is passed to paggctl by dplace to get info on the current
 * system load.
 */
struct dplace_system_load {
	unsigned int	count;			/* Number of cpus in list */
	int		*dplace_load;		/* pointer to physical per-cpu load. */
	long		unused1;
	long		unused2;
};

/*
 * Define the request block that is passed to paggctl by dplace to get info on the active
 * dplace jobs.
 */
struct dplace_desc_job {
	int		key;
	unsigned int	tasks;
	uid_t		uid;
};

struct dplace_desc_task {
	pid_t		pid;
	short		cpu;
	char		name[NAMESIZE];
};

struct dplace_desc {
	char	is_job;
	union {
		struct dplace_desc_job job;
		struct dplace_desc_task task;
	} u;
};

struct dplace_job_info {
	unsigned int		desc_count;		/* Number of entries in list */
	char			show_tasks;		/* fetch detailed task info */
	struct dplace_desc 	descs[1];		/* pointer to array of descriptors */
};


/*
 * Define the request block that is passed to numatools.ko by libdplace
 */
struct dplace_ioctl_req {
	int		reqcode;		/* function code (fork, exec, etc) */
	void		*vaddr;			/* vaddr of /proc/numatools */
	void		*nodemask;		/* OUT: pointer to nodemask */
	short		*textrep;		/* OUT: pointer to textrep */  
	int		cpu;			/* OUT: cpu assigned to new task */
	char		name[NAMESIZE];		/* process name that will be exec'd */
};
#define DP_PRE_FORK			0
#define DP_POST_FORK_PARENT		1
#define DP_PRE_EXEC			2
#define DP_PRE_PTHREAD_CREATE		3
#define DP_POST_PTHREAD_CREATE_PARENT	4
#define DP_PTHREAD_EXIT			5
#define DP_CANCEL_AFFINITY		6
#define DP_GET_CPU			7
#define DP_GET_REPLICATION_INFO		8
#define DP_GET_SYSTEM_CALL_KEY		9


/*
 * Define the request block that is passed to paggctl by dplace to get info on the current
 * cpus that the user is allowed to use.
 */
struct dplace_cpus_allowed_info {
	unsigned int	cpumap_count;		/* Number of cpus in list */
	short		*cpumap;		/* pointer to cpus allowed.array */
};

/*
 * Define the request block that is passed to paggctl by bcfree to free
 * buffer cache pages.
 */
struct bcfree_info {
	int		free_slab_caches;	/* free slab caches */
	int		node;			/* node to free */
};
#define NO_NODES	-2
#define ALL_NODES	-1

/*
 * Page attribute flags
 */
#define PD_SWAPPED		0x0001
#define PD_RAM			0x0002
#define PD_DIRTY		0x0004
#define PD_SHARED		0x0008

#define PD_RW			0x0010
#define PD_RESERVED		0x0020
#define PD_MA_UC		0x0040

#define PD_HP_2MB		0x0100
#define PD_HP_1GB		0x0200
#define PD_HOLE			0x8000

#define PD_PADDR_MASK		0x0000fffffffff000UL

typedef struct {
	unsigned long	pte;		/* physical address of page */
	signed short	nid;		/* node id (logical) */
	signed short	pnid;		/* physical node id */
	unsigned int	flags;		/* page attribute flags */
} page_desc_t;

#define NULL_DESC	{0, 0, 0, 0}

static inline long
get_nodeid(page_desc_t desc)
{
	return desc.nid;
}

static inline long
get_pnodeid(page_desc_t desc)
{
	return desc.pnid;
}

static inline long
get_paddr(page_desc_t desc)
{
	return desc.pte & PD_PADDR_MASK;
}

static inline int
get_memory_attr(page_desc_t desc)
{
	return  desc.flags;
}

static inline int
get_pagesize(page_desc_t desc)
{
	if (desc.flags & PD_HP_1GB)
		return 1UL * 1024 * 1024 * 1024;
	else if (desc.flags & PD_HP_2MB)
		return 2UL * 1024 * 1024;
	else
		return 4 * 1024;

}

struct dlook_get_map_info {
	pid_t		pid;
	size_t		start_vaddr;
	size_t		end_vaddr;
	page_desc_t	*pd;
};

struct mapsum_get_map_sum {
	pid_t	pid;
	long	weighted_sum;
};
#define PG_WSIZE_FRAC 2048


#ifdef __KERNEL__   /* Functions needed in the kernel */
#include <linux/fs.h>

#define NUMATOOLS_TRACE 1
#if NUMATOOLS_TRACE
#define DDprintk(s, x...)  if (trace) printk("%d:%d %s: " s, current->pid, smp_processor_id(), __FUNCTION__, x)
#else
#define DDprintk(x...)
#endif

extern int trace;
int dlook_get_task_map_info(void *data);
int dlook_get_task_map_info(void *data);
int dlook_get_system_info(void *data);
int dplace_create(struct file *file, void *data);
int dplace_reattach_orphan(struct file *file, void *data);
int dplace_file_open(struct inode *ip, struct file *fp);
int dplace_file_mmap(struct file *file, struct vm_area_struct *vma);
int dplace_file_release(struct inode *inode, struct file *file);
int dplace_get_job_info(void *data);
int dplace_ioctl(struct file *file, void *data);
int dplace_get_system_load(void *data);
int dplace_get_cpus_allowed(void *data);
int dplace_module_init(void);
void dplace_module_exit(void);

int mapsum_get_map_sum_info(void *data);

/*
 * The following structure is the job container data structure for placement. All processes of the same
 * placement aggregate point to an instance of this data structure. It is used for controlling placement
 * of the processes.
 */
struct dplace_control {
	struct list_head		control_list;	/* list of all control structures */
	struct list_head		task_list;	/* list of all tasks in placement group structures */
	struct mutex			task_list_lock;	/* task_list lock */
	int				key;		/* unique ID of job */
	uid_t				uid;		/* uid of task that created dplace group */
	atomic_t			refcnt;		/* Number of processes sharing the placement group. */
	char				firsttask;	/* flag to indicate if first 'exec' has been done */
	struct dplace_create_reqblk	*req;		/* Placement descriptors */
	cpumask_t			cpus_allowed;	/* last snapshot of cpus in cpuset. */
	short				cpu_count;	/* number of cpus in cpulist */
	short				cpumap[NR_CPUS]; /* logical -> physical mapping for cpus_allowed */
};


/*
 * The following structure is a per-task structure. It contains info about placement
 * for the task.
 */
struct task_control {
	struct list_head	task_list;	/* list of all tasks in placement group structures */
	struct placement_desc	*pd;		/* placement desc used to place task */
	atomic_t		refcnt;		/* Reference count to the task control structure */
	pid_t			pid;		/* PID of task */
	struct dplace_control	*ctl;		/* Pointer to global dplace info */
	int			cpu;		/* logical (cpuset relative) cpu that task has been
						   place on. (-1 = not placed) */
	int			physcpu;	/* physical cpu that task has been place on.
						   (-1 = not placed) */
	char			name[NAMESIZE];	/* process name. From task struct at fork/exec. */
};

#endif /* __KERNEL__ */



#endif /* __NUMATOOLS_H_ */
