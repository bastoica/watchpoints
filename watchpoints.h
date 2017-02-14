#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

/*
 * Macros declaration
 */

/* on x86_64 there are only 4 watchpoints */
#define INTEL_HW_WP  (4)
#define MAX_PIDS (65536)

#define HBITS    (16)
#define FNV_MULT (16777619)
#define FNV_INIT (2166136261)

#define WATCHPOINT_ADD    (0x1000)
#define WATCHPOINT_MODIFY (0x2000)
#define WATCHPOINT_REMOVE (0x4000)
#define CLEANUP  (0x8000)

#define INF64 (0xFFFFFFFFFFFFFFFFL)
#define MAX_TRAPS (100)

/* Returns the minimum between two values */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Structs declarations
 */

/* Tracing information per address */
typedef struct _wp_list_unit_t {
    struct perf_event *active;            /* active watchpoint */
    uint num_traps;                       /* number of traps elapsed */
    uint64_t itrace_ptr;                  /* user-space buffer to store PCs */
} wp_list_unit_t;

/* Tracing information per process */
typedef struct _proc_context_t {
    pid_t pid;                            /* calling pid */
    struct proc_dir_entry *proc_entry;    /* process directory unit in /proc */
    wp_list_unit_t watched[INTEL_HW_WP];  /* list of traced addresses */
    int no_active;                        /* no of active breakpoint registers */
} proc_context_t;

/* Watchpoint internal struct */
typedef struct _watchpoint_t {
    uint64_t addr;                        /* traced address */
    uint32_t len;                         /* traced address size */
} watchpoint_t;

/* IOCTL message received form a process */
typedef struct ioctl_t {
    watchpoint_t set;                     /* watchpoint to add */
    watchpoint_t modif;                   /* watchpoint to modify */
    uint64_t itrace_ptr;                  /* user-space buffer to store PCs */
} ioctl_t;


typedef struct wpcontext_t {
    proc_context_t *traced_pids[MAX_PIDS];
    int no_entries;
} wpcontext_t;


/*
 * Function prototypes
 */

/* initialization function for the module */
static int
__init wpmodule_init(void);

/* cleanup function for the module */
static void
__exit wpmodule_exit(void);

 /* handles the opening of a pointer file */
static int
proc_open(struct inode *inode, struct file *file);

/* handles the display of information on the pointer file */
static int
proc_display(struct seq_file *m, void *v);

/* */
static int
proc_init(void);

/* free all proc records and return the size used by them */
static int
proc_free(int pid);

/* Gracefully clean data structures and release active hardware breakpoints after a crash */
static int
proc_crash(struct inode *ind, struct file *fl);

/* handles the watchpoint event */
static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

/* handles the ioctl event */
static long
watchpoint_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg);

/* init */
static void
wplist_init(wp_list_unit_t *unit);

/* gets the head of the pointer list for the specified pid */
static wp_list_unit_t *
wplist_search(uint64_t addr);

/* adds a new pointer to the list of pointers tracked by the pid */
static int
wplist_add(struct perf_event *active, uint64_t usrspace_ptr);

/* modifies a current pointer tracked by the pid */
static int
wplist_modify(wp_list_unit_t *active, struct perf_event_attr *attr, uint64_t ptr);

/* removes an entry from the watchpoint list */
static void
wplist_clean(wp_list_unit_t *unit);

/* frees all pointers recorded and returns the size used by them */
static void
wplist_free(proc_context_t *proc);

/* initializes the watchpoint */
static struct perf_event *
watchpoint_init(watchpoint_t *wp, pid_t pid);

/* adds a new watchpoint */
static int
watchpoint_add(watchpoint_t *wp, uint64_t usrspace_ptr);

/* probe a watchpoint for memory accesses */
static int
watchpoint_modify(watchpoint_t *watch, watchpoint_t *swtich, uint64_t ptr);

/* removes a watchpoint */
static int
watchpoint_remove(watchpoint_t *wp);

#ifdef DEBUG
static int
wplist_print(void);
#endif /* DEBUG */

#endif /* WATCHPOINTS_H */