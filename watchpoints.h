#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

/*
 * Macros declaration
 */

 #define MEM_ALIGN(ptr, len) ( ((((uintptr_t)(const void *)ptr) % len) == 0) ? len : 1 )

#define HBITS               (16)
#define FNV_MULT            (16777619)
#define FNV_INIT            (2166136261)

/* on x86_64 there are only 4 watchpoints */
#define MAX_HW_WATCHPOINTS  (4)

#define ADD_WATCHPOINT      (0x1000)
#define MODIFY_WATCHPOINT   (0x2000)
#define REMOVE_WATCHPOINT   (0x4000)
#define CLEAN_KMODULE       (0x8000)

#define MAX_BUF_LEN         (0x400)

/* */
#define MAX_ACCESSES        (102)
#define MAX_WP_TRAPS        (MAX_ACCESSES - 2)

/* Returns the minimum between two values */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Structs declarations
 */

typedef struct perf_event perf_event;

typedef struct proc_dir_entry proc_dir_entry;

typedef struct kmodule_context kmodule_context;

/* information about a pointer tracked by a watchpoint */
typedef struct addr_list {
  /* Multi-threaded synchronization */
  //spinlock_t *lock;
  /* list to which the pointer belongs */
  struct list_head head;
  /* pointer tracked */
  perf_event *event;
  /* size of the pointer data area */
  size_t size;
  /* Number of accesses */
  uint nr_accesses;
  /* Kernel-space buffer to store PCs */
  uint64_t kernel_buff[MAX_ACCESSES];
  /* User-space buffer to copy PCs */
  uint64_t user_buff;
} addr_list;

/* information about a pid tracked */
struct kmodule_context {
  /* Multi-threaded synchronization */
  //spinlock_t *lock;
  /* pid tracked */
  pid_t pid;
  /* process /proc directory enter */
  proc_dir_entry *proc_entry;
  /* list of pointers to track for this pid */
  addr_list *addresses;
  /* list to which the pointer belongs */
  struct list_head head;
};

typedef struct _wp_msg_t {
  /* */
  uint64_t data_ptr;
  /* */
  uint32_t data_size;
} wp_msg_t;

typedef struct usr_msg_t {
  /* */
  wp_msg_t wp;
  /* */
  uint64_t user_buff;
} usr_msg_t;

/*
 * Function prototypes
 */

/* initialization function for the module */
static int
__init watchpoint_init(void);

/* cleanup function for the module */
static void
__exit watchpoint_exit(void);

 /* handles the opening of a pointer file */
static int
proc_open(struct inode *inode, struct file *file);

/* handles the display of information on the pointer file */
static int
proc_display(struct seq_file *m, void *v);

/* */
static int
proc_init(void);

/* handles the watchpoint event */
static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

/* handles the ioctl event */
static long
watchpoint_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg);

/* gets the head of the pointer list for the specified pid */
struct addr_list *
addr_list_get(uint64_t addr);

/* initializes the watchpoint */
static struct perf_event *
initialize_watchpoint(wp_msg_t *wp, pid_t pid);

/* adds a new pointer to the list of pointers tracked by the pid */
static int
addr_list_add(struct perf_event *event, uint64_t user_buff);

/* adds a new watchpoint */
static int
watchpoint_add(wp_msg_t *wp, uint64_t user_buff);

/* probe a watchpoint for memory accesses */
static int
watchpoint_modify(wp_msg_t *wp_old, wp_msg_t *wp_new);

/* removes a watchpoint */
static int
watchpoint_remove(wp_msg_t *wp);

/* frees all pointers recorded and returns the size used by them */
static int
clean_addr_list(addr_list *pointers);

/* free all proc records and return the size used by them */
static int
clean_kmodule_context(void) ;

#endif