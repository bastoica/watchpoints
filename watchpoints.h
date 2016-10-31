#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

/*
 * Macros declaration
 */

/* on x86_64 there are only 4 watchpoints */
#define WATCHPOINTS_MAX (4)

#define ADD_WATCHPOINT      (0x1000)
#define POLL_WATCHPOINT     (0x2000)
#define REMOVE_WATCHPOINT   (0x4000)
#define CLEAN_KMODULE       (0x8000)

#define MAX_BUF_LEN         (0x400)

/* */
#define MAX_ACCESSES    (1000) /* 64K buffers */

/* Returns the minimum between two values */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Structs declarations
 */

typedef struct perf_event perf_event;

typedef struct proc_dir_entry proc_dir_entry;

typedef struct kmodule_context_list kmodule_context_list;

/* representation of a change in data */
typedef struct values_list {
  /* new value of the data */
  u8 *data;
  /* size of the data chunk */
  size_t data_size;
  /* list to which the data belongs */
  struct list_head head;
} values_list;

typedef struct accesses_list {
  /* new value of the data */
  uint64_t pc;
  /* list to which the data belongs */
  struct list_head head;
} accesses_list;

/* information about a pointer tracked by a watchpoint */
typedef struct mem_loc_list {
  /* pointer tracked */
  perf_event *event;
  /* size of the pointer data area */
  size_t size;
  /* list to which the pointer belongs */
  struct list_head head;
  /* changes to the data to which the pointer points */
  values_list *values;
  /* PCs that access the memory location */
  accesses_list *accesses;
  /* Number of accesses */
  uint no_accesses;
  /* User-space buffer address to copy PCs */
  uint64_t ubuff;
} mem_loc_list;

/* information about a pid tracked */
struct kmodule_context_list {
  /* pid tracked */
  pid_t pid;
  /* process /proc directory enter */
  proc_dir_entry *proc_entry;
  /* list of pointers to track for this pid */
  mem_loc_list *pointers;
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
  uint64_t ubuff;
} usr_msg_t;

/*
 * Function prototypes
 */

 /* handles the opening of a pointer file */
static int proc_open(struct inode *inode, struct file *file);

/* handles the display of information on the pointer file */
static int proc_display(struct seq_file *m, void *v);

/* handles the watchpoint event */
static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

/* handles the ioctl event */
static long
watchpoints_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg);

/* initialization function for the module */
static int
__init watchpoint_init(void);

/* cleanup function for the module */
static void
__exit watchpoint_exit(void);

/* gets the head of the pointer list for the specified pid */
struct mem_loc_list *
get_mem_loc_entry(uint64_t addr);

/* initializes the watchpoint */
static struct perf_event *
initialize_watchpoint(wp_msg_t *wp, pid_t pid);

/* adds a new pointer to the list of pointers tracked by the pid */
static void
add_mem_loc_entry(struct perf_event *event, uint64_t ubuff);

/* adds a new watchpoint */
static long
add_watchpoint(wp_msg_t *wp, uint64_t ubuff);

/* probe a watchpoint for memory accesses */
static long
poll_watchpoint(wp_msg_t *wp, uint64_t ubuff);

/* removes a watchpoint */
static long
remove_watchpoint(wp_msg_t *wp, uint64_t ubuff);

/* frees all values recorded and returns the size used by the data */
static size_t
clean_values_list(values_list *values);

/* frees all PCs recorded and returns the size used by the data */
static size_t
clean_accesses_list(accesses_list *accesses);

/* frees all pointers recorded and returns the size used by them */
static size_t
clean_mem_loc_list(mem_loc_list *pointers);

/* free all proc records and return the size used by them */
static int
clean_kmodule_context(void) ;

#endif