/* */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <asm/user_64.h>
#include <asm/elf.h>
#include <asm/debugreg.h>

#include "watchpoints.h"

MODULE_AUTHOR("Bogdan-Alexandru Stoica <bogdan.stoica@epfl.ch>");
MODULE_DESCRIPTION
    ("Set watchpoints from proc without going through ptrace");
MODULE_LICENSE("GPL");

#define DEVICE_NAME "watchpoints"

/*
 * Globals declaration
 */

/* file operations for the watchpoint entry in /dev */
const struct file_operations ctrl_fops = {
  .owner = THIS_MODULE,
  .read = NULL,
  .write = NULL,
  .unlocked_ioctl = watchpoint_ioctl,
  .open = NULL,
  .release = NULL,
};

/* informations about the watchpoint entry in /dev */
struct miscdevice watchpoints_misc = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = DEVICE_NAME,
  .fops = &ctrl_fops
};

/* file operations for the pointer entries in /proc/watchpoints/pid */
const struct file_operations proc_fops = {
  .owner = THIS_MODULE,
  .open = proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release
};

/* entry in the proc directory for the module */
proc_dir_entry *proc_watchpoints;

/* centralizes everything that is tracked by the module */
kmodule_context *tracked_pids[1<<HBITS];

// TODO: Add #ifdef macros for debugging

/* register the initialization and cleanup functions */
module_init(watchpoint_init);
module_exit(watchpoint_exit);

inline
uint32_t fnv_hash(uint64_t pid) {

  uint64_t hval64 = FNV_INIT;
  uint32_t hval = 0;

  while (pid > 0) {
    hval64 = (hval64 * FNV_MULT) ^ (pid % 10);
    pid /= 10;
  }
  hval = hval64 & ( (1 << HBITS) - 1 );

  return hval;
}

static int
__init watchpoint_init(void) {

  int i;

  for (i = 0; i < (1<<HBITS); ++i) {
    tracked_pids[i] = NULL;
  }

  proc_watchpoints = proc_mkdir("watchpoints", NULL);
  misc_register(&watchpoints_misc);

  pr_err("[kernel-space]: module successfully loaded\n");

  return 0;
}


static void
__exit watchpoint_exit(void) {

  int rval = 0;

  rval = clean_kmodule_context();
  remove_proc_entry("watchpoints", NULL);
  misc_deregister(&watchpoints_misc);
  pr_err("[kernel-space]: module successfully unloaded\n");
}


static int
proc_display(struct seq_file *m, void *v) {

  addr_list *entry = (struct addr_list *) m->private;

  seq_printf(m, "Watchpoint on <0x%llx> of size <%lld>.",
    entry->event->attr.bp_addr, entry->event->attr.bp_len);

  return 0;
}

static int
proc_open(struct inode *inode, struct file *file) {

  return single_open(file, proc_display, PDE_DATA(inode));
}

static int
proc_init(void) {

  kmodule_context *proc;
  proc_dir_entry *pid_entry;
  addr_list *entry;
  uint8_t pid_name[30];
  uint64_t pid;
  uint32_t hval;

  proc = kmalloc(sizeof(*proc), 0);
  entry = kmalloc(sizeof(*entry), 0);
  // spin_lock_init(entry->lock);
  INIT_LIST_HEAD(&entry->head);

  sprintf(pid_name, "%d", current->pid);
  pid_entry = proc_mkdir(pid_name, proc_watchpoints);
  proc->proc_entry = pid_entry;
  proc->pid = current->pid;
  proc->addresses = entry;
  INIT_LIST_HEAD(&proc->head);
  // spin_lock_init(proc->lock);

  pid = current->pid;
  hval = fnv_hash(pid);
  tracked_pids[hval] = proc;

  return 0;
}

static int
addr_list_add(struct perf_event *event, uint64_t user_buff) {

  // TODO: check return values + pr_debug("[kernel-space]: ... ");
  kmodule_context *tracked_pid;
  addr_list *entry;
  uint32_t hval;
  uint64_t pid = current->pid;

  entry = kmalloc(sizeof(*entry), 0);
  entry->event = event;
  entry->nr_accesses = 0;
  entry->user_buff = user_buff;
  // spin_lock_init(entry->lock);

  hval = fnv_hash(pid);
  if (tracked_pids[hval] == NULL) {
    // pr_err("[kernel]: [error]: NULL pid entry for %d", (int)current->pid);
    return -1;
  }
  tracked_pid = tracked_pids[hval];
  //spin_lock(tracked_pid->lock);
  list_add(&(entry->head), &(tracked_pid->addresses->head));
  //spin_unlock(tracked_pid->lock);

  return 0;
}

addr_list *
addr_list_get(uint64_t addr) {

  kmodule_context *tracked_pid;
  addr_list *entry, *temp;
  int wp_regs;
  uint32_t hval;
  uint64_t pid = current->pid;

  hval = fnv_hash(pid);

  if (tracked_pids[hval] == NULL) {
    pr_err("[kernel]: [error]: NULL pid entry for %d", (int)current->pid);
    return NULL;
  }
  tracked_pid = tracked_pids[hval];

  //spin_lock(tracked_pid->lock);
  wp_regs = 0;
  list_for_each_entry_safe(entry, temp, &(tracked_pid->addresses->head), head) {

    if (entry->event->attr.bp_addr == addr) {
      //spin_unlock(tracked_pid->lock);
      return entry;
    }
  }
  //spin_unlock(tracked_pid->lock);

  return NULL;
}


static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {

  addr_list *entry;
  wp_msg_t wp;
  uint64_t pc, dereg = -1;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  pc = (uint64_t)regs->ip;
  entry = addr_list_get(bp->attr.bp_addr);

  //spin_lock(entry->lock);
  if (entry == NULL) {
    // pr_err("[kernel-space]: No watchpoint on address <0x%llx>.\n", (uint64_t)bp->attr.bp_addr);
    return;
  }

  // pr_info("[kernel-space]: Watchpoint fired on address <0x%llx>.\n", (uint64_t)bp->attr.bp_addr);

  if (entry->nr_accesses == MAX_WP_TRAPS) {

    wp.data_ptr = bp->attr.bp_addr;
    wp.data_size = bp->attr.bp_len;
    copy_to_user((__user void *)entry->user_buff, &dereg, sizeof(dereg));
    entry->user_buff += sizeof(dereg);
    watchpoint_remove(&wp);

  } else {
    copy_to_user((__user void *)entry->user_buff, &pc, sizeof(pc));
    entry->user_buff += sizeof(pc);
    entry->nr_accesses++;
  }
  //spin_unlock(entry->lock);

  return;
}

static struct perf_event *
initialize_watchpoint(wp_msg_t *wp, pid_t pid) {

  struct perf_event *perf_watchpoint;
  struct task_struct *tsk;
  struct perf_event_attr attr;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  /* Initialize watchpoint */
  hw_breakpoint_init(&attr);
  attr.bp_addr = wp->data_ptr;
  attr.bp_len = 1; //MEM_ALIGN(&wp->data_ptr, wp->data_size);
  attr.bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W;

  tsk = pid_task(find_vpid(pid), PIDTYPE_PID);

  perf_watchpoint =
      register_user_hw_breakpoint(&attr, watchpoint_handler, NULL, tsk);

  if (IS_ERR(perf_watchpoint)) {
    pr_err("[kernel]: [error]: Cannot set watchpoint on %llx, size %llu, pid %d (code %ld).\n",
      attr.bp_addr, attr.bp_len, (int)pid, PTR_ERR(perf_watchpoint));
    return NULL;
  }

  return perf_watchpoint;
}

static int
watchpoint_add(wp_msg_t *wp, uint64_t user_buff) {

  struct perf_event *perf_watchpoint;
  int rval;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  if (addr_list_get(wp->data_ptr) != NULL) {
    pr_info("[kernel]: Breakpoint already set on <0x%llx>", wp->data_ptr);
    return -1;
  }

  perf_watchpoint = initialize_watchpoint(wp, current->pid);

  if (perf_watchpoint == NULL) {
    return -1;
  }

  rval = addr_list_add(perf_watchpoint, user_buff);
  if (rval < 0) {
    return -1;
  }

  return 0;
}

static int
watchpoint_modify(wp_msg_t *wp_old, wp_msg_t *wp_new) {

  addr_list *entry;
  struct perf_event_attr attr;
  int rval;

  if (wp_old == NULL || wp_old->data_ptr == 0) {
    pr_err("[kernel-space]: [error]: Invalid address.\n");
    return -1;
  }

  entry = addr_list_get(wp_old->data_ptr);
  if (entry == NULL) {
    pr_info("[kernel]: [error]: No watchpoint on address 0x%llx.\n", wp_old->data_ptr);
    return -1;
  }

  if (entry->event == NULL) {
    pr_info("[kernel]: Empty perf_event structure for 0x%llx", wp_old->data_ptr);
  }

  attr.bp_addr = wp_new->data_ptr;
  attr.bp_len = 1; //MEM_ALIGN(&wp->data_ptr, wp->data_size);
  attr.bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W;
  rval = modify_user_hw_breakpoint(entry->event, &attr);

  if (rval != 0) {
    return -1;
  }

  list_del(&entry->head);
  kfree(entry);

  return 0;
}


static int
watchpoint_remove(wp_msg_t *wp) {

  addr_list *entry;

  if (wp == NULL || wp->data_ptr == 0) {
    // pr_err("[kernel-space]: [error]: Invalid address.\n");
    return -1;
  }

  entry = addr_list_get(wp->data_ptr);
  if (entry == NULL) {
    pr_info("[kernel]: [error]: No watchpoint on address 0x%llx.\n", wp->data_ptr);
    return -1;
  }

  if (entry->event == NULL) {
    pr_info("[kernel]: Empty perf_event structure for 0x%llx", wp->data_ptr);
  }

  unregister_hw_breakpoint(entry->event);

  list_del(&entry->head);
  kfree(entry);

  return 0;
}

static long
watchpoint_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg) {

  usr_msg_t usr;
  int rval;
  uint64_t pid;
  uint32_t hval;

  rval = copy_from_user(&usr, (void *)user_msg, sizeof(usr));
  if (rval != 0 && cmd != CLEAN_KMODULE) {
    pr_err("[kernel]: Cannot copy ioctl message from user (%llx, %d): %d.\n",
     (uint64_t)(void *)user_msg, cmd, rval);
    return -EINVAL;
  }

  pid = current->pid;
  hval = fnv_hash(pid);
  if (tracked_pids[hval] == NULL) {
    proc_init();
  }

  // pr_err("[kernel-space]: cmd = %x, on <0x%llx> (size %u)\n",
  //     cmd, (uint64_t)usr.wp.data_ptr, usr.wp.data_size);

  // pr_info("[kernel]: Active watchpoints: %d\n", no_watchpoints);

  switch (cmd) {
    case ADD_WATCHPOINT:
      rval = watchpoint_add(&usr.wp, usr.user_buff);
      // pr_err("[kernel]: Done adding with outcome %ld\n", rval);
      break;
    case MODIFY_WATCHPOINT:
      rval = watchpoint_modify(&usr.wp, NULL);
      break;
    case REMOVE_WATCHPOINT:
      rval = watchpoint_remove(&usr.wp);
      // pr_err("[kernel]: Done removing with outcome %ld\n", rval);
      break;
    case CLEAN_KMODULE:
      rval = clean_kmodule_context();
      break;
    default:
      // pr_err("[kernel-space]: Watchpoints was sent an unknown command %d\n", cmd);
      rval = -EINVAL;
      break;
  }

#ifdef DEBUG_PRINT
  // pr_err("[kernel-space]: Done removing with outcome %d\n", (int)rval);
#endif

  return rval;
}

static int
clean_addr_list(addr_list *addresses) {

  addr_list *entry;
  addr_list *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  if (addresses == NULL) {
    return memory_used;
  }

  list_for_each_entry_safe(entry, temp, &addresses->head, head) {

    memory_used += ksize(entry);
    list_del(&entry->head);
    kfree(entry);
  }

  return memory_used;
}

static int
clean_kmodule_context(void) {

  kmodule_context *pid_list;
  kmodule_context *temp;
  size_t memory_used = 0, per_pid = 0;
  uint64_t pid, hval;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");
  pid = current->pid;
  hval = fnv_hash(pid);
  if (tracked_pids[hval] == NULL) {
    return 0;
  }
  list_for_each_entry_safe(pid_list, temp, &tracked_pids[hval]->head, head) {
    uint8_t pid_name[30];

    per_pid = clean_addr_list(pid_list->addresses);
    memory_used += per_pid;

    sprintf(pid_name, "%d", pid_list->pid);
    remove_proc_entry(pid_name, proc_watchpoints);

    memory_used += ksize(pid_list);
    list_del(&pid_list->head);
    kfree(pid_list);
  }
  tracked_pids[hval]->pid = -1;
  // pr_err("%lu bytes freed\n", memory_used);

  return 0;
}
