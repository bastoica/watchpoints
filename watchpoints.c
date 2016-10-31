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
  .unlocked_ioctl = watchpoints_ioctl,
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


int no_wathcpoints = 0;
int no_clean_calls = 0;

/* entry in the proc directory for the module */
proc_dir_entry *proc_watchpoints;

/* centralizes everything that is tracked by the module */
kmodule_context_list kmodule_context;

// TODO: Add #ifdef macros for debugging

/* register the initialization and cleanup functions */
module_init(watchpoint_init);
module_exit(watchpoint_exit);

static int
__init watchpoint_init(void) {

  proc_watchpoints = proc_mkdir("watchpoints", NULL);
  INIT_LIST_HEAD(&kmodule_context.head);
  misc_register(&watchpoints_misc);
  pr_info("[kernel-space]: module successfully loaded\n");

  return 0;
}


static void
__exit watchpoint_exit(void) {

  int rval = 0;

  rval = clean_kmodule_context();
  remove_proc_entry("watchpoints", NULL);
  misc_deregister(&watchpoints_misc);
  pr_info("[kernel-space]: module successfully unloaded\n");
}


static int
proc_display(struct seq_file *m, void *v) {

  mem_loc_list *pointer = (struct mem_loc_list *) m->private;
  values_list *change;

  list_for_each_entry(change, &pointer->values->head, head) {
    long counter;
    seq_printf(m, "%lu ", change->data_size);
    for (counter = 0; counter < change->data_size; counter++) {
      seq_printf(m, "%c", change->data[counter]);
    }
  }

  return 0;
}

static int
proc_open(struct inode *inode, struct file *file) {

  return single_open(file, proc_display, PDE_DATA(inode));
}

static kmodule_context_list *
get_addr_for_pid(void) {

  // TODO: check return values + pr_debug("[kernel-space]: ... ");
  kmodule_context_list *proc;
  kmodule_context_list *iter;
  proc_dir_entry *pid_entry;
  mem_loc_list *pointers;
  uint8_t pid_name[30];

  list_for_each_entry(iter, &kmodule_context.head, head) {
    if (iter->pid == current->pid) {
      return iter;
    }
  }

  proc = kmalloc(sizeof(*proc), 0);
  pointers = kmalloc(sizeof(*pointers), 0);

  sprintf(pid_name, "%d", current->pid);
  pid_entry = proc_mkdir(pid_name, proc_watchpoints);
  proc->proc_entry = pid_entry;
  proc->pid = current->pid;
  proc->pointers = pointers;

  INIT_LIST_HEAD(&pointers->head);
  list_add_tail(&(proc->head), &kmodule_context.head);

  return proc;
}


static void
add_mem_loc_entry(struct perf_event *event, uint64_t ubuff) {

  // TODO: check return values + pr_debug("[kernel-space]: ... ");
  kmodule_context_list *tracked_pid;
  mem_loc_list *mem_loc;
  accesses_list *accesses;
  values_list *values;

  tracked_pid = NULL;
  tracked_pid = get_addr_for_pid();

  if (tracked_pid == NULL) {
    return;
  }

  if (get_mem_loc_entry((uint64_t)event->attr.bp_addr) != NULL) {
    pr_info("[kernel-space]: <0x%llx> not found.\n", (uint64_t)event->attr.bp_addr);
    return;
  }

  accesses = kmalloc(sizeof(*accesses), 0);
  values = kmalloc(sizeof(*values), 0);

  mem_loc = kmalloc(sizeof(*mem_loc), 0);
  mem_loc->event = event;
  mem_loc->size = event->attr.bp_len;
  mem_loc->no_accesses = 0;
  mem_loc->accesses = accesses;
  mem_loc->values = values;
  mem_loc->ubuff = ubuff;

  pr_info("[kernel-space]: Adding <0x%llx> with <%p>.\n",
    (uint64_t)event->attr.bp_addr, mem_loc);

  INIT_LIST_HEAD(&accesses->head);
  INIT_LIST_HEAD(&values->head);

  list_add_tail(&(mem_loc->head), &tracked_pid->pointers->head);
}

mem_loc_list *
get_mem_loc_entry(uint64_t addrs) {

  kmodule_context_list *tracked_pid;
  mem_loc_list *mem_loc;

  tracked_pid = get_addr_for_pid();
  if (tracked_pid == NULL) {
    // TODO: pr_debug("[kernel-space]: ... ");
    return NULL;
  }

  list_for_each_entry(mem_loc, &tracked_pid->pointers->head, head) {
    if (mem_loc->event->attr.bp_addr == addrs) {
      return mem_loc;
    }
  }

  // TODO: pr_debug("[kernel-space]: ... ");
  return NULL;
}


static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {

  mem_loc_list *pointer;
  accesses_list *access;
  wp_msg_t wp;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  pointer = get_mem_loc_entry(bp->attr.bp_addr);

  if (pointer == NULL) {
    pr_info("[kernel-space]: No watchpoint on address <0x%llx>.\n", (uint64_t)bp->attr.bp_addr);
    return;
  }

  /* Cheap run-length encoding */
  //if (access->pc != regs->ip) {

  pr_info("[kernel-space]: Watchpoint fired on <0x%llx>.\n", (uint64_t)bp->attr.bp_addr);

    access = kmalloc(sizeof(*access), 0);
    access->pc = regs->ip;

    list_add_tail(&(access->head), &(pointer->accesses->head));

    if (pointer->no_accesses == MAX_ACCESSES) {

      wp.data_ptr = bp->attr.bp_addr;
      wp.data_size = bp->attr.bp_len;
      remove_watchpoint(&wp, pointer->ubuff);
    }
  //}

  /*********** Record values ***********/
  // FIXME: We can run out of memory if there are many entries. There will be panic.

  // new_change = kmalloc(sizeof(*new_change), 0);
  // new_change->data = kmalloc((pointer->size + 1) * sizeof(u8), 0);
  // new_change->data[pointer->size] = '\0';

  // copy_from_user(new_change->data,
  //          (void *) pointer->event->attr.bp_addr,
  //          pointer->size);
  // new_change->data_size = pointer->size;
  // // list_add_tail(&(new_change->head), &pointer->values->head);

  // pr_info("[kernel-space]: Process %d accessed 0x%016llx from PC=0x%016llu, value: %s\n",
  //    bp->ctx->task->pid, pointer->event->attr.bp_addr, entry->pc, new_change->data);

  // kfree(new_change);

  return;
}

static struct perf_event *
initialize_watchpoint(wp_msg_t *wp, pid_t pid) {

  struct perf_event *perf_watchpoint;
  struct task_struct *tsk;
  struct perf_event_attr attr;
  struct pt_regs *regs;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  /* Initialize watchpoint */
  hw_breakpoint_init(&attr);
  attr.bp_addr = wp->data_ptr;
  attr.bp_len = wp->data_size;
  attr.bp_type = HW_BREAKPOINT_RW;

  tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
  regs = task_pt_regs(tsk);

  perf_watchpoint =
      register_user_hw_breakpoint(&attr, watchpoint_handler, NULL, tsk);

  return perf_watchpoint;
}

static long
add_watchpoint(wp_msg_t *wp, uint64_t ubuff) {

  struct perf_event *perf_watchpoint;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  if (get_mem_loc_entry((uint64_t)wp->data_ptr) != NULL) {
    pr_info("[kernel-space]: Breakpoint already set on <0x%llx>\n", (uint64_t)wp->data_ptr);
    return -1;
  }

  perf_watchpoint = initialize_watchpoint(wp, current->pid);

  if (IS_ERR(perf_watchpoint)) {
    pr_info("[kernel-space]: [error]: Could not set watchpoint.\n");
    return -1;
  }

  add_mem_loc_entry(perf_watchpoint, ubuff);

  no_wathcpoints++;

  return 0;
}

static long
poll_watchpoint(wp_msg_t *wp, uint64_t ubuff) {

  mem_loc_list *pointer;
  accesses_list *entry;
  accesses_list *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  pointer = get_mem_loc_entry((uint64_t)wp->data_ptr);
  if (pointer == NULL) {
    pr_info("[kernel-space]: [error]: No watchpoint on address 0x%llx.\n",
      (uint64_t)wp->data_ptr);
    return -1;
  }

  list_for_each_entry_safe(entry, temp, &pointer->accesses->head, head) {

    memory_used += ksize(entry);
    copy_to_user((__user void *)ubuff, &entry->pc, sizeof(entry->pc));
    kfree(entry);
  }

  return 0;
}

static long
remove_watchpoint(wp_msg_t *wp, uint64_t ubuff) {

  mem_loc_list *pointer;
  accesses_list *entry, *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  pointer = get_mem_loc_entry((uint64_t)wp->data_ptr);
  if (pointer == NULL) {
    pr_info("[kernel-space]: [error]: No watchpoint on address 0x%llx.\n",
      (uint64_t)wp->data_ptr);
    return -1;
  }

  list_for_each_entry_safe(entry, temp, &pointer->accesses->head, head) {

    memory_used += ksize(entry);
    copy_to_user((__user void *)ubuff, &entry->pc, sizeof(entry->pc));
    kfree(entry);
  }

  unregister_hw_breakpoint(pointer->event);

  memory_used += clean_values_list(pointer->values);
  memory_used += ksize(pointer);
  list_del(&pointer->head);
  kfree(pointer);

  no_wathcpoints--;

  return 0;
}

static long
watchpoints_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg) {

  usr_msg_t usr;
  long ret_val;

  ret_val = copy_from_user(&usr, (void *)user_msg, sizeof(usr));
  if (ret_val != 0 && cmd != CLEAN_KMODULE) {
    pr_info("[kernel-space]: Cannot copy ioctl message from user (%llx, %d): %ld.\n",
      (uint64_t)(void *)user_msg, cmd, ret_val);
    return -EINVAL;
  }

  pr_info("[kernel-space]: cmd = %x, on <0x%llx> (size %u), no_bps = %d (cleanups=%d)\n",
     cmd, (uint64_t)usr.wp.data_ptr, usr.wp.data_size, no_wathcpoints, no_clean_calls);

  switch (cmd) {
    case ADD_WATCHPOINT:
      ret_val = add_watchpoint(&usr.wp, usr.ubuff);
      pr_info("[kernel-space] Done adding with outcome %d\n", (int)ret_val);
      break;
    case POLL_WATCHPOINT:
      ret_val = poll_watchpoint(&usr.wp, usr.ubuff);
      pr_info("[kernel-space] Done polling with outcome %d\n", (int)ret_val);
      break;
    case REMOVE_WATCHPOINT:
      ret_val = remove_watchpoint(&usr.wp, usr.ubuff);
      pr_info("[kernel-space] Done removing with outcome %d\n", (int)ret_val);
      break;
    case CLEAN_KMODULE:
      ret_val = clean_kmodule_context();
      pr_info("[kernel-space] Done cleanup with outcome %d\n", (int)ret_val);
      no_wathcpoints = 0;
      no_clean_calls++;
      break;
    default:
      pr_debug("[kernel-space]: Watchpoints was sent an unknown command %d\n", cmd);
      ret_val = -EINVAL;
      break;
  }

  return ret_val;
}

static size_t
clean_values_list(values_list *values) {

  values_list *entry;
  values_list *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  list_for_each_entry_safe(entry, temp, &values->head, head) {

    memory_used += ksize(entry->data);
    kfree(entry->data);
    memory_used += ksize(entry);
    kfree(entry);
  }

  return memory_used;
}

static size_t
clean_accesses_list(accesses_list *accesses) {

  accesses_list *entry;
  accesses_list *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  list_for_each_entry_safe(entry, temp, &accesses->head, head) {

    memory_used += ksize(entry);
    // copy_to_user((__user void *)ubuff, entry->pc, sizeof(entry->pc));
    kfree(entry);
  }

  return memory_used;
}

static size_t
clean_mem_loc_list(mem_loc_list *pointers) {

  mem_loc_list *pointer;
  mem_loc_list *temp;
  size_t memory_used = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");

  if (pointers == NULL) {
    return memory_used;
  }

  list_for_each_entry_safe(pointer, temp, &pointers->head, head) {

    memory_used +=
          clean_values_list(pointer->values);

    memory_used +=
          clean_accesses_list(pointer->accesses);

    memory_used += ksize(pointer);
    list_del(&pointer->head);
    kfree(pointer);
  }

  return memory_used;
}

static int
clean_kmodule_context(void) {

  kmodule_context_list *pid_list;
  kmodule_context_list *temp;
  size_t memory_used = 0, per_pid = 0;

  // TODO: check return values + pr_debug("[kernel-space]: ... ");
  list_for_each_entry_safe(pid_list, temp, &kmodule_context.head, head) {
    uint8_t pid_name[30];

    per_pid = clean_mem_loc_list(pid_list->pointers);
    memory_used += per_pid;

    sprintf(pid_name, "%d", pid_list->pid);
    remove_proc_entry(pid_name, proc_watchpoints);

    memory_used += ksize(pid_list);
    list_del(&pid_list->head);
    kfree(pid_list);
  }
  pr_info("%lu bytes freed\n", memory_used);

  return 0;
}
