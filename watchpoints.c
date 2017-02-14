/* */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#undef DEBUG

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
#include <linux/spinlock.h>
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

/* file operations for the watchpoint unit in /dev */
const struct file_operations ctrl_fops = {
    .owner = THIS_MODULE,
    .read = NULL,
    .write = NULL,
    .unlocked_ioctl = watchpoint_ioctl,
    .open = NULL,
    .release = proc_crash,
};

/* informations about the watchpoint unit in /dev */
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

/* unit in the proc directory for the module */
struct proc_dir_entry *proc_watchpoints;

/* centralizes everything that is tracked by the module */
wpcontext_t wpcontext;

// TODO: Add #ifdef macros for debugging

/* register the initialization and cleanup functions */
module_init(wpmodule_init);
module_exit(wpmodule_exit);

#ifdef DEBUG
static int
wplist_print(void) {

    proc_context_t *proc;
    int i;

    if (current->pid >= MAX_PIDS) return 0;

    proc = wpcontext.traced_pids[current->pid];
    if (proc == NULL) {
        return 0;
    }

    pr_info("--- Watchpoint list (PID %d) ---\n", current->pid);
    for (i = 0; i < INTEL_HW_WP; ++i) {
        if (proc->watched[i].active != NULL) {
            pr_info("0x%llx", proc->watched[i].active->attr.bp_addr);
        }
    }

    return 0;
}
#endif /* DEBUG */

static int
__init wpmodule_init(void) {

    int i;

    for (i = 0; i < MAX_PIDS; ++i) {
        wpcontext.traced_pids[i] = NULL;
    }

    proc_watchpoints = proc_mkdir("watchpoints", NULL);
    misc_register(&watchpoints_misc);

    pr_info("module successfully loaded\n");

    return 0;
}


static void
__exit wpmodule_exit(void) {

    int pid;

    for (pid = 0; pid < MAX_PIDS; ++pid) {
        proc_free(pid);
    }
    remove_proc_entry("watchpoints", NULL);
    misc_deregister(&watchpoints_misc);
    pr_info("module successfully unloaded\n");
}


static int
proc_display(struct seq_file *m, void *v) {

    wp_list_unit_t *unit = (wp_list_unit_t *) m->private;

    seq_printf(m, "Watchpoint on <0x%llx> of size <%lld>.",
        unit->active->attr.bp_addr, unit->active->attr.bp_len);

    return 0;
}

static int
proc_open(struct inode *inode, struct file *file) {

    return single_open(file, proc_display, PDE_DATA(inode));
}

static int
proc_init(void) {

    proc_context_t *proc;
    struct proc_dir_entry *pid_entry;
    uint8_t pid_name[30];
    int i;

    if (current->pid > MAX_PIDS) {
        pr_info("PID too large.\n");
        return -EINVAL;
    }

    proc = wpcontext.traced_pids[current->pid];
    if (proc != NULL) {
        return 0;
    }

    proc = kmalloc(sizeof(*proc), 0);
    proc->pid = current->pid;
    sprintf(pid_name, "%d", current->pid);
    pid_entry = proc_mkdir(pid_name, proc_watchpoints);
    proc->proc_entry = pid_entry;
    proc->pid = current->pid;
    proc->no_active = 0;
    for (i = 0; i < INTEL_HW_WP; ++i) {
        wplist_init(&(proc->watched[i]));
    }
    wpcontext.traced_pids[current->pid] = proc;
    ++wpcontext.no_entries;

    return 0;
}

static int
proc_crash(struct inode *ind, struct file *fl) {

    // pr_info("PID %d crashed. Cleaning up.\n", current->pid);
    proc_free(current->pid);
    return 0;
}

static int
proc_free(int pid) {

    uint8_t pid_name[30];

    if (wpcontext.traced_pids[pid] == NULL) {
        return 0;
    }

    sprintf(pid_name, "%d", pid);
    remove_proc_entry(pid_name, proc_watchpoints);
    wplist_free(wpcontext.traced_pids[pid]);

    kfree(wpcontext.traced_pids[pid]);
    wpcontext.traced_pids[pid] = NULL;

    return 0;
}


static void
wplist_init(wp_list_unit_t *unit) {

    unit->active = NULL;
    unit->num_traps = 0;
    unit->itrace_ptr = 0;
}

static int
wplist_add(struct perf_event *event, uint64_t itrace_ptr) {

    // TODO: check return values + pr_debug(" ... ");
    wp_list_unit_t *unit;
    proc_context_t *proc;

    proc = wpcontext.traced_pids[current->pid];
    if (proc == NULL) {
        pr_info("PID [%d] currently not traced.\n", current->pid);
        return -EINVAL;
    }

    if (proc->no_active == INTEL_HW_WP) {
        pr_info("Hardware breakpoints resources full\n");
        return -EBUSY;
    }

    unit = &(proc->watched[proc->no_active]);
    unit->active = event;
    unit->num_traps = 0;
    unit->itrace_ptr = itrace_ptr;
    ++proc->no_active;

    return 0;
}

static wp_list_unit_t *
wplist_search(uint64_t addr) {

    proc_context_t *proc;
    int i;

    proc = wpcontext.traced_pids[current->pid];
    if (proc == NULL) {
        pr_err("[error]: NULL pid unit for %d", (int)current->pid);
        return NULL;
    }

    for (i = 0; i < INTEL_HW_WP; ++i) {

        if (proc->watched[i].active == NULL) {
            continue;
        }
        if (proc->watched[i].active->attr.bp_addr == addr) {
            return &(proc->watched[i]);
        }
    }

    return NULL;
}

static int
wplist_modify(wp_list_unit_t *unit, struct perf_event_attr *attr, uint64_t ptr) {

    unit->active->attr.bp_addr = attr->bp_addr;
    unit->active->attr.bp_len  = attr->bp_len;
    unit->active->attr.bp_type = attr->bp_type;
    unit->itrace_ptr = ptr;

    return 0;
}


static void
wplist_clean(wp_list_unit_t *unit) {

    if (unit->active != NULL) {
        unregister_hw_breakpoint(unit->active);
        unit->active = NULL;
    }
    unit->num_traps = 0;
    unit->itrace_ptr = 0;
}

static void
wplist_free(proc_context_t *proc) {

    int i;

    if (proc == NULL) {
        return;
    }

    for (i = 0; i < INTEL_HW_WP; ++i) {
        wplist_clean(&proc->watched[i]);
    }

    return;
}

static void
watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {

    int ret;
    wp_list_unit_t *unit;
    watchpoint_t modif, zero;
    uint64_t pc;

    // TODO: check return values + pr_debug("... ");

    zero.addr = zero.len = 0;
    pc = (uint64_t)regs->ip;
    unit = wplist_search(bp->attr.bp_addr);

    if (unit == NULL) {
        pr_err("[error]: No watchpoint to modify at <0x%llx> (pid: %d).\n",
            (uint64_t)bp->attr.bp_addr, (int)current->pid);
        return;
    }

    if (unit->num_traps == MAX_TRAPS) {

        modif.addr = bp->attr.bp_addr;
        modif.len  = bp->attr.bp_len;
        pc = INF64;
        ret = copy_to_user((__user void *)unit->itrace_ptr, &pc, sizeof(pc));
        unit->itrace_ptr += sizeof(pc);
        // pr_err("[warning]: Modifying watchpoint at <0x%llx> (pid: %d)", modif.addr, current->pid);
        watchpoint_modify(&zero, &modif, 0);
        unit->num_traps = 0;

    } else {

        if (unit->itrace_ptr > 0) {
            ret = copy_to_user((__user void *)unit->itrace_ptr, &pc, sizeof(pc));
            unit->itrace_ptr += sizeof(pc);
            ++unit->num_traps;
        }
    }

    return;
}

static struct perf_event *
watchpoint_init(watchpoint_t *set, pid_t pid) {

    struct perf_event *perf_watchpoint;
    struct task_struct *tsk;
    struct perf_event_attr attr;

    // TODO: check return values + pr_debug("... ");

    /* Initialize watchpoint */
    hw_breakpoint_init(&attr);
    attr.bp_addr = set->addr;
    attr.bp_len  = 1;
    attr.bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W;

    tsk = pid_task(find_vpid(pid), PIDTYPE_PID);

    perf_watchpoint =
            register_user_hw_breakpoint(&attr, watchpoint_handler, NULL, tsk);

    if (IS_ERR(perf_watchpoint)) {
        pr_err("[error]: code %ld: Cannot set watchpoint on <%llx> (pid: %d).\n",
            PTR_ERR(perf_watchpoint), attr.bp_addr, (int)current->pid);
        return NULL;
    }

    return perf_watchpoint;
}

static int
watchpoint_add(watchpoint_t *set, uint64_t itrace_ptr) {

    struct perf_event *perf_watchpoint;
    int ret;

    // TODO: check return values + pr_debug("... ");

    if (wplist_search(set->addr) != NULL) {
        pr_debug("[warning]: Watchpoint already set on <0x%llx>", set->addr);
        return -ENXIO;
    }

    /* Attempt to add a new watchpoint */
    perf_watchpoint = watchpoint_init(set, current->pid);
    if (perf_watchpoint == NULL) {
        pr_err("[error]: Cannot add watchpoint at <0x%llx> (pid: %d)",
            set->addr, (int)current->pid);
        return -EPERM;
    }

    /* Update bookeeping */
    ret = wplist_add(perf_watchpoint, itrace_ptr);
    if (ret < 0) {
        return ret;
    }

#ifdef DEBUG
    wplist_print();
#endif

    return 0;
}

static int
watchpoint_modify(watchpoint_t *set, watchpoint_t *modif, uint64_t ptr) {

    wp_list_unit_t *unit;
    struct perf_event_attr attr;
    int ret;

    /* Check for invalid data */
    if (set == NULL || modif == NULL) {
        pr_err("[error]: Invalid watchpoint\n");
        return -EINVAL;
    }

    /* Search for active watchpoints at $addr */
    unit = wplist_search(modif->addr);
    if (unit == NULL) {
        pr_err("[error]: No watchpoint on <0x%llx> (pid: %d)\n", modif->addr, current->pid);
        return -ENOENT;
    }

    /* Check current watchpoint struct */
    if (unit->active == NULL) {
        pr_err("[error]: Empty perf_event structure for <0x%llx>", modif->addr);
        return -EFAULT;
    }

    /* Attempt to modify the active watchpoint */
    attr.bp_addr = set->addr;
    attr.bp_len  = 1;
    attr.bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W;
    ret = modify_user_hw_breakpoint(unit->active, &attr);

    if (ret != 0) {
        return -EPERM;
    }

    /* Update bookeeping */
    wplist_modify(unit, &attr, ptr);

#ifdef DEBUG
    wplist_print();
#endif

    return 0;
}


static int
watchpoint_remove(watchpoint_t *set) {

    wp_list_unit_t *unit;

    /* Check for invalid data */
    if (set == NULL) {
        pr_err("[error]: Attempting to remove an invalid address\n");
        return -EINVAL;
    }

    /* Search for active watchpoints at $addr */
    unit = wplist_search(set->addr);
    if (unit == NULL) {
        pr_debug("[warning]: No watchpoint on address <0x%llx>\n", set->addr);
        return -ENOENT;
    }

    /* Check current watchpoint struct */
    if (unit->active == NULL) {
        pr_err("[error]: Empty perf_event structure for <0x%llx>", set->addr);
        return -EFAULT;
    }

    /* Unregister watchpoint and update bookeeping */
    wplist_clean(unit);
    --wpcontext.traced_pids[current->pid]->no_active;

    return 0;
}

static long
watchpoint_ioctl(struct file *file, unsigned int cmd, unsigned long user_msg) {

    ioctl_t msg;
    int ret;

    ret = copy_from_user(&msg, (void *)user_msg, sizeof(msg));
    if (ret != 0 && cmd != CLEANUP) {
        pr_err(" Cannot copy ioctl message from user (code %d).\n", ret);
        return -EINVAL;
    }

    proc_init();

    switch (cmd) {
        case WATCHPOINT_ADD:
            ret = watchpoint_add(&msg.set, msg.itrace_ptr);
            break;
        case WATCHPOINT_MODIFY:
            ret = watchpoint_modify(&msg.set, &msg.modif, msg.itrace_ptr);
            break;
        case WATCHPOINT_REMOVE:
            ret = watchpoint_remove(&msg.set);
            break;
        case CLEANUP:
            ret = proc_free(current->pid);
            break;
        default:
            pr_err("Invalid command %d\n", cmd);
            ret = -EINVAL;
            break;
    }

    return ret;
}