#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x5c0c0377, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x781fcaa4, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0x91be1677, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0xa9b789a6, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x44b1d426, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x840ce4ba, __VMLINUX_SYMBOL_STR(unregister_hw_breakpoint) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xde990047, __VMLINUX_SYMBOL_STR(misc_deregister) },
	{ 0x5fc4c1a7, __VMLINUX_SYMBOL_STR(misc_register) },
	{ 0xed26343e, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0x5e55b0a6, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x243d0674, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x2bd306c9, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x56d4ca56, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0xe519be40, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0x55393eb6, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xac07b6c6, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x4ea5d10, __VMLINUX_SYMBOL_STR(ksize) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x8981fc30, __VMLINUX_SYMBOL_STR(register_user_hw_breakpoint) },
	{ 0x279abf6b, __VMLINUX_SYMBOL_STR(pid_task) },
	{ 0x109a2b21, __VMLINUX_SYMBOL_STR(find_vpid) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "25508BC84533FB5AC67128D");
