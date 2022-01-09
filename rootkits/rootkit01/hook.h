#ifndef HOOK_H
#define HOOK_H
#include <linux/ftrace.h>

#define pr_hook(string, ...) pr_info("hook_api : %s  : " string, __func__, ## __VA_ARGS__)
#define create_hook(symbolname, hooked, original) {.symbol_name = symbolname, .hooked_func = hooked, .original_func = original}
#define create_original(ret, name) static ret (*name) (const struct pt_regs * registers)

typedef struct hook_st{
	const char * symbol_name;
	void * original_func;
	void * hooked_func;
	struct ftrace_ops ftrace_operations;
} hook, *phook;

static int get_original_func_address(struct hook_st * hook){
	unsigned long func_address;

	func_address = kallsyms_lookup_name(hook->symbol_name);
	if (!func_address){
		pr_hook("Unresolved symbol name : %s\n", hook->symbol_name);
		return -1;
	}

	*((unsigned long *)hook->original_func) = func_address;
	return 0;
}


static void ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops * fops, struct pt_regs * registers){
	struct hook_st * hook;
	hook = container_of(fops, struct hook_st, ftrace_operations);
	if (!within_module(parent_ip, THIS_MODULE)){
		registers->ip = hook->hooked_func;
	}
}

static int InstallHook(struct hook_st * hook){
	int err;

	err = get_original_func_address(hook);
	if (err)
		return 1;

	hook->ftrace_operations.func = ftrace_callback;
	hook->ftrace_operations.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ftrace_operations, *((unsigned long*)hook->original_func), 0, 0);
	if (err){
		pr_hook("Failed seting ftrace filter\n");
		return 1;
	}

	err = register_ftrace_function(&hook->ftrace_operations);
	if (err){
		pr_hook("Failed registering functions\n");
		return 1;
	}

	pr_hook("Hooked installed in [%s]\n", hook->symbol_name);
	return 0;
}


static void RemoveHook(struct hook_st * hook){
	unregister_ftrace_function(&hook->ftrace_operations);
}



#endif // HOOK_H
