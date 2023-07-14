#include <linux/printk.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
// #include <asm-generic/errno-base.h>

MODULE_AUTHOR("squ");
MODULE_LICENSE("Dual BSD/GPL");

enum CMD {
    ALLOC = 0x0d00,
    FREE,
    UAFW,
    UAFR,
};

static void *myptr;
static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    struct {
        uint64_t addr;
        uint64_t len;
    } u;

    long ret = 0;

    switch(cmd) {
        case ALLOC: {
            pr_info("GFP_KERNEL_ACCOUNT is %x", GFP_KERNEL_ACCOUNT);
            myptr = kmalloc(arg, GFP_KERNEL_ACCOUNT);
            break;
        }
        case FREE: {
            kfree(myptr);
            break;
        }
        case UAFW: {
            if (copy_from_user(&u, (void *)arg, sizeof(u))) {
                return -1;
            }
            if (copy_from_user(myptr, (void *)u.addr, u.len)) {
                return -1;
            }
            break;
        }
        case UAFR: {
            if (copy_from_user(&u, (void *)arg, sizeof(u))) {
                return -1;
            }
            if (copy_to_user((void *)u.addr, myptr, u.len)) {
                return -1;
            }
            break;
        }
        default:
            return -EINVAL;
    }


    return ret;
}

static struct file_operations vuln_fops = {
    .owner          = THIS_MODULE,
    .open           = NULL,
    .release        = NULL,
    .read           = NULL,
    .write          = NULL,
    .unlocked_ioctl = vuln_ioctl
};

static struct miscdevice vuln_miscdev = {
    .minor = MISC_DYNAMIC_MINOR, 
    .name  = "vuln", 
    .fops  = &vuln_fops
};

static int __init vuln_init(void) {
    pr_info("vuln: module init.\n");
    misc_register(&vuln_miscdev);
    return 0;
}

static void __exit vuln_exit(void) {
    pr_info("vuln: module exit.\n");
    misc_deregister(&vuln_miscdev);
}

module_init(vuln_init);
module_exit(vuln_exit);