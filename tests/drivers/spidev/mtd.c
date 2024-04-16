#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#define PROC_NAME "mtd"

const char *proc_file_content = "dev:    size   erasesize  name\n\
mtd0: 04000000 00010000 \"bmc\"\n\
mtd1: 02012040 00010000 \"root\"\n";
char buffer[128];
static int len = 1;

struct proc_dir_entry *ent;

/**
 * @brief Function that is called when read the mtd file
 * 
 */
static ssize_t mtd_read(struct file *file, char __user *data, size_t size, loff_t *offset) {
    int rv;
    int res;

    printk(KERN_INFO "MTD: Read mtd\n");

    if(len) {
        len = 0;
    }
    else {
        len = 1;
        return 0;
    }

    rv = sprintf(buffer, "%s", proc_file_content);
    printk(KERN_INFO "rv = %d\n", rv);

    res = copy_to_user(data, buffer, rv);
    if(res == 0) {
        printk(KERN_INFO "MTD: Copy to user success!\n");
    }
    else {
        printk(KERN_INFO "MTD: Copy to user failed!\n");
    }

    return size;
}

/* Proc operation structure */
static struct proc_ops proc_ops = {
    .proc_read = mtd_read,
};

/**
 * @brief Function that is called when the proc file is loaded into the kernel.
 * 
 */
static int __init mtd_init(void) {
    ent = proc_create(PROC_NAME, 0, NULL, &proc_ops);

    if(ent != NULL) {
        printk(KERN_INFO "MTD: /proc/%s created!\n", PROC_NAME);
    }
    else {
        printk(KERN_INFO "MTD: Failed to created /proc/%s!\n", PROC_NAME);
        return -1;
    }

return 0;
}

/**
 * @brief Function that is called when the proc file is removed from the kernel.
 * 
 */
static void __exit mtd_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "MTD: /proc/%s removed!\n", PROC_NAME);
}

module_init(mtd_init);
module_exit(mtd_exit);

/* Meta Information */
MODULE_AUTHOR("Mateusz Mydlarz");
MODULE_DESCRIPTION("Create /proc/mtd file and implement basic callback functions.");
MODULE_VERSION("1.0");
MODULE_LICENSE("Internal");
