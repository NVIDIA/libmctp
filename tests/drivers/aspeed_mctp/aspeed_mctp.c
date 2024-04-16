#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/socket.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/wait.h>
#include <linux/slab.h>                 //kmalloc()
#include <linux/uaccess.h>              //copy_to/from_user()
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/sysfs.h> 
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/kfifo.h>
#include <linux/moduleparam.h>
#include <linux/version.h>

#include <linux/aspeed-mctp.h>

#define DEVICE_NAME_IN "aspeed-mctp"
#define DEVICE_NAME_OUT "aspeed-mctp-mock"

// Module parameters:
// skip_packets_in - if set to 1 then packets written
//   from tested application will not be transferred to
//   mocked driver (usefull for massive number of packets tests)
int skip_packets_in = 0;
module_param(skip_packets_in, int, 0664);

// Set module strings as variables, 
// so they may be configurable in the future
const char* mock_mctp_dev_name = DEVICE_NAME_IN;
const char* mock_mctp_dev_name_out = DEVICE_NAME_OUT;
static unsigned char* mock_mctp_proc_name = "mctp_" DEVICE_NAME_IN;

// Main driver module structure
struct drv {
	// main driver properties
	dev_t dev_in;
	struct class* kernel_class_in;
	struct cdev* kernel_cdev_in;

	// mock driver properties
	dev_t dev_out;
	struct class* kernel_class_out;
	struct cdev* kernel_cdev_out;

	// proc properties
	struct proc_dir_entry *mctp_entry;
};

static struct drv _mock_mctp_drv = {0};

// Sending data structures
DECLARE_WAIT_QUEUE_HEAD(mock_mctp_wait_queue_data_in);
DECLARE_WAIT_QUEUE_HEAD(mock_mctp_wait_queue_data_out);

struct data_pkt {
	ssize_t len;			// full length of the packet in bytes
	ssize_t offset;			// read write bytes from the packet
	char *buf;				// packet buffer pointer
};

static struct data_pkt *mock_mctp_current_packet_rin = NULL;
static struct data_pkt *mock_mctp_current_packet_rout = NULL;

struct mock_mctp_counters {
	int packets_written_in;
	int packets_read_in;
	long unsigned int bytes_written_in;
	long unsigned int bytes_read_in;
	int packet_fifo_in;
	int packets_written_out;
	int packets_read_out;
	long unsigned int bytes_written_out;
	long unsigned int bytes_read_out;
	int packet_fifo_out;
	int errors_copy_to_user_in;
	int errors_copy_from_user_in;
	int errors_copy_to_user_out;
	int errors_copy_from_user_out;
};

static struct mock_mctp_counters _mock_mctp_counters = { 0 };

#define MOCK_MCTP_FIFO_SIZE 			(1024*16)
DEFINE_KFIFO(mock_mctp_fifo_in, void*, MOCK_MCTP_FIFO_SIZE);
DEFINE_KFIFO(mock_mctp_fifo_out, void*, MOCK_MCTP_FIFO_SIZE);

// proc main internal variables
static char proc_buffer[2048];
static int proc_len = 1;

/**
 * @brief Function that is called when read the MCTP mock driver proc statistics
 * 
 */
static ssize_t mock_mctp_mtd_read(struct file *file, char __user *data, size_t size, loff_t *offset) {

    if (proc_len) {
        proc_len = 0;
    }
    else {
        proc_len = 1;
        return 0;
    }

    printk(KERN_INFO "[mock_mctp_mtd_read] Read mtd (size = %lu)\n", size);

    int rv = sprintf(proc_buffer, "Mock MCTP driver\n");
	char *buf_ptr = &(proc_buffer[rv]);

	// FIFOs status
	rv += sprintf(buf_ptr, "FIFO in: full = %d, empty = %d, len = %d, max = %d, skip = %d\n", 
			kfifo_is_full(&mock_mctp_fifo_in), kfifo_is_empty(&mock_mctp_fifo_in),
			kfifo_len(&mock_mctp_fifo_in), MOCK_MCTP_FIFO_SIZE, skip_packets_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "FIFO out: full = %d, empty = %d, len = %d, max = %d\n\n",
			kfifo_is_full(&mock_mctp_fifo_out), kfifo_is_empty(&mock_mctp_fifo_out),
			kfifo_len(&mock_mctp_fifo_out), MOCK_MCTP_FIFO_SIZE);
	buf_ptr = &(proc_buffer[rv]);

    // Read packets status
	if (mock_mctp_current_packet_rin == NULL) {
		rv += sprintf(buf_ptr, "mock_mctp_current_packet_rin is null\n");
	}
	else {
		rv += sprintf(buf_ptr, "mock_mctp_current_packet_rin len = %lu, offset = %lu\n", 
			mock_mctp_current_packet_rin->len, mock_mctp_current_packet_rin->offset);
	}
	buf_ptr = &(proc_buffer[rv]);

	if (mock_mctp_current_packet_rout == NULL) {
		rv += sprintf(buf_ptr, "mock_mctp_current_packet_rout is null\n");
	}
	else {
		rv += sprintf(buf_ptr, "mock_mctp_current_packet_rout len = %lu, offset = %lu\n", 
			mock_mctp_current_packet_rout->len, mock_mctp_current_packet_rout->offset);
	}
	buf_ptr = &(proc_buffer[rv]);

	// Print all counters
	rv += sprintf(buf_ptr, "\npackets_written_in\t\t: %d\n", _mock_mctp_counters.packets_written_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packets_read_in\t\t\t: %d\n", _mock_mctp_counters.packets_read_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_written_in\t\t: %lu\n", _mock_mctp_counters.bytes_written_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_read_in\t\t\t: %lu\n", _mock_mctp_counters.bytes_read_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packet_fifo_in\t\t\t: %d\n", _mock_mctp_counters.packet_fifo_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "\npackets_written_out\t\t: %d\n", _mock_mctp_counters.packets_written_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packets_read_out\t\t: %d\n", _mock_mctp_counters.packets_read_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_written_out\t\t: %lu\n", _mock_mctp_counters.bytes_written_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_read_out\t\t\t: %lu\n", _mock_mctp_counters.bytes_read_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packet_fifo_out\t\t\t: %d\n", _mock_mctp_counters.packet_fifo_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "\nerrors_copy_to_user_in\t\t: %d\n", _mock_mctp_counters.errors_copy_to_user_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_from_user_in\t: %d\n", _mock_mctp_counters.errors_copy_from_user_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_to_user_out\t\t: %d\n", _mock_mctp_counters.errors_copy_to_user_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_from_user_out\t: %d\n", _mock_mctp_counters.errors_copy_from_user_out);

    printk(KERN_INFO "[mock_mctp_mtd_read] rv = %d\n", rv);

    int missed = copy_to_user(data, proc_buffer, rv);
    if(missed != 0) {
        printk(KERN_INFO "[mock_mctp_mtd_read] Copy to user missed %d bytes\n", missed);
    }

    return rv;
}

/**
 * @brief Function that is called when write the MCTP mock driver proc
 * 			Use this to send a simple data block to demux demon
 * 
 */
static ssize_t mock_mctp_mtd_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
    printk(KERN_INFO "[mock_mctp_mtd_write] proc file write (len = %lu)\t", len);

	if (kfifo_is_full(&mock_mctp_fifo_out)) {
		return -EBUSY;
	}

	struct data_pkt *packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(len, GFP_KERNEL);
	packet->offset = 0;
	int missed = copy_from_user(packet->buf, buff, len);
	packet->len = len - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_out += 1;
		printk(KERN_ERR "[mock_mctp_mtd_write] Error in coping data from user (%lu vs %lu)\n", len, packet->len);
	}
	kfifo_put(&mock_mctp_fifo_out, packet);
	wake_up(&mock_mctp_wait_queue_data_out);

    return len;
}

/* Proc operation structure */
static struct proc_ops mock_mctp_proc_ops = {
    .proc_read = mock_mctp_mtd_read,
	.proc_write = mock_mctp_mtd_write
};

/**
 * @brief Function that is called when open the Device file
 * 
 */
static int mock_mctp_driver_cdev_in_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_in_open] Open device\n");
	return 0;
}

/**
 * @brief Function that is called when release the Device file
 * 
 */
static int mock_mctp_driver_cdev_in_release(struct inode *inode, struct file *file) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_in_release] Release device\n");
	return 0;
}

/**
 * @brief Function that is called when write ioctl on the Device file
 * 
 */
static long mock_mctp_driver_cdev_in_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_in_ioctl] Ioctl device\n");

	switch(cmd) {
		case ASPEED_MCTP_IOCTL_GET_BDF:
			printk(KERN_INFO "\tASPEED_MCTP_IOCTL_GET_BDF\n");
			return 0;
			break;
		case ASPEED_MCTP_IOCTL_GET_MEDIUM_ID:
			printk(KERN_INFO "\tASPEED_MCTP_IOCTL_GET_MEDIUM_ID\n");
			return 0;
			break;
		case ASPEED_MCTP_IOCTL_SET_EID_INFO:
			printk(KERN_INFO "\tASPEED_MCTP_IOCTL_SET_EID_INFO\n");
			return 1;
			break;
		case ASPEED_MCTP_IOCTL_GET_EID_INFO:
			printk(KERN_INFO "\tASPEED_MCTP_IOCTL_GET_EID_INFO\n");
			return 1;
			break;
		case ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER:
			printk(KERN_INFO "\tASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER\n");
			return 0;
			break;
		default:
			printk(KERN_INFO "\tioctl default\n");
			return 1;
			break;
	}
}

/**
 * @brief Function that is called when polling the device
 * 
 */
static unsigned int mock_mctp_driver_cdev_in_poll(struct file *filp, struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &mock_mctp_wait_queue_data_out, wait);

	if (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		mask |= ( POLLIN | POLLRDNORM );
	}
    
	if (!kfifo_is_full(&mock_mctp_fifo_in)) {
		mask |= ( POLLOUT | POLLWRNORM );
	}

	return mask;
}

/**
 * @brief Function that is called when read the device file
 * 
 */
static ssize_t mock_mctp_driver_cdev_in_read(struct file *file, char __user *data, size_t size, loff_t *offset) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_in_read] Read device (size = %lu)\n", size);

	if ((mock_mctp_current_packet_rin != NULL) && (mock_mctp_current_packet_rin->offset > 0)) {
		// we process further an already started packet
		// left intentionally empty to sustain simple logic
	}
	else if (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_out, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR "[mock_mctp_driver_cdev_in_read] Error in getting packet from fifo\n");
			return -EAGAIN;
		}
		else {
			mock_mctp_current_packet_rin = packet_ptr;
		}
	}
	else {
		return -EAGAIN;
	}

	size_t bytes_in_packet = mock_mctp_current_packet_rin->len - mock_mctp_current_packet_rin->offset;
	size_t bytes_to_read = (bytes_in_packet <= size) ? bytes_in_packet : size;

	size_t missed = copy_to_user(data, &(mock_mctp_current_packet_rin->buf[mock_mctp_current_packet_rin->offset]), bytes_to_read);
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_to_user_in += 1;
		printk(KERN_ERR "[mock_mctp_driver_cdev_in_read] Error in coping data to user, missed = %lu\n", missed);
	}

	size_t copied = bytes_to_read - missed;

	if ((mock_mctp_current_packet_rin->offset + copied) <= mock_mctp_current_packet_rin->len) {
		mock_mctp_current_packet_rin->offset += copied;
	}
	else {
		mock_mctp_current_packet_rin->offset = mock_mctp_current_packet_rin->len;
	}

	_mock_mctp_counters.bytes_read_in += copied;

	if (mock_mctp_current_packet_rin->offset >= mock_mctp_current_packet_rin->len) {
		kfree(mock_mctp_current_packet_rin->buf);
		kfree(mock_mctp_current_packet_rin);
		mock_mctp_current_packet_rin = NULL;
		_mock_mctp_counters.packets_read_in += 1;
	}

	return copied;
}

/**
 * @brief Function that is called when write the device file
 * 
 */
static ssize_t mock_mctp_driver_cdev_in_write(struct file *file, const char __user *data, size_t size, loff_t *offset) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_in_write] Write device (size = %lu)\n", size);

	if (kfifo_is_full(&mock_mctp_fifo_in)) {
		return -EBUSY;
	}

	struct data_pkt *packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(size, GFP_KERNEL);
	packet->offset = 0;

	int missed = copy_from_user(packet->buf, data, size);
	packet->len = size - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_in += 1;
		printk(KERN_ERR "[mock_mctp_driver_cdev_in_write] Error in coping data from user (%lu vs %lu)\n", size, packet->len);
	}

	_mock_mctp_counters.packets_written_in += 1;
	_mock_mctp_counters.bytes_written_in += size;

	if (skip_packets_in == 1) {
		printk(KERN_INFO "[mock_mctp_driver_cdev_in_write] Skipping received packet, size = %lu\n", packet->len);
		kfree(packet->buf );
		kfree(packet);
	}
	else {
		kfifo_put(&mock_mctp_fifo_in, packet);
		wake_up(&mock_mctp_wait_queue_data_in);
	}

	return size;
}

/* File operation structure */
static struct file_operations mock_mctp_fops_in = {
	.owner = THIS_MODULE,
	.open = mock_mctp_driver_cdev_in_open,
	.release = mock_mctp_driver_cdev_in_release,
	.unlocked_ioctl = mock_mctp_driver_cdev_in_ioctl,
	.read = mock_mctp_driver_cdev_in_read,
	.write = mock_mctp_driver_cdev_in_write,
	.poll = mock_mctp_driver_cdev_in_poll,
};

/**
 * @brief Function that is called when open the Device file
 * 
 */
static int mock_mctp_driver_cdev_out_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_open] Open device\n");
	return 0;
}

/**
 * @brief Function that is called when release the Device file
 * 
 */
static int mock_mctp_driver_cdev_out_release(struct inode *inode, struct file *file) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_release] Release device\n");
	return 0;
}

/**
 * @brief Function that is called when write ioctl on the Device file
 * 
 */
static long mock_mctp_driver_cdev_out_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_out_ioctl] Ioctl device\n");

	switch(cmd) {
		case ASPEED_MCTP_IOCTL_GET_BDF:
			printk(KERN_INFO "\t  ASPEED_MCTP_IOCTL_GET_BDF\n");
			return 0;
			break;
		case ASPEED_MCTP_IOCTL_GET_MEDIUM_ID:
			printk(KERN_INFO "\t  ASPEED_MCTP_IOCTL_GET_MEDIUM_ID\n");
			return 0;
			break;
		default:
			printk(KERN_INFO "\t  ioctl default\n");
			return 1;
			break;
	}
}

/**
 * @brief Function that is called when polling the device
 * 
 */
static unsigned int mock_mctp_driver_cdev_out_poll(struct file *filp, struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &mock_mctp_wait_queue_data_in, wait);

	if (!kfifo_is_empty(&mock_mctp_fifo_in)) {
		mask |= ( POLLIN | POLLRDNORM );
	}
    
	if (!kfifo_is_full(&mock_mctp_fifo_out)) {
		mask |= ( POLLOUT | POLLWRNORM );
	}
    
	return mask;
}

/**
 * @brief Function that is called when read the Device file
 * 
 */
static ssize_t mock_mctp_driver_cdev_out_read(struct file *file, char __user *data, size_t size, loff_t *offset) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_out_read] Read device (size = %lu)\n", size);

	if ((mock_mctp_current_packet_rout != NULL) && (mock_mctp_current_packet_rout->offset > 0)) {
		// we process further an already started packet
		// left intentionally empty to sustain simple logic
	}
	else if (!kfifo_is_empty(&mock_mctp_fifo_in)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_in, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR "[mock_mctp_driver_cdev_out_read] Error in getting packet from fifo\n");
			return -EAGAIN;
		}
		else {
			mock_mctp_current_packet_rout = packet_ptr;
		}
	}
	else {
		return -EAGAIN;
	}

	size_t bytes_in_packet = mock_mctp_current_packet_rout->len - mock_mctp_current_packet_rout->offset;
	size_t bytes_to_read = (bytes_in_packet <= size) ? bytes_in_packet : size;

	size_t missed = copy_to_user(data, &(mock_mctp_current_packet_rout->buf[mock_mctp_current_packet_rout->offset]), bytes_to_read);
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_to_user_out += 1;
		printk(KERN_ERR "[mock_mctp_driver_cdev_out_read] Error in coping data to user, missed = %lu\n", missed);
	}

	size_t copied = bytes_to_read - missed;

	if ((mock_mctp_current_packet_rout->offset + copied) <= mock_mctp_current_packet_rout->len) {
		mock_mctp_current_packet_rout->offset += copied;
	}
	else {
		mock_mctp_current_packet_rout->offset = mock_mctp_current_packet_rout->len;
	}

	_mock_mctp_counters.bytes_read_out += copied;

	if (mock_mctp_current_packet_rout->offset >= mock_mctp_current_packet_rout->len) {
		kfree(mock_mctp_current_packet_rout->buf);
		kfree(mock_mctp_current_packet_rout);
		mock_mctp_current_packet_rout = NULL;
		_mock_mctp_counters.packets_read_out += 1;
	}

	return copied;
}

/**
 * @brief Function that is called when write the Device file
 * 
 */
static ssize_t mock_mctp_driver_cdev_out_write(struct file *file, const char __user *data, size_t size, loff_t *offset) {
	printk(KERN_INFO "[mock_mctp_driver_cdev_out_write] Write device (size = %lu)\n", size);

	if (kfifo_is_full(&mock_mctp_fifo_out)) {
		return -EBUSY;
	}

	struct data_pkt *packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(size, GFP_KERNEL);
	packet->offset = 0;
	int missed = copy_from_user(packet->buf, data, size);
	packet->len = size - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_out += 1;
		printk(KERN_ERR "[mock_mctp_driver_cdev_out_write] Error in coping data from user (%lu vs %lu)\n", size, packet->len);
	}
	kfifo_put(&mock_mctp_fifo_out, packet);
	_mock_mctp_counters.packets_written_out += 1;
	_mock_mctp_counters.bytes_written_out += size;
	wake_up(&mock_mctp_wait_queue_data_out);
	return size;
}

/* File operation structure */
static struct file_operations mock_mctp_fops_out = {
	.owner = THIS_MODULE,
	.open = mock_mctp_driver_cdev_out_open,
	.release = mock_mctp_driver_cdev_out_release,
	.unlocked_ioctl = mock_mctp_driver_cdev_out_ioctl,
	.read = mock_mctp_driver_cdev_out_read,
	.write = mock_mctp_driver_cdev_out_write,
	.poll = mock_mctp_driver_cdev_out_poll,
};

/**
 * @brief Function used to set drivers permission
 * 
 */
static int mock_mctp_dev_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

/**
 * @brief Function that is called when the module is exiting.
 * 
 */
static void mock_mctp_remove(struct drv* drv)
{
	if (drv == NULL) {
		return;
	}

	// Clean up any pending packets
	while (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_out, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR "[mock_mctp_remove] Error in getting packet from fifo out\n");
			break;
		}

		if (packet_ptr != NULL) {
			struct data_pkt *data_packet_ptr = packet_ptr;
			if (data_packet_ptr->buf != NULL) {
				kfree(data_packet_ptr->buf);
			}

			kfree(data_packet_ptr);
		}
	}

	while (!kfifo_is_empty(&mock_mctp_fifo_in)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_in, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR "[mock_mctp_remove] Error in getting packet from fifo in\n");
			break;
		}

		if (packet_ptr != NULL) {
			struct data_pkt *data_packet_ptr = packet_ptr;
			if (data_packet_ptr->buf != NULL) {
				kfree(data_packet_ptr->buf);
			}

			kfree(data_packet_ptr);
		}
	}

    if (drv->kernel_class_in != 0) {
		printk(KERN_INFO "[mock_mctp_remove] Destroying device in\n");
		device_destroy(drv->kernel_class_in, drv->dev_in);
		class_destroy(drv->kernel_class_in);
	}

	if (drv->kernel_cdev_in != 0) {
		printk(KERN_INFO "[mock_mctp_remove] Removing kernel cdev in\n");
		cdev_del(drv->kernel_cdev_in);
	}

	unregister_chrdev_region(drv->dev_in, 1);

    if (drv->kernel_class_out != 0) {
		printk(KERN_INFO "[mock_mctp_remove] Destroying device out\n");
		device_destroy(drv->kernel_class_out, drv->dev_out);
		class_destroy(drv->kernel_class_out);
	}

	if (drv->kernel_cdev_out != 0) {
		printk(KERN_INFO "[mock_mctp_remove] Removing kernel cdev out\n");
		cdev_del(drv->kernel_cdev_out);
	}

	unregister_chrdev_region(drv->dev_out, 1);

	printk(KERN_INFO "[mock_mctp_remove] Removing proc mctp entry\n");
	remove_proc_entry(mock_mctp_proc_name, NULL);
}

/**
 * @brief Function that is called when the module is loaded into the kernel.
 * 
 */
static int __init mock_mctp_module_init(void) {
	struct drv* drv;
	int result;

	printk(KERN_INFO "[mock_mctp_module_init] Init %s module!\n", mock_mctp_dev_name);

	// Initialize main module structure
	drv = &_mock_mctp_drv;
	drv->dev_in = MKDEV(0,0);
	drv->kernel_class_in = NULL;
	drv->kernel_cdev_in = NULL;
	drv->dev_out = MKDEV(0,0);
	drv->kernel_class_out = NULL;
	drv->kernel_cdev_out = NULL;

	drv->mctp_entry = proc_create(mock_mctp_proc_name, 0666, NULL, &mock_mctp_proc_ops);

    if (drv->mctp_entry != NULL) {
        printk(KERN_INFO "[mock_mctp_module_init] /proc/%s created\n", mock_mctp_proc_name);
    }
    else {
        printk(KERN_ERR "[mock_mctp_module_init] Failed to created /proc/%s!\n", mock_mctp_proc_name);
        result = -1;
		goto on_error;
    }

	// Alloc MAJOR number
	result = alloc_chrdev_region(&(drv->dev_in), 0, 1, mock_mctp_dev_name);
	if (result >= 0) {
		printk(KERN_INFO "[mock_mctp_module_init] Succeed alloc chrdev region as major number %d!\n", result);
	}
	else {
		printk(KERN_ERR "[mock_mctp_module_init] Could not alloc chrdev region!\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Create cdev structure
	drv->kernel_cdev_in = cdev_alloc();
	if (drv->kernel_cdev_in == NULL) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to alloc cdev\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Initialize cdev structure and add char device to the system
	cdev_init(drv->kernel_cdev_in, &mock_mctp_fops_in);
	result = cdev_add(drv->kernel_cdev_in, drv->dev_in, 1);
	if (result < 0) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to add cdev\n");
		goto on_error;
	}

	printk(KERN_INFO "[mock_mctp_module_init] Major = %d Minor = %d \n", MAJOR(drv->dev_in), MINOR(drv->dev_in));

	// Create struct class
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) 
	drv->kernel_class_in = class_create(mock_mctp_dev_name);
#else 
	drv->kernel_class_in = class_create(THIS_MODULE, mock_mctp_dev_name);
#endif 
	if (drv->kernel_class_in == NULL) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to create kernel class\n");
		result = -1;
		goto on_error;
	}

	// Make sure the driver is RW not only for sudo user
	drv->kernel_class_in->dev_uevent = mock_mctp_dev_uevent;

	// Create device
	if (IS_ERR(device_create(drv->kernel_class_in, NULL, drv->dev_in, NULL, "%s", (const char*)mock_mctp_dev_name))) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to create device\n");
		result = -1;
		goto on_error;
	}

	// Alloc MAJOR number
	result = alloc_chrdev_region(&(drv->dev_out), 0, 1, mock_mctp_dev_name_out);
	if (result >= 0) {
		printk(KERN_INFO "[mock_mctp_module_init] Succeed alloc chrdev region as major number %d!\n", result);
	}
	else {
		printk(KERN_ERR "[mock_mctp_module_init] Could not alloc chrdev region!\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Create cdev structure
	drv->kernel_cdev_out = cdev_alloc();
	if (drv->kernel_cdev_out == NULL) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to alloc cdev\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Initialize cdev structure and add char device to the system
	cdev_init(drv->kernel_cdev_out, &mock_mctp_fops_out);
	result = cdev_add(drv->kernel_cdev_out, drv->dev_out, 1);
	if (result < 0) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to add cdev\n");
		goto on_error;
	}

	printk(KERN_INFO "[mock_mctp_module_init] Major = %d Minor = %d \n", MAJOR(drv->dev_out), MINOR(drv->dev_out));

	// Create struct class
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) 
	drv->kernel_class_out = class_create(mock_mctp_dev_name_out);
#else 
	drv->kernel_class_out = class_create(THIS_MODULE, mock_mctp_dev_name_out);
#endif 
	if (drv->kernel_class_out == NULL) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to create kernel class\n");
		result = -1;
		goto on_error;
	}

	// Make sure the driver is RW not only for sudo user
	drv->kernel_class_out->dev_uevent = mock_mctp_dev_uevent;

	// Create device
	if (IS_ERR(device_create(drv->kernel_class_out, NULL, drv->dev_out, NULL, "%s", (const char*)mock_mctp_dev_name_out))) {
		printk(KERN_ERR "[mock_mctp_module_init] Failed to create device\n");
		result = -1;
		goto on_error;
	}

	return 0;

  on_error:
    mock_mctp_remove(drv);
	return result;
}

/**
 * @brief Function that is called when the module is removed from the kernel.
 * 
 */
static void __exit mock_mctp_module_exit(void) {
	printk(KERN_INFO "[mock_mctp_module_exit] Exit %s module!\n", mock_mctp_dev_name);
	mock_mctp_remove(&_mock_mctp_drv);
}

module_init(mock_mctp_module_init);
module_exit(mock_mctp_module_exit);

/* Meta Information */
MODULE_AUTHOR("Marcin Nowakowski");
MODULE_DESCRIPTION("Register mock aspeed-mctp device with cross data transfers.");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
