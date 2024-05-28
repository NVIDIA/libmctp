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
#include <linux/slab.h>	   //kmalloc()
#include <linux/uaccess.h> //copy_to/from_user()
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/kfifo.h>
#include <linux/moduleparam.h>
#include <linux/version.h>

#include <linux/spi/spidev.h>

#define DEVICE_NAME_IN	"spidev0.2"
#define DEVICE_NAME_OUT "spidev0.2-mock"

// Module parameters:
// skip_packets_in - if set to 1 then packets written
//   from tested application will not be transferred to
//   mocked driver (usefull for massive number of packets tests)
int skip_packets_in = 0;
module_param(skip_packets_in, int, 0664);

// Set module strings as variables,
// so they may be configurable in the future
const char *mock_mctp_spi_dev_name = DEVICE_NAME_IN;
const char *mock_mctp_spi_dev_name_out = DEVICE_NAME_OUT;
static unsigned char *mock_mctp_spi_proc_name = "mctp_" DEVICE_NAME_IN;

// Main driver module structure
struct drv {
	// main driver properties
	dev_t dev_in;
	struct class *kernel_class_in;
	struct cdev *kernel_cdev_in;

	// mock driver properties
	dev_t dev_out;
	struct class *kernel_class_out;
	struct cdev *kernel_cdev_out;

	// proc properties
	struct proc_dir_entry *mctp_entry;
};

static struct drv _mock_mctp_spi_drv = { 0 };

// Sending data structures
DECLARE_WAIT_QUEUE_HEAD(mock_mctp_spi_wait_queue_data_in);
DECLARE_WAIT_QUEUE_HEAD(mock_mctp_spi_wait_queue_data_out);

struct data_pkt {
	ssize_t len;	// full length of the packet in bytes
	ssize_t offset; // read write bytes from the packet
	char *buf;	// packet buffer pointer
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

#define MOCK_MCTP_FIFO_SIZE (1024 * 16)
DEFINE_KFIFO(mock_mctp_fifo_in, void *, MOCK_MCTP_FIFO_SIZE);
DEFINE_KFIFO(mock_mctp_fifo_out, void *, MOCK_MCTP_FIFO_SIZE);

#define SPB_GPIO_INTR_NUM 986

typedef enum {
	CMD_SREG_W8 = 0x9,
	CMD_SREG_W16,
	CMD_SREG_W32,

	CMD_SREG_R8 = 0xD,
	CMD_SREG_R16,
	CMD_SREG_R32,

	CMD_MEM_W8 = 0x21,
	CMD_MEM_W16,
	CMD_MEM_W32,

	CMD_MEM_R8 = 0x25,
	CMD_MEM_R16,
	CMD_MEM_R32,

	CMD_RD_SNGL_FIFO8 = 0x28,
	CMD_RD_SNGL_FIFO16 = 0x29,
	CMD_RD_SNGL_FIFO32 = 0x2b,

	CMD_POLL_LOW = 0x2C,
	CMD_POLL_HIGH = 0x2D,
	CMD_POLL_ALL = 0x2F,

	CMD_MEM_BLK_W1 = 0x80,

	CMD_MEM_BLK_R1 = 0xA0,
	CMD_RD_BLK_FIFO1 = 0xC0,

	CMD_RD_SNGL_FIFO8_FSR = 0x68,
	CMD_RD_SNGL_FIFO16_FSR = 0x69,
	CMD_RD_SNGL_FIFO32_FSR = 0x6B,
	CMD_BLK_RD_FIFO_FSR = 0xE0,
} spb_spi_cmds_t;

typedef enum {
	SPI_CFG = 0x00,
	SPI_STS = 0x04,
	SPI_EC_STS = 0x08,
	SPI_IEN = 0x0C,
	// ...
	SPI_SPIM2EC_MBX = 0x44,
	SPI_EC2SPIM_MBX = 0x48,
} spb_spi_regs_t;

typedef enum {
	EC_ACK = 0x01,
	AP_REQUEST_WRITE = 0x02,
	AP_READY_TO_READ = 0x03,
	AP_FINISHED_READ = 0x04,
	AP_REQUEST_RESET = 0x05,
	EC_MSG_AVAILABLE = 0x10,
} spb_spi_mailbox_cmds_t;

// proc main internal variables
static char proc_buffer[2048];
static int proc_len = 1;

/**
 * @brief Function that is called when read the MCTP mock driver proc statistics
 * 
 */
static ssize_t mock_mctp_spi_mtd_read(struct file *file, char __user *data,
				      size_t size, loff_t *offset)
{
	int rv;
	int missed;
	char *buf_ptr;

	if (proc_len) {
		proc_len = 0;
	} else {
		proc_len = 1;
		return 0;
	}

	printk(KERN_INFO "[mock_mctp_spi_mtd_read] Read mtd (size = %lu)\n",
	       size);

	rv = sprintf(proc_buffer, "Mock MCTP SPI driver\n");
	buf_ptr = &(proc_buffer[rv]);

	// FIFOs status
	rv += sprintf(
		buf_ptr,
		"FIFO in: full = %d, empty = %d, len = %d, max = %d, skip = %d\n",
		kfifo_is_full(&mock_mctp_fifo_in),
		kfifo_is_empty(&mock_mctp_fifo_in),
		kfifo_len(&mock_mctp_fifo_in), MOCK_MCTP_FIFO_SIZE,
		skip_packets_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr,
		      "FIFO out: full = %d, empty = %d, len = %d, max = %d\n\n",
		      kfifo_is_full(&mock_mctp_fifo_out),
		      kfifo_is_empty(&mock_mctp_fifo_out),
		      kfifo_len(&mock_mctp_fifo_out), MOCK_MCTP_FIFO_SIZE);
	buf_ptr = &(proc_buffer[rv]);

	// Read packets status
	if (mock_mctp_current_packet_rin == NULL) {
		rv += sprintf(buf_ptr,
			      "mock_mctp_current_packet_rin is null\n");
	} else {
		rv += sprintf(
			buf_ptr,
			"mock_mctp_current_packet_rin len = %lu, offset = %lu\n",
			mock_mctp_current_packet_rin->len,
			mock_mctp_current_packet_rin->offset);
	}
	buf_ptr = &(proc_buffer[rv]);

	if (mock_mctp_current_packet_rout == NULL) {
		rv += sprintf(buf_ptr,
			      "mock_mctp_current_packet_rout is null\n");
	} else {
		rv += sprintf(
			buf_ptr,
			"mock_mctp_current_packet_rout len = %lu, offset = %lu\n",
			mock_mctp_current_packet_rout->len,
			mock_mctp_current_packet_rout->offset);
	}
	buf_ptr = &(proc_buffer[rv]);

	// Print all counters
	rv += sprintf(buf_ptr, "\npackets_written_in\t\t: %d\n",
		      _mock_mctp_counters.packets_written_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packets_read_in\t\t\t: %d\n",
		      _mock_mctp_counters.packets_read_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_written_in\t\t: %lu\n",
		      _mock_mctp_counters.bytes_written_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_read_in\t\t\t: %lu\n",
		      _mock_mctp_counters.bytes_read_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packet_fifo_in\t\t\t: %d\n",
		      _mock_mctp_counters.packet_fifo_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "\npackets_written_out\t\t: %d\n",
		      _mock_mctp_counters.packets_written_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packets_read_out\t\t: %d\n",
		      _mock_mctp_counters.packets_read_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_written_out\t\t: %lu\n",
		      _mock_mctp_counters.bytes_written_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "bytes_read_out\t\t\t: %lu\n",
		      _mock_mctp_counters.bytes_read_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "packet_fifo_out\t\t\t: %d\n",
		      _mock_mctp_counters.packet_fifo_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "\nerrors_copy_to_user_in\t\t: %d\n",
		      _mock_mctp_counters.errors_copy_to_user_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_from_user_in\t: %d\n",
		      _mock_mctp_counters.errors_copy_from_user_in);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_to_user_out\t\t: %d\n",
		      _mock_mctp_counters.errors_copy_to_user_out);
	buf_ptr = &(proc_buffer[rv]);
	rv += sprintf(buf_ptr, "errors_copy_from_user_out\t: %d\n",
		      _mock_mctp_counters.errors_copy_from_user_out);

	printk(KERN_INFO "[mock_mctp_spi_mtd_read] rv = %d\n", rv);

	missed = copy_to_user(data, proc_buffer, rv);
	if (missed != 0) {
		printk(KERN_INFO
		       "[mock_mctp_spi_mtd_read] Copy to user missed %d bytes\n",
		       missed);
	}

	return rv;
}

/**
 * @brief Function that is called when write the MCTP mock driver proc
 * 			Use this to send a simple data block to demux demon
 * 
 */
static ssize_t mock_mctp_spi_mtd_write(struct file *filp, const char *buff,
				       size_t len, loff_t *off)
{
	int missed;
	struct data_pkt *packet;

	printk(KERN_INFO
	       "[mock_mctp_spi_mtd_write] proc file write (len = %lu)\t",
	       len);

	if (kfifo_is_full(&mock_mctp_fifo_out)) {
		return -EBUSY;
	}

	packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(len, GFP_KERNEL);
	packet->offset = 0;
	missed = copy_from_user(packet->buf, buff, len);
	packet->len = len - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_out += 1;
		printk(KERN_ERR
		       "[mock_mctp_spi_mtd_write] Error in coping data from user (%lu vs %lu)\n",
		       len, packet->len);
	}
	kfifo_put(&mock_mctp_fifo_out, packet);
	wake_up(&mock_mctp_spi_wait_queue_data_out);

	return len;
}

/* Proc operation structure */
static struct proc_ops mock_mctp_spi_proc_ops = {
	.proc_read = mock_mctp_spi_mtd_read,
	.proc_write = mock_mctp_spi_mtd_write
};

/**
 * @brief Function that is called when open the Device file
 * 
 */
static int mock_mctp_spi_driver_cdev_in_open(struct inode *inode,
					     struct file *file)
{
	printk(KERN_INFO "[mock_mctp_spi_driver_cdev_in_open] Open device\n");
	return 0;
}

/**
 * @brief Function that is called when release the Device file
 * 
 */
static int mock_mctp_spi_driver_cdev_in_release(struct inode *inode,
						struct file *file)
{
	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_in_release] Release device\n");
	return 0;
}

static struct spi_ioc_transfer *
spidev_get_ioc_message(unsigned int cmd, struct spi_ioc_transfer __user *u_ioc,
		       unsigned *n_ioc)
{
	u32 tmp;

	/* Check type, command number and direction */
	if (_IOC_TYPE(cmd) != SPI_IOC_MAGIC ||
	    _IOC_NR(cmd) != _IOC_NR(SPI_IOC_MESSAGE(0)) ||
	    _IOC_DIR(cmd) != _IOC_WRITE)
		return ERR_PTR(-ENOTTY);

	tmp = _IOC_SIZE(cmd);
	if ((tmp % sizeof(struct spi_ioc_transfer)) != 0)
		return ERR_PTR(-EINVAL);
	*n_ioc = tmp / sizeof(struct spi_ioc_transfer);
	if (*n_ioc == 0)
		return NULL;

	/* copy into scratch area */
	return memdup_user(u_ioc, tmp);
}

void gpiod_mock_gen_irq(long gpio);

long mock_mctp_spidev_message(struct spi_ioc_transfer *ioc, unsigned n_ioc)
{
	unsigned char tx_buf[256] = { 0 };
	int missed;

	if (n_ioc == 1) {
		if ((ioc->len >= 3) && (ioc->len < 256)) {
			missed = copy_from_user(
				tx_buf,
				(const u8 __user *)(uintptr_t)ioc->tx_buf,
				ioc->len);
			if ((tx_buf[0] == CMD_SREG_W32) && (tx_buf[1] == 0) &&
			    (tx_buf[2] == SPI_SPIM2EC_MBX)) {
				if (tx_buf[3] == AP_REQUEST_RESET) {
					printk(KERN_DEBUG
					       "[mock_mctp_spidev_message] Get [SPIM2ECMB] AP_REQUEST_RESET\n");
					gpiod_mock_gen_irq(SPB_GPIO_INTR_NUM);
				} else if ((tx_buf[0] == CMD_SREG_W32) &&
					   (tx_buf[1] == 0) &&
					   (tx_buf[2] == SPI_SPIM2EC_MBX) &&
					   (tx_buf[3] == AP_REQUEST_WRITE)) {
					printk(KERN_DEBUG
					       "[mock_mctp_spidev_message] Get [SPIM2ECMB] AP_REQUEST_WRITE\n");
					gpiod_mock_gen_irq(SPB_GPIO_INTR_NUM);
				} else if ((tx_buf[0] == CMD_SREG_W32) &&
					   (tx_buf[1] == 0) &&
					   (tx_buf[2] == SPI_SPIM2EC_MBX) &&
					   (tx_buf[3] == AP_READY_TO_READ)) {
					printk(KERN_DEBUG
					       "[mock_mctp_spidev_message] Get [SPIM2ECMB] AP_READY_TO_READ\n");
					gpiod_mock_gen_irq(SPB_GPIO_INTR_NUM);
				} else if ((tx_buf[0] == CMD_SREG_W32) &&
					   (tx_buf[1] == 0) &&
					   (tx_buf[2] == SPI_SPIM2EC_MBX) &&
					   (tx_buf[3] == AP_FINISHED_READ)) {
					printk(KERN_DEBUG
					       "[mock_mctp_spidev_message] Get [SPIM2ECMB] AP_FINISHED_READ\n");
					gpiod_mock_gen_irq(SPB_GPIO_INTR_NUM);
				} else {
					printk(KERN_DEBUG
					       "[mock_mctp_spidev_message] Get length = %d\n",
					       tx_buf[6]);
					gpiod_mock_gen_irq(SPB_GPIO_INTR_NUM);
				}
			} else if ((tx_buf[0] == CMD_SREG_R32) &&
				   (tx_buf[1] == 0) &&
				   (tx_buf[2] == SPI_EC2SPIM_MBX)) {
				// Ack request
				printk(KERN_DEBUG
				       "[mock_mctp_spidev_message] Get ACK request command\n");
				tx_buf[3] = EC_ACK;
				missed = copy_to_user(
					(void *)(uintptr_t)ioc->rx_buf, tx_buf,
					4);
			} else if ((tx_buf[0] == CMD_POLL_ALL) &&
				   (tx_buf[1] == 0)) {
				printk(KERN_DEBUG
				       "[mock_mctp_spidev_message] Get CMD_POLL_ALL command\n");
				tx_buf[0] = 0x2f;
				tx_buf[1] = 0;
				tx_buf[2] = 0;
				tx_buf[3] = 0x01;
				tx_buf[4] = 0x08;
				missed = copy_to_user(
					(void *)(uintptr_t)ioc->rx_buf, tx_buf,
					5);
			} else {
				printk(KERN_DEBUG
				       "[mock_mctp_spidev_message] Get request: len=%d: %02x %02x %02x %02x, missed = %d\n",
				       ioc->len, tx_buf[0], tx_buf[1],
				       tx_buf[2], tx_buf[3], missed);
			}
		} else {
			printk(KERN_WARNING
			       "[mock_mctp_spidev_message] Expected at least 3 bytes message, but is only %d\n",
			       ioc->len);
		}

		return ioc->len;
	} else {
		// add support for more transfers in one transaction
		printk(KERN_WARNING
		       "[mock_mctp_spidev_message] Received %u messages - unsupported for now\n",
		       n_ioc);
	}

	return 0;
}

/**
 * @brief Function that is called when write ioctl on the Device file
 * 
 */
static long mock_mctp_spi_driver_cdev_in_ioctl(struct file *file,
					       unsigned int cmd,
					       unsigned long arg)
{
	unsigned n_ioc;
	long retval;
	struct spi_ioc_transfer *ioc;

	switch (cmd) {
	case SPI_IOC_MESSAGE(1):
		/* segmented and/or full-duplex I/O request */
		/* Check message and copy into scratch area */
		ioc = spidev_get_ioc_message(
			cmd, (struct spi_ioc_transfer __user *)arg, &n_ioc);
		if (IS_ERR(ioc)) {
			retval = PTR_ERR(ioc);
			break;
		}
		if (!ioc)
			break; /* n_ioc is also 0 */

		/* translate to spi_message, execute */
		retval = mock_mctp_spidev_message(ioc, n_ioc);
		kfree(ioc);
		return retval;
		break;
	case SPI_IOC_WR_MAX_SPEED_HZ:
		printk(KERN_INFO "\tSPI_IOC_WR_MAX_SPEED_HZ\n");
		return 0;
		break;
	case SPI_IOC_RD_MAX_SPEED_HZ:
		printk(KERN_INFO "\tSPI_IOC_RD_MAX_SPEED_HZ\n");
		return 0;
		break;
	case SPI_IOC_WR_MODE:
		printk(KERN_INFO "\tSPI_IOC_WR_MODE\n");

		if (arg == 0) { //Set bpw
			return 1;
		}
		if (arg == 1) { //Set mode
			return 2;
		}
		break;
	case SPI_IOC_RD_MODE:
		printk(KERN_INFO "\tSPI_IOC_RD_MODE\n");
		return 1;
		break;
	default:
		printk(KERN_INFO
		       "[mock_mctp_spi_driver_cdev_in_ioctl] Ioctl device - cmd = 0x%08x, 0xarg = %08lx\n",
		       cmd, arg);
		return 1;
		break;
	}

	return 1;
}

/**
 * @brief Function that is called when polling the device
 * 
 */
static unsigned int
mock_mctp_spi_driver_cdev_in_poll(struct file *filp,
				  struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &mock_mctp_spi_wait_queue_data_out, wait);

	if (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		mask |= (POLLIN | POLLRDNORM);
	}

	if (!kfifo_is_full(&mock_mctp_fifo_in)) {
		mask |= (POLLOUT | POLLWRNORM);
	}

	return mask;
}

/**
 * @brief Function that is called when read the device file
 * 
 */
static ssize_t mock_mctp_spi_driver_cdev_in_read(struct file *file,
						 char __user *data, size_t size,
						 loff_t *offset)
{
	size_t copied;
	size_t missed;
	size_t bytes_to_read;
	size_t bytes_in_packet;

	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_in_read] Read device (size = %lu)\n",
	       size);

	if ((mock_mctp_current_packet_rin != NULL) &&
	    (mock_mctp_current_packet_rin->offset > 0)) {
		// we process further an already started packet
		// left intentionally empty to sustain simple logic
	} else if (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_out, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR
			       "[mock_mctp_spi_driver_cdev_in_read] Error in getting packet from fifo\n");
			return -EAGAIN;
		} else {
			mock_mctp_current_packet_rin = packet_ptr;
		}
	} else {
		return -EAGAIN;
	}

	bytes_in_packet = mock_mctp_current_packet_rin->len -
			  mock_mctp_current_packet_rin->offset;
	bytes_to_read = (bytes_in_packet <= size) ? bytes_in_packet : size;

	missed = copy_to_user(
		data,
		&(mock_mctp_current_packet_rin
			  ->buf[mock_mctp_current_packet_rin->offset]),
		bytes_to_read);
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_to_user_in += 1;
		printk(KERN_ERR
		       "[mock_mctp_spi_driver_cdev_in_read] Error in coping data to user, missed = %lu\n",
		       missed);
	}

	copied = bytes_to_read - missed;

	if ((mock_mctp_current_packet_rin->offset + copied) <=
	    mock_mctp_current_packet_rin->len) {
		mock_mctp_current_packet_rin->offset += copied;
	} else {
		mock_mctp_current_packet_rin->offset =
			mock_mctp_current_packet_rin->len;
	}

	_mock_mctp_counters.bytes_read_in += copied;

	if (mock_mctp_current_packet_rin->offset >=
	    mock_mctp_current_packet_rin->len) {
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
static ssize_t mock_mctp_spi_driver_cdev_in_write(struct file *file,
						  const char __user *data,
						  size_t size, loff_t *offset)
{
	int missed;
	struct data_pkt *packet;

	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_in_write] Write device (size = %lu)\n",
	       size);

	if (kfifo_is_full(&mock_mctp_fifo_in)) {
		return -EBUSY;
	}

	packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(size, GFP_KERNEL);
	packet->offset = 0;

	missed = copy_from_user(packet->buf, data, size);
	packet->len = size - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_in += 1;
		printk(KERN_ERR
		       "[mock_mctp_spi_driver_cdev_in_write] Error in coping data from user (%lu vs %lu)\n",
		       size, packet->len);
	}

	_mock_mctp_counters.packets_written_in += 1;
	_mock_mctp_counters.bytes_written_in += size;

	if (skip_packets_in == 1) {
		printk(KERN_INFO
		       "[mock_mctp_spi_driver_cdev_in_write] Skipping received packet, size = %lu\n",
		       packet->len);
		kfree(packet->buf);
		kfree(packet);
	} else {
		kfifo_put(&mock_mctp_fifo_in, packet);
		wake_up(&mock_mctp_spi_wait_queue_data_in);
	}

	return size;
}

/* File operation structure */
static struct file_operations mock_mctp_fops_in = {
	.owner = THIS_MODULE,
	.open = mock_mctp_spi_driver_cdev_in_open,
	.release = mock_mctp_spi_driver_cdev_in_release,
	.unlocked_ioctl = mock_mctp_spi_driver_cdev_in_ioctl,
	.read = mock_mctp_spi_driver_cdev_in_read,
	.write = mock_mctp_spi_driver_cdev_in_write,
	.poll = mock_mctp_spi_driver_cdev_in_poll,
};

/**
 * @brief Function that is called when open the Device file
 * 
 */
static int mock_mctp_spi_driver_cdev_out_open(struct inode *inode,
					      struct file *file)
{
	printk(KERN_INFO "[mock_mctp_spi_driver_cdev_open] Open device\n");
	return 0;
}

/**
 * @brief Function that is called when release the Device file
 * 
 */
static int mock_mctp_spi_driver_cdev_out_release(struct inode *inode,
						 struct file *file)
{
	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_release] Release device\n");
	return 0;
}

/**
 * @brief Function that is called when write ioctl on the Device file
 * 
 */
static long mock_mctp_spi_driver_cdev_out_ioctl(struct file *file,
						unsigned int cmd,
						unsigned long arg)
{
	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_in_ioctl] Ioctl device - cmd = %u, arg = %lu\n",
	       cmd, arg);

	switch (cmd) {
	case SPI_IOC_MESSAGE(1):
		printk(KERN_INFO "\tSPI_IOC_MESSAGE(1)\n");
		return 0;
		break;
	case SPI_IOC_WR_MAX_SPEED_HZ:
		printk(KERN_INFO "\tSPI_IOC_WR_MAX_SPEED_HZ\n");
		return 0;
		break;
	case SPI_IOC_RD_MAX_SPEED_HZ:
		printk(KERN_INFO "\tSPI_IOC_RD_MAX_SPEED_HZ\n");
		return 0;
		break;
	case SPI_IOC_WR_MODE:
		printk(KERN_INFO "\tSPI_IOC_WR_MODE\n");

		if (arg == 0) { //Set bpw
			return 1;
		}
		if (arg == 1) { //Set mode
			return 2;
		}
		break;
	case SPI_IOC_RD_MODE:
		printk(KERN_INFO "\tSPI_IOC_RD_MODE\n");
		return 1;
		break;
	default:
		printk(KERN_INFO "\tioctl default\n");
		return 1;
		break;
	}

	return 1;
}

/**
 * @brief Function that is called when polling the device
 * 
 */
static unsigned int
mock_mctp_spi_driver_cdev_out_poll(struct file *filp,
				   struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &mock_mctp_spi_wait_queue_data_in, wait);

	if (!kfifo_is_empty(&mock_mctp_fifo_in)) {
		mask |= (POLLIN | POLLRDNORM);
	}

	if (!kfifo_is_full(&mock_mctp_fifo_out)) {
		mask |= (POLLOUT | POLLWRNORM);
	}

	return mask;
}

/**
 * @brief Function that is called when read the Device file
 * 
 */
static ssize_t mock_mctp_spi_driver_cdev_out_read(struct file *file,
						  char __user *data,
						  size_t size, loff_t *offset)
{
	size_t copied;
	size_t missed;
	size_t bytes_to_read;
	size_t bytes_in_packet;

	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_out_read] Read device (size = %lu)\n",
	       size);

	if ((mock_mctp_current_packet_rout != NULL) &&
	    (mock_mctp_current_packet_rout->offset > 0)) {
		// we process further an already started packet
		// left intentionally empty to sustain simple logic
	} else if (!kfifo_is_empty(&mock_mctp_fifo_in)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_in, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR
			       "[mock_mctp_spi_driver_cdev_out_read] Error in getting packet from fifo\n");
			return -EAGAIN;
		} else {
			mock_mctp_current_packet_rout = packet_ptr;
		}
	} else {
		return -EAGAIN;
	}

	bytes_in_packet = mock_mctp_current_packet_rout->len -
			  mock_mctp_current_packet_rout->offset;
	bytes_to_read = (bytes_in_packet <= size) ? bytes_in_packet : size;

	missed = copy_to_user(
		data,
		&(mock_mctp_current_packet_rout
			  ->buf[mock_mctp_current_packet_rout->offset]),
		bytes_to_read);
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_to_user_out += 1;
		printk(KERN_ERR
		       "[mock_mctp_spi_driver_cdev_out_read] Error in coping data to user, missed = %lu\n",
		       missed);
	}

	copied = bytes_to_read - missed;

	if ((mock_mctp_current_packet_rout->offset + copied) <=
	    mock_mctp_current_packet_rout->len) {
		mock_mctp_current_packet_rout->offset += copied;
	} else {
		mock_mctp_current_packet_rout->offset =
			mock_mctp_current_packet_rout->len;
	}

	_mock_mctp_counters.bytes_read_out += copied;

	if (mock_mctp_current_packet_rout->offset >=
	    mock_mctp_current_packet_rout->len) {
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
static ssize_t mock_mctp_spi_driver_cdev_out_write(struct file *file,
						   const char __user *data,
						   size_t size, loff_t *offset)
{
	int missed;
	struct data_pkt *packet;

	printk(KERN_INFO
	       "[mock_mctp_spi_driver_cdev_out_write] Write device (size = %lu)\n",
	       size);

	if (kfifo_is_full(&mock_mctp_fifo_out)) {
		return -EBUSY;
	}

	packet = kmalloc(sizeof(struct data_pkt), GFP_KERNEL);
	packet->buf = kmalloc(size, GFP_KERNEL);
	packet->offset = 0;
	missed = copy_from_user(packet->buf, data, size);
	packet->len = size - missed;
	if (missed != 0) {
		_mock_mctp_counters.errors_copy_from_user_out += 1;
		printk(KERN_ERR
		       "[mock_mctp_spi_driver_cdev_out_write] Error in coping data from user (%lu vs %lu)\n",
		       size, packet->len);
	}
	kfifo_put(&mock_mctp_fifo_out, packet);
	_mock_mctp_counters.packets_written_out += 1;
	_mock_mctp_counters.bytes_written_out += size;
	wake_up(&mock_mctp_spi_wait_queue_data_out);
	return size;
}

/* File operation structure */
static struct file_operations mock_mctp_fops_out = {
	.owner = THIS_MODULE,
	.open = mock_mctp_spi_driver_cdev_out_open,
	.release = mock_mctp_spi_driver_cdev_out_release,
	.unlocked_ioctl = mock_mctp_spi_driver_cdev_out_ioctl,
	.read = mock_mctp_spi_driver_cdev_out_read,
	.write = mock_mctp_spi_driver_cdev_out_write,
	.poll = mock_mctp_spi_driver_cdev_out_poll,
};

/**
 * @brief Function used to set drivers permission
 * 
 */
static int mock_mctp_spi_dev_uevent(const struct device *dev,
				    struct kobj_uevent_env *env)
{
	add_uevent_var(env, "DEVMODE=%#o", 0666);
	return 0;
}

/**
 * @brief Function that is called when the module is exiting.
 * 
 */
static void mock_mctp_remove(struct drv *drv)
{
	if (drv == NULL) {
		return;
	}

	// Clean up any pending packets
	while (!kfifo_is_empty(&mock_mctp_fifo_out)) {
		void *packet_ptr;
		int ret = kfifo_get(&mock_mctp_fifo_out, &packet_ptr);
		if (ret != 1) {
			printk(KERN_ERR
			       "[mock_mctp_remove] Error in getting packet from fifo out\n");
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
			printk(KERN_ERR
			       "[mock_mctp_remove] Error in getting packet from fifo in\n");
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
		printk(KERN_INFO
		       "[mock_mctp_remove] Removing kernel cdev in\n");
		cdev_del(drv->kernel_cdev_in);
	}

	unregister_chrdev_region(drv->dev_in, 1);

	if (drv->kernel_class_out != 0) {
		printk(KERN_INFO "[mock_mctp_remove] Destroying device out\n");
		device_destroy(drv->kernel_class_out, drv->dev_out);
		class_destroy(drv->kernel_class_out);
	}

	if (drv->kernel_cdev_out != 0) {
		printk(KERN_INFO
		       "[mock_mctp_remove] Removing kernel cdev out\n");
		cdev_del(drv->kernel_cdev_out);
	}

	unregister_chrdev_region(drv->dev_out, 1);

	printk(KERN_INFO "[mock_mctp_remove] Removing proc mctp entry\n");
	remove_proc_entry(mock_mctp_spi_proc_name, NULL);
}

/**
 * @brief Function that is called when the module is loaded into the kernel.
 * 
 */
static int __init mock_mctp_spi_module_init(void)
{
	struct drv *drv;
	int result;

	printk(KERN_INFO "[mock_mctp_spi_module_init] Init %s module!\n",
	       mock_mctp_spi_dev_name);

	// Initialize main module structure
	drv = &_mock_mctp_spi_drv;
	drv->dev_in = MKDEV(0, 0);
	drv->kernel_class_in = NULL;
	drv->kernel_cdev_in = NULL;
	drv->dev_out = MKDEV(0, 0);
	drv->kernel_class_out = NULL;
	drv->kernel_cdev_out = NULL;

	drv->mctp_entry = proc_create(mock_mctp_spi_proc_name, 0666, NULL,
				      &mock_mctp_spi_proc_ops);

	if (drv->mctp_entry != NULL) {
		printk(KERN_INFO
		       "[mock_mctp_spi_module_init] /proc/%s created\n",
		       mock_mctp_spi_proc_name);
	} else {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to created /proc/%s!\n",
		       mock_mctp_spi_proc_name);
		result = -1;
		goto on_error;
	}

	// Alloc MAJOR number
	result = alloc_chrdev_region(&(drv->dev_in), 0, 1,
				     mock_mctp_spi_dev_name);
	if (result >= 0) {
		printk(KERN_INFO
		       "[mock_mctp_spi_module_init] Succeed alloc chrdev region as major number %d!\n",
		       result);
	} else {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Could not alloc chrdev region!\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Create cdev structure
	drv->kernel_cdev_in = cdev_alloc();
	if (drv->kernel_cdev_in == NULL) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to alloc cdev\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Initialize cdev structure and add char device to the system
	cdev_init(drv->kernel_cdev_in, &mock_mctp_fops_in);
	result = cdev_add(drv->kernel_cdev_in, drv->dev_in, 1);
	if (result < 0) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to add cdev\n");
		goto on_error;
	}

	printk(KERN_INFO "[mock_mctp_spi_module_init] Major = %d Minor = %d \n",
	       MAJOR(drv->dev_in), MINOR(drv->dev_in));

	// Create struct class
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	drv->kernel_class_in = class_create(mock_mctp_spi_dev_name);
#else
	drv->kernel_class_in =
		class_create(THIS_MODULE, mock_mctp_spi_dev_name);
#endif
	if (drv->kernel_class_in == NULL) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to create kernel class\n");
		result = -1;
		goto on_error;
	}

	// Make sure the driver is RW not only for sudo user
	drv->kernel_class_in->dev_uevent = mock_mctp_spi_dev_uevent;

	// Create device
	if (IS_ERR(device_create(drv->kernel_class_in, NULL, drv->dev_in, NULL,
				 "%s", (const char *)mock_mctp_spi_dev_name))) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to create device\n");
		result = -1;
		goto on_error;
	}

	// Alloc MAJOR number
	result = alloc_chrdev_region(&(drv->dev_out), 0, 1,
				     mock_mctp_spi_dev_name_out);
	if (result >= 0) {
		printk(KERN_INFO
		       "[mock_mctp_spi_module_init] Succeed alloc chrdev region as major number %d!\n",
		       result);
	} else {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Could not alloc chrdev region!\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Create cdev structure
	drv->kernel_cdev_out = cdev_alloc();
	if (drv->kernel_cdev_out == NULL) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to alloc cdev\n");
		result = -ENOMEM;
		goto on_error;
	}

	// Initialize cdev structure and add char device to the system
	cdev_init(drv->kernel_cdev_out, &mock_mctp_fops_out);
	result = cdev_add(drv->kernel_cdev_out, drv->dev_out, 1);
	if (result < 0) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to add cdev\n");
		goto on_error;
	}

	printk(KERN_INFO "[mock_mctp_spi_module_init] Major = %d Minor = %d \n",
	       MAJOR(drv->dev_out), MINOR(drv->dev_out));

	// Create struct class
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	drv->kernel_class_out = class_create(mock_mctp_spi_dev_name_out);
#else
	drv->kernel_class_out =
		class_create(THIS_MODULE, mock_mctp_spi_dev_name_out);
#endif
	if (drv->kernel_class_out == NULL) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to create kernel class\n");
		result = -1;
		goto on_error;
	}

	// Make sure the driver is RW not only for sudo user
	drv->kernel_class_out->dev_uevent = mock_mctp_spi_dev_uevent;

	// Create device
	if (IS_ERR(device_create(drv->kernel_class_out, NULL, drv->dev_out,
				 NULL, "%s",
				 (const char *)mock_mctp_spi_dev_name_out))) {
		printk(KERN_ERR
		       "[mock_mctp_spi_module_init] Failed to create device\n");
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
static void __exit mock_mctp_spi_module_exit(void)
{
	printk(KERN_INFO "[mock_mctp_spi_module_exit] Exit %s module!\n",
	       mock_mctp_spi_dev_name);
	mock_mctp_remove(&_mock_mctp_spi_drv);
}

module_init(mock_mctp_spi_module_init);
module_exit(mock_mctp_spi_module_exit);

/* Meta Information */
MODULE_AUTHOR("Marcin Nowakowski");
MODULE_DESCRIPTION("Register mock spidev0.2 device with cross data transfers.");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
