// SPDX-License-Identifier: GPL-2.0
// This is a mocked version of GPIO SYSFS driver
//   It is prepared only for test purposes.
//   This driver does not control any real GPIO.
//   Values of any pins may be controlled by other drivers
//     using dedicated auxiliary functions.

#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/driver.h>
#include <linux/interrupt.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/version.h>

/* ------------------------------------------------
 * START: GPIO lib specific mocked function */

struct gpio_mock_desc {
	unsigned long		flags;
	/* flag symbols are bit numbers */
	#define FLAG_REQUESTED	0
	#define FLAG_IS_OUT	1
	#define FLAG_EXPORT	2	/* protected by sysfs_lock */
	#define FLAG_SYSFS	3	/* exported via /sys/class/gpio/control */
	#define FLAG_ACTIVE_LOW	6	/* value has active low */
	#define FLAG_OPEN_DRAIN	7	/* Gpio is open drain type */
	#define FLAG_OPEN_SOURCE 8	/* Gpio is open source type */
	#define FLAG_USED_AS_IRQ 9	/* GPIO is connected to an IRQ */
	#define FLAG_IRQ_IS_ENABLED 10	/* GPIO is connected to an enabled IRQ */
	#define FLAG_IS_HOGGED	11	/* GPIO is hogged */
	#define FLAG_TRANSITORY 12	/* GPIO may lose value in sleep or reset */
	#define FLAG_PULL_UP    13	/* GPIO has pull up enabled */
	#define FLAG_PULL_DOWN  14	/* GPIO has pull down enabled */
	#define FLAG_BIAS_DISABLE    15	/* GPIO has pull disabled */
	#define FLAG_EDGE_RISING     16	/* GPIO CDEV detects rising edge events */
	#define FLAG_EDGE_FALLING    17	/* GPIO CDEV detects falling edge events */

	/* Connection label */
	const char		*label;
	/* Name of the GPIO */
	const char		*name;
	/* Value of the mocked GPIO */
	int				value;
	/* Direction of the mocked GPIO */
	int				dir;
	/* number of this GPIO (the same as in the name) */
	long 			gpio;
};

/* Mocked GPIOs - run time created in this module */
struct gpio_mock_gpios {
	struct gpio_mock_desc	*descs;
	u16						ngpio;
} _mocked_gpios = { 0 };

int mock_desc_to_gpio(const struct gpio_mock_desc *desc)
{
	return desc->gpio;
}

static inline void mock_desc_set_label(struct gpio_mock_desc *d, const char *label)
{
	d->label = label;
}

int gpiod_mock_export(struct gpio_mock_desc *desc, bool direction_may_change);
void gpiod_mock_unexport(struct gpio_mock_desc *desc);

static int gpiod_mock_request_commit(struct gpio_mock_desc *desc, const char *label)
{
	int	ret;

	if (label) {
		label = kstrdup_const(label, GFP_KERNEL);
		if (!label)
			return -ENOMEM;
	}

	if (test_and_set_bit(FLAG_REQUESTED, &desc->flags) == 0) {
		mock_desc_set_label(desc, label ? : "?");
		ret = 0;
	} else {
		kfree_const(label);
		ret = -EBUSY;
		goto done;
	}

done:
	return ret;
}

static int validate_desc(const struct gpio_mock_desc *desc, const char *func)
{
	if (!desc)
		return 0;
	if (IS_ERR(desc)) {
		pr_warn("%s: invalid GPIO (errorpointer)\n", func);
		return PTR_ERR(desc);
	}

	return 1;
}

#define VALIDATE_DESC(desc) do { \
	int __valid = validate_desc(desc, __func__); \
	if (__valid <= 0) \
		return __valid; \
	} while (0)

#define VALIDATE_DESC_VOID(desc) do { \
	int __valid = validate_desc(desc, __func__); \
	if (__valid <= 0) \
		return; \
	} while (0)

int gpiod_mock_request(struct gpio_mock_desc *desc, const char *label)
{
	int ret = -EPROBE_DEFER;

	ret = gpiod_mock_request_commit(desc, label);

	if (ret)
		pr_debug("%s: status %d\n", __func__, ret);

	return ret;
}

static bool gpiod_mock_free_commit(struct gpio_mock_desc *desc)
{
	bool			ret = false;

	gpiod_mock_unexport(desc);

	if (test_bit(FLAG_REQUESTED, &desc->flags)) {
		kfree_const(desc->label);
		mock_desc_set_label(desc, NULL);
		clear_bit(FLAG_ACTIVE_LOW, &desc->flags);
		clear_bit(FLAG_REQUESTED, &desc->flags);
		clear_bit(FLAG_OPEN_DRAIN, &desc->flags);
		clear_bit(FLAG_OPEN_SOURCE, &desc->flags);
		clear_bit(FLAG_PULL_UP, &desc->flags);
		clear_bit(FLAG_PULL_DOWN, &desc->flags);
		clear_bit(FLAG_BIAS_DISABLE, &desc->flags);
		clear_bit(FLAG_EDGE_RISING, &desc->flags);
		clear_bit(FLAG_EDGE_FALLING, &desc->flags);
		clear_bit(FLAG_IS_HOGGED, &desc->flags);
		ret = true;
	}

	return ret;
}

void gpiod_mock_free(struct gpio_mock_desc *desc)
{
	if (desc) {
		gpiod_mock_free_commit(desc);
	}
}

int gpiod_mock_direction_output_raw(struct gpio_mock_desc *desc, int value)
{
	VALIDATE_DESC(desc);

	set_bit(FLAG_IS_OUT, &desc->flags);

	desc->dir = 1;
	desc->value = value;

	return 0;
}

int gpiod_mock_direction_input(struct gpio_mock_desc *desc)
{
	VALIDATE_DESC(desc);

	clear_bit(FLAG_IS_OUT, &desc->flags);

	desc->dir = 0;

	return 0;
}

int gpiod_mock_get_value(const struct gpio_mock_desc *desc)
{
	int value;

	VALIDATE_DESC(desc);

	value = desc->value;

	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;

	return value;
}

void gpiod_mock_set_value(struct gpio_mock_desc *desc, int value)
{
	VALIDATE_DESC_VOID(desc);
	
	desc->value = value;
}

int gpiod_mock_get_direction(struct gpio_mock_desc *desc)
{
	if (test_bit(FLAG_OPEN_DRAIN, &desc->flags) &&
	    test_bit(FLAG_IS_OUT, &desc->flags))
		return 0;

	return desc->dir;
}

struct gpio_mock_desc *gpiod_mock_to_desc(long gpio)
{
	int i;
	struct gpio_mock_desc *desc;

	desc = NULL;

	for (i=0; i<_mocked_gpios.ngpio; i++) {
		if (_mocked_gpios.descs[i].gpio == gpio) {
			desc = &(_mocked_gpios.descs[i]);
		}
	}

	return desc;
}

/* END: GPIO lib specific mocked function 
 * ------------------------------------------------*/

#define GPIO_MOCKED_NUMBER_MAX		3

#define GPIO_IRQF_TRIGGER_FALLING	BIT(0)
#define GPIO_IRQF_TRIGGER_RISING	BIT(1)
#define GPIO_IRQF_TRIGGER_BOTH		(GPIO_IRQF_TRIGGER_FALLING | \
					 GPIO_IRQF_TRIGGER_RISING)

struct gpiod_mock_data {
	struct gpio_mock_desc *desc;

	struct mutex mutex;

	struct kernfs_node *value_kn;
	int irq;
	unsigned char irq_flags;

	bool direction_can_change;
};

/*
 * Lock to serialise gpiod export and unexport, and prevent re-export of
 * gpiod whose chip is being unregistered.
 */
static DEFINE_MUTEX(sysfs_lock);

/*
 * /sys/class/gpio/gpioN... only for GPIOs that are exported
 *   /direction
 *      * MAY BE OMITTED if kernel won't allow direction changes
 *      * is read/write as "in" or "out"
 *      * may also be written as "high" or "low", initializing
 *        output value as specified ("out" implies "low")
 *   /value
 *      * always readable, subject to hardware behavior
 *      * may be writable, as zero/nonzero
 *   /edge
 *      * configures behavior of poll(2) on /value
 *      * available only if pin can generate IRQs on input
 *      * is read/write as "none", "falling", "rising", or "both"
 *   /active_low
 *      * configures polarity of /value
 *      * is read/write as zero/nonzero
 *      * also affects existing and subsequent "falling" and "rising"
 *        /edge configuration
 */

static ssize_t direction_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	ssize_t			status;

	status = sprintf(buf, "%s\n",
			test_bit(FLAG_IS_OUT, &desc->flags)
				? "out" : "in");

	return status;
}

static ssize_t direction_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	ssize_t			status;

	mutex_lock(&data->mutex);

	if (sysfs_streq(buf, "high"))
		status = gpiod_mock_direction_output_raw(desc, 1);
	else if (sysfs_streq(buf, "out") || sysfs_streq(buf, "low"))
		status = gpiod_mock_direction_output_raw(desc, 0);
	else if (sysfs_streq(buf, "in"))
		status = gpiod_mock_direction_input(desc);
	else
		status = -EINVAL;

	mutex_unlock(&data->mutex);

	return status ? : size;
}
static DEVICE_ATTR_RW(direction);

static ssize_t value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	ssize_t			status;

	mutex_lock(&data->mutex);

	status = gpiod_mock_get_value(desc);
	if (status < 0)
		goto err;

	buf[0] = '0' + status;
	buf[1] = '\n';
	status = 2;
err:
	mutex_unlock(&data->mutex);

	return status;
}

static ssize_t value_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	ssize_t status = 0;

	mutex_lock(&data->mutex);

	if (!test_bit(FLAG_IS_OUT, &desc->flags)) {
		status = -EPERM;
	} else {
		long		value;

		if (size <= 2 && isdigit(buf[0]) &&
		    (size == 1 || buf[1] == '\n'))
			value = buf[0] - '0';
		else
			status = kstrtol(buf, 0, &value);
		if (status == 0) {
			gpiod_mock_set_value(desc, value);
			status = size;
		}
	}

	mutex_unlock(&data->mutex);

	return status;
}
static DEVICE_ATTR_PREALLOC(value, S_IWUSR | S_IRUGO, value_show, value_store);

/* Caller holds gpiod-data mutex. */
static int gpio_mock_sysfs_request_irq(struct device *dev, unsigned char flags)
{
	struct gpiod_mock_data	*data = dev_get_drvdata(dev);
	struct gpio_mock_desc	*desc = data->desc;
	unsigned long		irq_flags;

	pr_debug("%s: Setup gpio %ld as irq\n", __func__, desc->gpio);

	data->irq = 1;

	data->value_kn = sysfs_get_dirent(dev->kobj.sd, "value");
	if (!data->value_kn)
		return -ENODEV;

	irq_flags = IRQF_SHARED;
	if (flags & GPIO_IRQF_TRIGGER_FALLING)
		irq_flags |= test_bit(FLAG_ACTIVE_LOW, &desc->flags) ?
			IRQF_TRIGGER_RISING : IRQF_TRIGGER_FALLING;
	if (flags & GPIO_IRQF_TRIGGER_RISING)
		irq_flags |= test_bit(FLAG_ACTIVE_LOW, &desc->flags) ?
			IRQF_TRIGGER_FALLING : IRQF_TRIGGER_RISING;

	data->irq_flags = flags;

	return 0;
}

/*
 * Caller holds gpiod-data mutex (unless called after class-device
 * deregistration).
 */
static void gpio_mock_sysfs_free_irq(struct device *dev)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc	*desc = data->desc;

	pr_debug("%s: Free gpio %ld as irq\n", __func__, desc->gpio);

	data->irq = 0;
	data->irq_flags = 0;

	sysfs_put(data->value_kn);
}

static const struct {
	const char *name;
	unsigned char flags;
} trigger_types[] = {
	{ "none",    0 },
	{ "falling", GPIO_IRQF_TRIGGER_FALLING },
	{ "rising",  GPIO_IRQF_TRIGGER_RISING },
	{ "both",    GPIO_IRQF_TRIGGER_BOTH },
};

static ssize_t edge_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	ssize_t	status = 0;
	int i;

	mutex_lock(&data->mutex);

	for (i = 0; i < ARRAY_SIZE(trigger_types); i++) {
		if (data->irq_flags == trigger_types[i].flags) {
			status = sprintf(buf, "%s\n", trigger_types[i].name);
			break;
		}
	}

	mutex_unlock(&data->mutex);

	return status;
}

static ssize_t edge_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	unsigned char flags;
	ssize_t	status = size;
	int i;

	for (i = 0; i < ARRAY_SIZE(trigger_types); i++) {
		if (sysfs_streq(trigger_types[i].name, buf))
			break;
	}

	if (i == ARRAY_SIZE(trigger_types))
		return -EINVAL;

	flags = trigger_types[i].flags;

	mutex_lock(&data->mutex);

	if (flags == data->irq_flags) {
		status = size;
		goto out_unlock;
	}

	if (data->irq_flags)
		gpio_mock_sysfs_free_irq(dev);

	if (flags) {
		status = gpio_mock_sysfs_request_irq(dev, flags);
		if (!status)
			status = size;
	}

out_unlock:
	mutex_unlock(&data->mutex);

	return status;
}
static DEVICE_ATTR_RW(edge);

/* Caller holds gpiod-data mutex. */
static int gpio_sysfs_set_active_low(struct device *dev, int value)
{
	struct gpiod_mock_data	*data = dev_get_drvdata(dev);
	struct gpio_mock_desc	*desc = data->desc;
	int			status = 0;
	unsigned int		flags = data->irq_flags;

	if (!!test_bit(FLAG_ACTIVE_LOW, &desc->flags) == !!value)
		return 0;

	if (value)
		set_bit(FLAG_ACTIVE_LOW, &desc->flags);
	else
		clear_bit(FLAG_ACTIVE_LOW, &desc->flags);

	/* reconfigure poll(2) support if enabled on one edge only */
	if (flags == GPIO_IRQF_TRIGGER_FALLING ||
					flags == GPIO_IRQF_TRIGGER_RISING) {
		gpio_mock_sysfs_free_irq(dev);
		status = gpio_mock_sysfs_request_irq(dev, flags);
	}

	return status;
}

static ssize_t active_low_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	ssize_t			status;

	mutex_lock(&data->mutex);

	status = sprintf(buf, "%d\n",
				!!test_bit(FLAG_ACTIVE_LOW, &desc->flags));

	mutex_unlock(&data->mutex);

	return status;
}

static ssize_t active_low_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct gpiod_mock_data	*data = dev_get_drvdata(dev);
	ssize_t			status;
	long			value;

	mutex_lock(&data->mutex);

	status = kstrtol(buf, 0, &value);
	if (status == 0)
		status = gpio_sysfs_set_active_low(dev, value);

	mutex_unlock(&data->mutex);

	return status ? : size;
}
static DEVICE_ATTR_RW(active_low);

static umode_t gpio_mock_is_visible(struct kobject *kobj, struct attribute *attr,
			       int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct gpiod_mock_data *data = dev_get_drvdata(dev);
	struct gpio_mock_desc *desc = data->desc;
	umode_t mode = attr->mode;
	bool show_direction = data->direction_can_change;

	if (attr == &dev_attr_direction.attr) {
		if (!show_direction)
			mode = 0;
	} else if (attr == &dev_attr_edge.attr) {
		if (!show_direction && test_bit(FLAG_IS_OUT, &desc->flags))
			mode = 0;
	}

	return mode;
}

static struct attribute *gpio_mock_attrs[] = {
	&dev_attr_direction.attr,
	&dev_attr_edge.attr,
	&dev_attr_value.attr,
	&dev_attr_active_low.attr,
	NULL,
};

static const struct attribute_group gpio_mock_group = {
	.attrs = gpio_mock_attrs,
	.is_visible = gpio_mock_is_visible,
};

static const struct attribute_group *gpio_mock_groups[] = {
	&gpio_mock_group,
	NULL
};

/*
 * /sys/class/gpio/export ... write-only
 *	integer N ... number of GPIO to export (full access)
 * /sys/class/gpio/unexport ... write-only
 *	integer N ... number of GPIO to unexport
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t export_store(const struct class *class,
				const struct class_attribute *attr,
				const char *buf, size_t len)
#else
static ssize_t export_store(struct class *class,
				struct class_attribute *attr,
				const char *buf, size_t len)
#endif
{
	long			gpio;
	struct gpio_mock_desc	*desc;
	int			status;

	status = kstrtol(buf, 0, &gpio);
	if (status < 0)
		goto done;

	/* Get mocked GPIO descriptor here */
	desc = gpiod_mock_to_desc(gpio);
	/* reject invalid GPIOs */
	if (!desc) {
		pr_warn("%s: invalid GPIO %ld\n", __func__, gpio);
		return -EINVAL;
	}

	/* No extra locking here; FLAG_SYSFS just signifies that the
	 * request and export were done by on behalf of userspace, so
	 * they may be undone on its behalf too.
	 */

	status = gpiod_mock_request(desc, "sysfs");
	if (status < 0) {
		if (status == -EPROBE_DEFER)
			status = -ENODEV;
		goto done;
	}

	status = gpiod_mock_export(desc, true);
	if (status < 0)
		gpiod_mock_free(desc);
	else
		set_bit(FLAG_SYSFS, &desc->flags);

done:
	if (status)
		pr_debug("%s: status %d\n", __func__, status);
	return status ? : len;
}
static CLASS_ATTR_WO(export);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t unexport_store(const struct class *class,
				const struct class_attribute *attr,
				const char *buf, size_t len)
#else
static ssize_t unexport_store(struct class *class,
				struct class_attribute *attr,
				const char *buf, size_t len)
#endif
{
	long			gpio;
	struct gpio_mock_desc	*desc;
	int			status;

	status = kstrtol(buf, 0, &gpio);
	if (status < 0)
		goto done;

	desc = gpiod_mock_to_desc(gpio);
	/* reject bogus commands (gpio_unexport ignores them) */
	if (!desc) {
		pr_warn("%s: invalid GPIO %ld\n", __func__, gpio);
		return -EINVAL;
	}

	status = -EINVAL;

	/* No extra locking here; FLAG_SYSFS just signifies that the
	 * request and export were done by on behalf of userspace, so
	 * they may be undone on its behalf too.
	 */
	if (test_and_clear_bit(FLAG_SYSFS, &desc->flags)) {
		status = 0;
		gpiod_mock_free(desc);
	}
done:
	if (status)
		pr_debug("%s: status %d\n", __func__, status);
	return status ? : len;
}
static CLASS_ATTR_WO(unexport);

static struct attribute *gpio_mock_class_attrs[] = {
	&class_attr_export.attr,
	&class_attr_unexport.attr,
	NULL,
};

ATTRIBUTE_GROUPS(gpio_mock_class);

static struct class gpio_mock_class = {
	.name =		"gpio_mock",
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
	.owner =	THIS_MODULE,
#endif
	.class_groups = gpio_mock_class_groups,
};

static int match_export(struct device *dev, const void *desc)
{
	struct gpiod_mock_data *data = dev_get_drvdata(dev);

	return data->desc == desc;
}

void gpiod_mock_gen_irq(long gpio)
{
	struct gpio_mock_desc	*desc;
	struct gpiod_mock_data 	*data;
	struct device *dev;

	mutex_lock(&sysfs_lock);

	desc = gpiod_mock_to_desc(gpio);
	if (!desc) {
		pr_warn("%s: invalid GPIO %ld\n", __func__, gpio);
		return;
	}

	if (!test_bit(FLAG_EXPORT, &desc->flags)) {
		pr_warn("%s: GPIO %ld is not exported\n", __func__, gpio);
		goto err_unlock;
	}

	dev = class_find_device(&gpio_mock_class, NULL, desc, match_export);
	if (!dev) {
		pr_warn("%s: GPIO %ld - cannot find a device\n", __func__, gpio);
		goto err_unlock;
	}

	data = dev_get_drvdata(dev);

	sysfs_notify_dirent(data->value_kn);

err_unlock:
	mutex_unlock(&sysfs_lock);	
}
EXPORT_SYMBOL_GPL(gpiod_mock_gen_irq);

/**
 * gpiod_mock_export - export a GPIO through sysfs
 * @desc: GPIO to make available, already requested
 * @direction_may_change: true if userspace may change GPIO direction
 * Context: arch_initcall or later
 *
 * When drivers want to make a GPIO accessible to userspace after they
 * have requested it -- perhaps while debugging, or as part of their
 * public interface -- they may use this routine.  If the GPIO can
 * change direction (some can't) and the caller allows it, userspace
 * will see "direction" sysfs attribute which may be used to change
 * the gpio's direction.  A "value" attribute will always be provided.
 *
 * Returns zero on success, else an error.
 */
int gpiod_mock_export(struct gpio_mock_desc *desc, bool direction_may_change)
{
	struct gpiod_mock_data	*data;
	int			status;
	struct device		*dev;

	/* can't export until sysfs is available ... */
	/* The linux kernel version may be wrong here - at least it was working earlier */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
	if (!gpio_mock_class.p) {
#else
	if (!class_is_registered(&gpio_mock_class)) {
#endif
		pr_debug("%s: called too early!\n", __func__);
		return -ENOENT;
	}

	if (!desc) {
		pr_debug("%s: invalid gpio descriptor\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&sysfs_lock);

	if (!test_bit(FLAG_REQUESTED, &desc->flags) ||
	     test_bit(FLAG_EXPORT, &desc->flags)) {
		pr_debug("%s: unavailable (requested=%d, exported=%d)\n",
				__func__,
				test_bit(FLAG_REQUESTED, &desc->flags),
				test_bit(FLAG_EXPORT, &desc->flags));
		status = -EPERM;
		goto err_unlock;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		status = -ENOMEM;
		goto err_unlock;
	}

	data->desc = desc;
	mutex_init(&data->mutex);
	data->direction_can_change = direction_may_change;

	dev = device_create_with_groups(&gpio_mock_class, NULL,
					MKDEV(0, 0), data, gpio_mock_groups,
					"gpio%u",
					mock_desc_to_gpio(desc));
	if (IS_ERR(dev)) {
		status = PTR_ERR(dev);
		goto err_free_data;
	}

	set_bit(FLAG_EXPORT, &desc->flags);
	mutex_unlock(&sysfs_lock);
	return 0;

err_free_data:
	kfree(data);
err_unlock:
	mutex_unlock(&sysfs_lock);
	pr_debug("%s: status %d\n", __func__, status);
	return status;
}
EXPORT_SYMBOL_GPL(gpiod_mock_export);

/**
 * gpiod_mock_export_link - create a sysfs link to an exported GPIO node
 * @dev: device under which to create symlink
 * @name: name of the symlink
 * @desc: GPIO to create symlink to, already exported
 *
 * Set up a symlink from /sys/.../dev/name to /sys/class/gpio/gpioN
 * node. Caller is responsible for unlinking.
 *
 * Returns zero on success, else an error.
 */
int gpiod_mock_export_link(struct device *dev, const char *name,
		      struct gpio_mock_desc *desc)
{
	struct device *cdev;
	int ret;

	if (!desc) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}

	cdev = class_find_device(&gpio_mock_class, NULL, desc, match_export);
	if (!cdev)
		return -ENODEV;

	ret = sysfs_create_link(&dev->kobj, &cdev->kobj, name);
	put_device(cdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gpiod_mock_export_link);

/**
 * gpiod_mock_unexport - reverse effect of gpiod_mock_export()
 * @desc: GPIO to make unavailable
 *
 * This is implicit on gpiod_free().
 */
void gpiod_mock_unexport(struct gpio_mock_desc *desc)
{
	struct gpiod_mock_data *data;
	struct device *dev;

	if (!desc) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return;
	}

	mutex_lock(&sysfs_lock);

	if (!test_bit(FLAG_EXPORT, &desc->flags))
		goto err_unlock;

	dev = class_find_device(&gpio_mock_class, NULL, desc, match_export);
	if (!dev)
		goto err_unlock;

	data = dev_get_drvdata(dev);

	clear_bit(FLAG_EXPORT, &desc->flags);

	device_unregister(dev);

	/*
	 * Release irq after deregistration to prevent race with edge_store.
	 */
	if (data->irq_flags)
		gpio_mock_sysfs_free_irq(dev);

	mutex_unlock(&sysfs_lock);

	put_device(dev);
	kfree(data);

	return;

err_unlock:
	mutex_unlock(&sysfs_lock);
}
EXPORT_SYMBOL_GPL(gpiod_mock_unexport);

static int __init gpiolib_mock_sysfs_init(void)
{
	int		status;

	_mocked_gpios.descs = kmalloc(sizeof(struct gpio_mock_desc) * GPIO_MOCKED_NUMBER_MAX, GFP_KERNEL);
	_mocked_gpios.descs[0].gpio = 1;
	_mocked_gpios.descs[1].gpio = 796;
	_mocked_gpios.descs[2].gpio = 986;
	_mocked_gpios.ngpio = GPIO_MOCKED_NUMBER_MAX;

	status = class_register(&gpio_mock_class);

	return status;
}

static void __exit gpiolib_mock_sysfs_exit(void) {
	printk(KERN_INFO "[gpiolib_mock_sysfs_exit] Exit module!\n");
	class_unregister(&gpio_mock_class);

	_mocked_gpios.ngpio = 0;
	kfree(_mocked_gpios.descs);
}

module_init(gpiolib_mock_sysfs_init);
module_exit(gpiolib_mock_sysfs_exit);

/* Meta Information */
MODULE_AUTHOR("Marcin Nowakowski");
MODULE_DESCRIPTION("Register mock gpio module.");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
