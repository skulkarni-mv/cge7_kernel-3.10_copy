#ifndef _ASM_GENERIC_GPIO_H
#define _ASM_GENERIC_GPIO_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/pinctrl/pinctrl.h>

#ifdef CONFIG_GPIOLIB

#include <linux/compiler.h>
#include <linux/gpio/driver.h>
#include <linux/gpio/consumer.h>

/* Platforms may implement their GPIO interface with library code,
 * at a small performance cost for non-inlined operations and some
 * extra memory (for code and for per-GPIO table entries).
 *
 * While the GPIO programming interface defines valid GPIO numbers
 * to be in the range 0..MAX_INT, this library restricts them to the
 * smaller range 0..ARCH_NR_GPIOS-1.
 *
 * ARCH_NR_GPIOS is somewhat arbitrary; it usually reflects the sum of
 * builtin/SoC GPIOs plus a number of GPIOs on expanders; the latter is
 * actually an estimate of a board-specific value.
 */

#ifndef ARCH_NR_GPIOS
#define ARCH_NR_GPIOS		256
#endif

/*
 * "valid" GPIO numbers are nonnegative and may be passed to
 * setup routines like gpio_request().  only some valid numbers
 * can successfully be requested and used.
 *
 * Invalid GPIO numbers are useful for indicating no-such-GPIO in
 * platform data and other tables.
 */

static inline bool gpio_is_valid(int number)
{
	return number >= 0 && number < ARCH_NR_GPIOS;
}

struct device;
struct gpio;
struct seq_file;
struct module;
struct device_node;
struct gpio_desc;

/* caller holds gpio_lock *OR* gpio is marked as requested */
static inline struct gpio_chip *gpio_to_chip(unsigned gpio)
{
	return gpiod_to_chip(gpio_to_desc(gpio));
}

/* Always use the library code for GPIO management calls,
 * or when sleeping may be involved.
 */
extern int gpio_request(unsigned gpio, const char *label);
extern void gpio_free(unsigned gpio);

extern int gpio_direction_input(unsigned gpio);
extern int gpio_direction_output(unsigned gpio, int value);

extern int gpio_set_debounce(unsigned gpio, unsigned debounce);

static inline int gpio_get_value_cansleep(unsigned gpio)
{
	return gpiod_get_raw_value_cansleep(gpio_to_desc(gpio));
}
static inline void gpio_set_value_cansleep(unsigned gpio, int value)
{
	return gpiod_set_raw_value_cansleep(gpio_to_desc(gpio), value);
}


/* A platform's <asm/gpio.h> code may want to inline the I/O calls when
 * the GPIO is constant and refers to some always-present controller,
 * giving direct access to chip registers and tight bitbanging loops.
 */
static inline int __gpio_get_value(unsigned gpio)
{
	return gpiod_get_raw_value(gpio_to_desc(gpio));
}
static inline void __gpio_set_value(unsigned gpio, int value)
{
	return gpiod_set_raw_value(gpio_to_desc(gpio), value);
}

static inline int __gpio_cansleep(unsigned gpio)
{
	return gpiod_cansleep(gpio_to_desc(gpio));
}

static inline int __gpio_to_irq(unsigned gpio)
{
	return gpiod_to_irq(gpio_to_desc(gpio));
}

extern int gpio_request_one(unsigned gpio, unsigned long flags, const char *label);
extern int gpio_request_array(const struct gpio *array, size_t num);
extern void gpio_free_array(const struct gpio *array, size_t num);

/*
 * A sysfs interface can be exported by individual drivers if they want,
 * but more typically is configured entirely from userspace.
 */
static inline int gpio_export(unsigned gpio, bool direction_may_change)
{
	return gpiod_export(gpio_to_desc(gpio), direction_may_change);
}

static inline int gpio_export_link(struct device *dev, const char *name,
				   unsigned gpio)
{
	return gpiod_export_link(dev, name, gpio_to_desc(gpio));
}

static inline int gpio_sysfs_set_active_low(unsigned gpio, int value)
{
	return gpiod_sysfs_set_active_low(gpio_to_desc(gpio), value);
}

static inline void gpio_unexport(unsigned gpio)
{
	gpiod_unexport(gpio_to_desc(gpio));
}

#ifdef CONFIG_PINCTRL

/**
 * struct gpio_pin_range - pin range controlled by a gpio chip
 * @head: list for maintaining set of pin ranges, used internally
 * @pctldev: pinctrl device which handles corresponding pins
 * @range: actual range of pins controlled by a gpio controller
 */

struct gpio_pin_range {
	struct list_head node;
	struct pinctrl_dev *pctldev;
	struct pinctrl_gpio_range range;
};

int gpiochip_add_pin_range(struct gpio_chip *chip, const char *pinctl_name,
			   unsigned int gpio_offset, unsigned int pin_offset,
			   unsigned int npins);
int gpiochip_add_pingroup_range(struct gpio_chip *chip,
			struct pinctrl_dev *pctldev,
			unsigned int gpio_offset, const char *pin_group);
void gpiochip_remove_pin_ranges(struct gpio_chip *chip);

#else

static inline int
gpiochip_add_pin_range(struct gpio_chip *chip, const char *pinctl_name,
		       unsigned int gpio_offset, unsigned int pin_offset,
		       unsigned int npins)
{
	return 0;
}
static inline int
gpiochip_add_pingroup_range(struct gpio_chip *chip,
			struct pinctrl_dev *pctldev,
			unsigned int gpio_offset, const char *pin_group)
{
	return 0;
}

static inline void
gpiochip_remove_pin_ranges(struct gpio_chip *chip)
{
}

#endif /* CONFIG_PINCTRL */

#else	/* !CONFIG_GPIOLIB */

static inline bool gpio_is_valid(int number)
{
	/* only non-negative numbers are valid */
	return number >= 0;
}

/* platforms that don't directly support access to GPIOs through I2C, SPI,
 * or other blocking infrastructure can use these wrappers.
 */

static inline int gpio_cansleep(unsigned gpio)
{
	return 0;
}

static inline int gpio_get_value_cansleep(unsigned gpio)
{
	might_sleep();
	return __gpio_get_value(gpio);
}

static inline void gpio_set_value_cansleep(unsigned gpio, int value)
{
	might_sleep();
	__gpio_set_value(gpio, value);
}

#endif /* !CONFIG_GPIOLIB */

#endif /* _ASM_GENERIC_GPIO_H */
