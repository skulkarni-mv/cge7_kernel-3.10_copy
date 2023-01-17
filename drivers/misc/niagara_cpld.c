#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/miscdevice.h>

#include <linux/slab.h>
#include <linux/mutex.h>

#include <asm/octeon/cvmx.h>

/* in order to use values from DT node compatible="imt,n830-cpld-serirq",
 * ('cpld_serirq_base' and 'polarity_offset'), please comment out the next line
 */
/* #define USE_CPLD_DEFINE */

/*
 * #############################################################################
 * MISC CPLD REGISTERS/BITS
 * #############################################################################
 */
#define MISC_CSR	0x0B
#define UART_CAN_SEL	(1<<2)/*bit2*/

/*
 * #############################################################################
 * CPLD READ/WRITE SUPPORT
 * #############################################################################
 */

static uint8_t *niagara_cpld_base;

static inline void cpldw(uint16_t offset, uint8_t val);
static inline uint8_t cpldr(uint16_t offset);

static inline void cpldw(uint16_t offset, uint8_t val)
{
	writeb(val, niagara_cpld_base + offset);
}

static inline uint8_t cpldr(uint16_t offset)
{
	uint8_t val = readb(niagara_cpld_base + offset);
	return val;
}

/*
 * #############################################################################
 * CPLD_LPC READ/WRITE SUPPORT
 * #############################################################################
 */
#define CPLD_ADDR_LPC_CMD		0x48
#define CPLD_ADDR_LPC_STAT		0x49
#define CPLD_ADDR_LPC_DATA		0x4A

#define CPLD_LPC_STAT_EV		0x01
#define CPLD_LPC_STAT_TOUT		0x08
#define CPLD_LPC_STAT_PERR		0x10
#define CPLD_LPC_STAT_INV		0x20

#define LPC_SUCCESS			0
#define LPC_ERROR_UNKNOWN		1
#define LPC_INV_SYNC			2
#define LPC_PERIPH_ERR			3
#define LPC_TIMEOUT			4

static uint8_t *cpld_lpc_base;

static inline int lpc_io_stat(void)
{
	return LPC_SUCCESS;
}

static inline int lpc_io_read(uint16_t addr)
{
	uint8_t data;
	int lpc_stat;
	data = readb(cpld_lpc_base + addr);
	lpc_stat = lpc_io_stat();
	return (lpc_stat == LPC_SUCCESS) ? data : lpc_stat;
}

static inline int lpc_io_write(uint16_t addr, uint8_t data)
{
	writeb(data, cpld_lpc_base + addr);
	return lpc_io_stat();
}


/*
 * #############################################################################
 * Winbond SIO LPC READ/WRITE SUPPORT
 * #############################################################################
 */
#define W83627_UART_A_BASE_DEFAULT	0x3F8
#define W83627_UART_B_BASE_DEFAULT	0x2F8

/** depends on the strapping on the carrier board */
#define W83627_EFER		0x4E
#define W83627_EF_ENTER		0x87
#define W83627_EF_EXIT		0xAA

#define W83627_EFIR		(W83627_EFER)
#define W83627_EFDR		(W83627_EFIR+1)

#define W83627_CR_GL_RESET	0x02
#define W83627_CR_GL_ID_MSB	0x20
#define W83627_CR_GL_ID_LSB	0x21
#define W83627_CR_GL_POWER	0x22
#define W83627_CR_GL_OPT	0x24

#define W83627_CR_GL_LEGACY	0x26

#define W83627_CR_GL_DEV	0x07
#define W83627_DEV_UART_A	0x02
#define W83627_DEV_UART_B	0x03

#define W83627_CR_UARTA_BASE_H	0x60
#define W83627_CR_UARTA_BASE_L	0x61
#define W83627_CR_UARTA_CLK	0xF0
#define W83627_UART_CLK_14_769	0x03

static int w83627_ef_read(uint8_t addr)
{
	int ret, val;
	ret = lpc_io_write(W83627_EFIR, addr);
	if (ret != LPC_SUCCESS)
		return ret;

	val = lpc_io_read(W83627_EFDR);
	return val;
}

static int w83627_ef_write(uint8_t addr, uint8_t data)
{
	int ret = lpc_io_write(W83627_EFIR, addr);
	if (ret != LPC_SUCCESS)
		return ret;

	return lpc_io_write(W83627_EFDR, data);
}

int w83627_init(void)
{
	int ret = lpc_io_write(W83627_EFER, W83627_EF_ENTER);
	if (ret != LPC_SUCCESS)
		return ret;

	ret = lpc_io_write(W83627_EFER, W83627_EF_ENTER);
	if (ret != LPC_SUCCESS)
		return ret;

	pr_info("SuperIO dev id <%02x%02x>\n",
		(uint8_t)w83627_ef_read(W83627_CR_GL_ID_MSB),
		(uint8_t)w83627_ef_read(W83627_CR_GL_ID_LSB));

	/* set the input clock to 24MHz */
	ret = w83627_ef_write(W83627_CR_GL_OPT, 0x06);
	if (ret != LPC_SUCCESS)
		return ret;

	/* only UART A enabled */
	ret = w83627_ef_write(W83627_CR_GL_POWER, 0x10);
	if (ret != LPC_SUCCESS)
		return ret;

	/* disable IRQ legacy mode for UARTA */
	ret = w83627_ef_write(W83627_CR_GL_LEGACY, 0x42);
	if (ret != LPC_SUCCESS)
		return ret;

	ret = w83627_ef_write(W83627_CR_GL_DEV, W83627_DEV_UART_A);
	if (ret != LPC_SUCCESS)
		return ret;

	ret = w83627_ef_write(W83627_CR_UARTA_CLK, W83627_UART_CLK_14_769);
	if (ret != LPC_SUCCESS)
		return ret;

	ret = lpc_io_write(W83627_EFER, W83627_EF_EXIT);
	if (ret != LPC_SUCCESS)
		return ret;

	return 0;
}

/*
 * #############################################################################
 * Winbond LPC UART SUPPORT
 * #############################################################################
 */
static uint8_t *lpc_uart_base;


/*
 * #############################################################################
 * CPLD INTERRUPT CONTROLLER
 * #############################################################################
 */
#define S_PAD		0x03
#define INT_STAT_0	0x0E
#define INT_EN_0	0x0F
#define INT_STAT_1	0x10
#define INT_EN_1	0x11

/* INT_STAT_0 bits */
#define TMP_ALERT	0x01
#define TMP_OVERT	0x02
#define CB_THERM	0x04
#define FAN_EV		0x08
#define CAN_RX0BF	0x10
#define CAN_RX1BF	0x20
#define LPC_EV		0x40
#define BATLOW		0x80

/* INT_STAT_1 bits */
#define SERIRQ_EV	0x01
#define PB_RST_EV	0x40
#define OVERT_EV	0x80

struct n830_irq_data {
	struct irq_domain	*domain;	/* Domain for this controller */
	unsigned int		num_ints;	/* number of interrupts */
	u32			irq_valid;
};
static struct n830_irq_data intctl;

static void n830_intctl_irq_unmask(struct irq_data *d)
{
	u8 status;
	u16 index, mask_reg;

	if (!(intctl.irq_valid & (1 << d->hwirq)))
		return;	/* ignore invalid irqs */

	index = d->hwirq < 8 ? 0 : 1;
	mask_reg = index == 0 ? INT_EN_0 : INT_EN_1;

	status = cpldr(mask_reg);
	status |= (1 << (d->hwirq - index*8));
	cpldw(mask_reg, status);
}

static void n830_intctl_irq_mask(struct irq_data *d)
{
	u8 status;
	u16 index, mask_reg;

	if (!(intctl.irq_valid & (1 << d->hwirq)))
		return;	/* ignore invalid irqs */

	index = d->hwirq < 8 ? 0 : 1;
	mask_reg = index == 0 ? INT_EN_0 : INT_EN_1;

	status = cpldr(mask_reg);
	status &= ~(1 << (d->hwirq - index*8));
	cpldw(mask_reg, status);
}

static int n830_intctl_irq_set_type(struct irq_data *d, unsigned int flow_type)
{
	switch (flow_type) {
	case IRQF_TRIGGER_HIGH:
		__irq_set_handler_locked(d->irq, handle_level_irq);
		break;
	case IRQF_TRIGGER_LOW:
	case IRQF_TRIGGER_FALLING:
	case IRQF_TRIGGER_RISING:
		return -EINVAL;
	}

	return 0;
}


static struct irq_chip n830_intctl_irq_chip = {
	.name = "n830_intctl",
	.irq_ack = n830_intctl_irq_mask,
	.irq_mask = n830_intctl_irq_mask,
	.irq_unmask = n830_intctl_irq_unmask,
	.irq_set_type = n830_intctl_irq_set_type,
};

static void __init n830_intctl_init_irq_hw(void)
{
	/* disable interrupts */
	cpldw(INT_EN_0, 0);
	cpldw(INT_EN_1, 0);
	/* clear interrupt_status */
	cpldw(INT_STAT_0, 0xFF);	/* W1C writable */
	cpldw(INT_STAT_1, 0xFF);
}

static void n830_intctl_handle_irq(unsigned int irq, struct irq_desc *desc)
{
	u32 stat, ints_en;
	int irqnr, virq, count_zeros;
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);

	/* read which interrupt happens in INT_STAT_x */
	stat = (u32)cpldr(INT_STAT_0) | ((u32)cpldr(INT_STAT_1) << 8);
	ints_en = (u32)cpldr(INT_EN_0) | ((u32)cpldr(INT_EN_1) << 8);
	stat &= ints_en;
	if (!(stat & intctl.irq_valid)) { /* ignore invalid irqs */
		chained_irq_exit(chip, desc);
		return;
	}
	/* handle all pending interrupts */
	stat &= intctl.irq_valid;
	count_zeros = 0;
	for (irqnr = 0; stat != 0; stat >>= 1, irqnr++) {
		int seq_irq;
		if (!(intctl.irq_valid & (1 << irqnr)))
			count_zeros++;	/* count '0' bits in irq_valid */
		if (!(stat & 0x1))
			continue;	/* skip '0' bits in stat */

		seq_irq = irqnr - count_zeros;	/* sub number of zeros */
		virq = irq_find_mapping(intctl.domain, seq_irq);
		generic_handle_irq(virq);
	}
	chained_irq_exit(chip, desc);
}


static int n830_intctl_irq_map(struct irq_domain *h, unsigned int virq,
							irq_hw_number_t hw)
{
	irq_set_chip_and_handler(virq, &n830_intctl_irq_chip, handle_level_irq);
	return 0;
}

static struct irq_domain_ops n830_intctl_domain_ops = {
	.map = n830_intctl_irq_map,
	.xlate = irq_domain_xlate_onecell,
};

int __init n830_intctl_irq_init(struct device_node *node,
				struct device_node *parent)
{
	int virq, i;
	u32 irq_valid_bits;
	struct device_node *np = node;

	if (niagara_cpld_base == 0) {
		niagara_cpld_base = of_iomap(node, 0);
		if (!niagara_cpld_base)
			goto out; /* return -ENODEV; */
	}

	if (of_property_read_u32_index(node, "irq-valid", 0,
		&intctl.irq_valid)) {
		pr_err("ERROR: when read 'irq-valid'\n");
		goto out;
	}
	/* find the number of valid interrupts ('1') in irq-valid */
	irq_valid_bits = __builtin_popcount(intctl.irq_valid);
	intctl.num_ints = irq_valid_bits;

	intctl.domain = irq_domain_add_linear(node, irq_valid_bits,
					&n830_intctl_domain_ops, &intctl);
	if (!intctl.domain) {
		pr_err("%s: Unable to add irq domain!\n", __func__);
		goto out;
	}

	for (i = 0; i < irq_valid_bits; i++) {
		virq = irq_create_mapping(intctl.domain, i);
		irq_set_chip_and_handler(virq, &n830_intctl_irq_chip,
					 handle_level_irq);
	}

	virq = irq_of_parse_and_map(np, 0);

	irq_set_chained_handler(virq, n830_intctl_handle_irq);

	n830_intctl_init_irq_hw();

	pr_info("Added n830 INTCTL interrupt controller\n");
out:
	return 0;
}


/*
 * #############################################################################
 * SERIRQ INTERRUPT CONTROLLER
 * #############################################################################
 */
#ifdef USE_CPLD_DEFINE

#define SERIRQ_CTL	0x20
#define SERIRQ_ST_0	0x21
#define SERIRQ_ST_1	0x22
#define SERIRQ_ST_2	0x23
#define SIRQ_EN_0	0x24
#define SIRQ_EN_1	0x25
#define SIRQ_EN_2	0x26
#define SIRQ_POL_0	0x50
#define SIRQ_POL_1	0x51
#define SIRQ_POL_2	0x52

#else

#define serirq_offset	(cpld_serirq_base - niagara_cpld_base)/*should be 0x20*/
#define SERIRQ_CTL	(serirq_offset + 0)/*0x20*/
#define SERIRQ_ST_0	(serirq_offset + 1)/*0x21*/
#define SERIRQ_ST_1	(serirq_offset + 2)/*0x22*/
#define SERIRQ_ST_2	(serirq_offset + 3)/*0x23*/
#define SIRQ_EN_0	(serirq_offset + 4)/*0x24*/
#define SIRQ_EN_1	(serirq_offset + 5)/*0x25*/
#define SIRQ_EN_2	(serirq_offset + 6)/*0x26*/
#define SIRQ_POL_0	(serirq_offset + polarity_offset + 0)/*0x50*/
#define SIRQ_POL_1	(serirq_offset + polarity_offset + 1)/*0x51*/
#define SIRQ_POL_2	(serirq_offset + polarity_offset + 2)/*0x52*/

#endif

/* SERIRQ_CTL bits */
#define START_FRM	0x01
#define SERIRQ_MD	0x02
#define FR0		0x10
#define FR1		0x20

/* SERIRQ_ST_0 bits */
#define SIRQ_IRQ0	0x01
#define SIRQ_IRQ1	0x02
#define SIRQ_IRQ2	0x04
#define SIRQ_IRQ3	0x08
#define SIRQ_IRQ4	0x10
#define SIRQ_IRQ5	0x20
#define SIRQ_IRQ6	0x40
#define SIRQ_IRQ7	0x80

/* SERIRQ_ST_1 bits */
#define SIRQ_IRQ8	0x01
#define SIRQ_IRQ9	0x02
#define SIRQ_IRQ10	0x04
#define SIRQ_IRQ11	0x08
#define SIRQ_IRQ12	0x10
#define SIRQ_IRQ13	0x20
#define SIRQ_IRQ14	0x40
#define SIRQ_IRQ15	0x80

/* SERIRQ_ST_2 bits */
#define IOCHK_N		0x01
#define PCI_INTA_N	0x02
#define PCI_INTB_N	0x04
#define PCI_INTC_N	0x08
#define PCI_INTD_N	0x10

/* Global variable for accessing io-mem addresses */
static uint8_t *cpld_serirq_base;
static struct n830_irq_data serirq;
static u32 polarity_offset;

static void n830_serirq_irq_unmask(struct irq_data *d)
{
	u8 status, mask_reg;
	u16 index;

	if (!(serirq.irq_valid & (1 << d->hwirq)))
		return;	/* ignore invalid irqs */

	index = d->hwirq < 8 ? 0 : (d->hwirq < 16 ? 1 : 2);

	mask_reg = index == 0 ? SIRQ_EN_0 :
			(index == 1 ? SIRQ_EN_1 : SIRQ_EN_2);

	status = cpldr(mask_reg);
	status |= (1 << (d->hwirq - 8*index));
	cpldw(mask_reg, status);
	mb();
}

static void n830_serirq_irq_mask(struct irq_data *d)
{
	u8 status, mask_reg;
	u16 index;

	if (!(serirq.irq_valid & (1 << d->hwirq)))
		return;	/* ignore invalid irqs */

	index = d->hwirq < 8 ? 0 : (d->hwirq < 16 ? 1 : 2);

	mask_reg = index == 0 ? SIRQ_EN_0 :
			(index == 1 ? SIRQ_EN_1 : SIRQ_EN_2);

	status = cpldr(mask_reg);
	status &= ~(1 << (d->hwirq - 8*index));
	cpldw(mask_reg, status);
	mb();
}

static void n830_serirq_irq_ack(struct irq_data *d)
{
	u8 status, stat_reg;
	u16 index;

	if (!(serirq.irq_valid & (1 << d->hwirq)))
		return;	/* ignore invalid irqs */

	index = d->hwirq < 8 ? 0 : (d->hwirq < 16 ? 1 : 2);

	stat_reg = index == 0 ? SERIRQ_ST_0 :
			(index == 1 ? SERIRQ_ST_1 : SERIRQ_ST_2);

	status = cpldr(stat_reg);
	status &= (1 << (d->hwirq - 8*index));
	cpldw(stat_reg, status);
	mb();
}

static int n830_serirq_irq_set_type(struct irq_data *d, unsigned int flow_type)
{
	switch (flow_type) {
	case IRQF_TRIGGER_HIGH:
		__irq_set_handler_locked(d->irq, handle_level_irq);
		break;
	case IRQF_TRIGGER_LOW:
	case IRQF_TRIGGER_FALLING:
	case IRQF_TRIGGER_RISING:
		return -EINVAL;
	}

	return 0;
}


static struct irq_chip n830_serirq_irq_chip = {
	.name = "n830_serirq",
	.irq_ack = n830_serirq_irq_ack,
	.irq_mask = n830_serirq_irq_mask,
	.irq_unmask = n830_serirq_irq_unmask,
	.irq_set_type = n830_serirq_irq_set_type,
};

static void __init n830_serirq_init_irq_hw(void)
{
	/* disable interrupts */
	cpldw(SIRQ_EN_0, 0);
	cpldw(SIRQ_EN_1, 0);
	cpldw(SIRQ_EN_2, 0);
	/* reset polarity */
	cpldw(SIRQ_POL_0, 0);
	cpldw(SIRQ_POL_1, 0);
	cpldw(SIRQ_POL_2, 0);
	wmb();
	/* clear interrupt_status */
	cpldw(SERIRQ_ST_0, 0xFF);	/* W1C writable */
	cpldw(SERIRQ_ST_1, 0xFF);
	cpldw(SERIRQ_ST_2, 0xFF);
	wmb();
}

static int n830_serirq_irq_map(struct irq_domain *h, unsigned int virq,
							irq_hw_number_t hw)
{
	irq_set_chip_and_handler(virq, &n830_serirq_irq_chip, handle_level_irq);
	return 0;
}

static struct irq_domain_ops n830_serirq_domain_ops = {
	.map = n830_serirq_irq_map,
	.xlate = irq_domain_xlate_onecell,
};


static void n830_serirq_handle_irq(unsigned int irq, struct irq_desc *desc)
{
	u32 stat, ints_en;
	int irqnr, virq;
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);

	/* read which interrupt happens in INT_STAT_x */
	stat = (u32)cpldr(SERIRQ_ST_0) | ((u32)cpldr(SERIRQ_ST_1) << 8) |
		((u32)cpldr(SERIRQ_ST_2) << 16);
	ints_en = (u32)cpldr(SIRQ_EN_0) | ((u32)cpldr(SIRQ_EN_1) << 8) |
		((u32)cpldr(SIRQ_EN_2) << 16);
	stat &= ints_en;

	if (!(stat & serirq.irq_valid)) { /* ignore invalid irqs */
		chained_irq_exit(chip, desc);
		return;
	}

	/* handle all pending interrupts */
	stat &= serirq.irq_valid;
	for (irqnr = 0; stat != 0; stat >>= 1, irqnr++) {
		if (!(stat & 0x1))
			continue;	/* skip '0' bits */
		virq = irq_find_mapping(serirq.domain, irqnr);
		generic_handle_irq(virq);
	}
	chained_irq_exit(chip, desc);
}


int __init n830_serirq_irq_init(struct device_node *node,
				struct device_node *parent)
{
	int virq, i;
	u32 irq_valid_bits;
	struct device_node *np = node;

	if (unlikely(niagara_cpld_base == 0)) {
		niagara_cpld_base = of_iomap(parent/*!!!*/, 0);
		if (!niagara_cpld_base)
			return -ENODEV;
	}

	if (of_property_read_u32_index(node, "irq-valid", 0,
		&serirq.irq_valid)) {
		pr_err("ERROR: when read 'irq-valid'\n");
		goto out;
	}
	if (of_property_read_u32_index(node, "polarity-offset", 0,
		&polarity_offset)) {
		pr_err("ERROR: when read 'polarity-offset'\n");
		goto out;
	}
	/* find the number of valid interrupts in irq-valid */
	irq_valid_bits = __builtin_popcount(serirq.irq_valid);
	serirq.num_ints = irq_valid_bits;
	serirq.domain = irq_domain_add_linear(node, irq_valid_bits,
					&n830_serirq_domain_ops, &serirq);

	if (!serirq.domain) {
		pr_err("%s: Unable to add irq domain!\n", __func__);
		goto out;
	}


	for (i = 0; i < irq_valid_bits; i++) {
		virq = irq_create_mapping(serirq.domain, i);
		irq_set_chip_and_handler(virq, &n830_serirq_irq_chip,
					 handle_level_irq);
	}

	virq = irq_of_parse_and_map(np, 0);	/* get irq num */

	irq_set_chained_handler(virq, n830_serirq_handle_irq);

	n830_serirq_init_irq_hw();

	pr_info("Added n830 SERIRQ interrupt controller\n");
out:
	return 0;
}

/*
 * #############################################################################
 * CPLD/LPC/SIO REGISTER ACCESS DRIVER
 * #############################################################################
 */

#define	CPLD_IOCTL_BASE	'G'
#define	CPLD_REG_READ			_IOWR(CPLD_IOCTL_BASE, 0, int)
#define	CPLD_REG_WRITE			_IOWR(CPLD_IOCTL_BASE, 1, int)
#define	LPC_REG_READ			_IOWR(CPLD_IOCTL_BASE, 2, int)
#define	LPC_REG_WRITE			_IOWR(CPLD_IOCTL_BASE, 3, int)
#define	SIO_REG_READ			_IOWR(CPLD_IOCTL_BASE, 4, int)
#define	SIO_REG_WRITE			_IOWR(CPLD_IOCTL_BASE, 5, int)
#define IOC_MAXNR			5

MODULE_DESCRIPTION("Niagara CPLD/LPC/SIO Register Read/Write driver");
MODULE_AUTHOR("EmilGoranov@caviumnetworks.com");
MODULE_LICENSE("GPL");


struct cpld_reg_t {
	unsigned int	addr;
	unsigned int	data;
};


/*===============================*/
inline unsigned int cpld_reg_read(unsigned int offset)
{
	return cpldr(offset);
}

inline void cpld_reg_write(unsigned int offset, unsigned int val)
{
	cpldw(offset, val);
}

inline unsigned int lpc_reg_read(unsigned int offset)
{
	return lpc_io_read(offset);
}

inline void lpc_reg_write(unsigned int offset, unsigned int val)
{
	lpc_io_write(offset, val);
}
inline unsigned int sio_reg_read(unsigned int offset)
{
	return w83627_ef_read(offset);
}

inline void sio_reg_write(unsigned int offset, unsigned int val)
{
	w83627_ef_write(offset, val);
}



static unsigned long cpld_is_open;

static int cpld_open(struct inode *inode, struct file *file)
{
	if (test_and_set_bit(0, &cpld_is_open))
		return -EBUSY;

	return nonseekable_open(inode, file);
}

static int cpld_release(struct inode *inode, struct file *file)
{
	clear_bit(0, &cpld_is_open);
	return 0;
}

static ssize_t cpld_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	return count;
}

static ssize_t cpld_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return count;
}

static long cpld_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	/* check cmd and arg */
	if (_IOC_TYPE(cmd) != CPLD_IOCTL_BASE)
		return -ENOTTY;

	if (_IOC_NR(cmd) > IOC_MAXNR)
		return -ENOTTY;

	/* check validation user address */
	if ((_IOC_DIR(cmd) & _IOC_READ) != 0)
		err = !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd));
	else if ((_IOC_DIR(cmd) & _IOC_WRITE) != 0)
		err = !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd));

	if (err != 0)
		return -EFAULT;

	switch (cmd) {

	case CPLD_REG_READ:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
			sizeof(struct cpld_reg_t))) {
			pr_err(
			"ioctl(CPLD_REG_READ):copy_from_user() FAIL\n");
			return -EFAULT;
		} else {
			reg.data = cpld_reg_read(reg.addr);
			if (copy_to_user((void *)arg, &reg,
				sizeof(struct cpld_reg_t))) {
				pr_err(
				"ioctl(CPLD_REG_READ):copy_to_user() FAIL\n");
				return -EFAULT;
			}
		}
	}
	break;

	case CPLD_REG_WRITE:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
				sizeof(struct cpld_reg_t))) {
			pr_err(
			 "ioctl(CPLD_REG_WRITE):copy_from_user() FAIL\n");
			return -EFAULT;
		} else
			cpld_reg_write(reg.addr, reg.data);
	}
	break;

	case LPC_REG_READ:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
					sizeof(struct cpld_reg_t))) {
			pr_err(
				"ioctl(PLC_REG_READ):copy_from_user() FAIL\n");
			return -EFAULT;
		} else {
			reg.data = lpc_reg_read(reg.addr);
			if (copy_to_user((void *)arg, &reg,
					sizeof(struct cpld_reg_t))) {
				pr_err(
				  "ioctl(LPC_REG_READ):copy_to_user() FAIL\n");
				return -EFAULT;
			}
		}
	}
	break;

	case LPC_REG_WRITE:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
				sizeof(struct cpld_reg_t))) {
			pr_err(
				"ioctl(LPC_REG_WRITE):copy_from_user() FAIL\n");
			return -EFAULT;
		} else
			lpc_reg_write(reg.addr, reg.data);
	}
	break;

	case SIO_REG_READ:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
				sizeof(struct cpld_reg_t))) {
			pr_err(
				"ioctl(SIO_REG_READ):copy_from_user() FAIL\n");
			return -EFAULT;
		} else {
			reg.data = sio_reg_read(reg.addr);
			if (copy_to_user((void *)arg, &reg,
					sizeof(struct cpld_reg_t))) {
				pr_err(
				 "ioctl(SIO_REG_READ):copy_to_user() FAIL\n");
				return -EFAULT;
			}
		}
	}
	break;

	case SIO_REG_WRITE:
	{
		struct cpld_reg_t reg;
		if (copy_from_user((void *)&reg, (void *)arg,
				sizeof(struct cpld_reg_t))) {
			pr_err(
				"ioctl(SIO_REG_WRITE):copy_from_user() FAIL\n");
			return -EFAULT;
		} else
			sio_reg_write(reg.addr, reg.data);
	}
	break;

	default:  /* redundant check */
	return -ENOTTY;
	}

	return 0;
}


static const struct file_operations cpld_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.write		= cpld_write,
	.read		= cpld_read,
	.unlocked_ioctl	= cpld_ioctl,
	.compat_ioctl	= cpld_ioctl,
	.open		= cpld_open,
	.release	= cpld_release,
};

#define CPLD_MINOR MISC_DYNAMIC_MINOR
static struct miscdevice cpld_miscdev = {
	.minor	= CPLD_MINOR,
	.name	= "cpld_miscdev",
	.fops	= &cpld_fops,
};

static int cpld_probe(struct platform_device *dev)
{
	int ret;

	ret = misc_register(&cpld_miscdev);

	if (ret) {
		pr_err("<cpld> cannot register miscdev (err=%d)\n", ret);
		return ret;
	}

	pr_info("<cpld_access> driver initialized.\n");
	return 0;
}

static int cpld_remove(struct platform_device *dev)
{
	misc_deregister(&cpld_miscdev);
	return 0;
}


static struct platform_device cpld_access_dev = {
	.name = "cpld_access",
};

static struct platform_driver cpld_driver = {
	.probe		= cpld_probe,
	.remove		= cpld_remove,
	.driver		= {
		.name	= "cpld_access",
	},
};

module_platform_driver(cpld_driver);


/*
 * #############################################################################
 * CPLD BASE DRIVER
 * #############################################################################
 */
static struct platform_device lpc_uart_pdev = {
	.name = "of_serial",
/*	.dev.of_node = lpc_uart_np; */
};


static int niagara_probe(struct platform_device *pdev)
{
	struct device_node *np, *serirq_np, *lpc_np, *lpc_uart_np;
	int ret;

	np = pdev->dev.of_node;
	if (np == NULL)
		return -EINVAL;

	niagara_cpld_base = of_iomap(np, 0);
	if (!niagara_cpld_base)
		return -ENODEV;

/* intialize INTCTL interrupt controller */
	n830_intctl_irq_init(np, of_get_parent(np));

/* initialize SERIRQ interrupt controller */
	/* find 'serirq' node */
	serirq_np = of_find_compatible_node(NULL, NULL, "imt,n830-cpld-serirq");
	cpld_serirq_base = of_iomap(serirq_np, 0);
	n830_serirq_irq_init(serirq_np, of_get_parent(serirq_np));

/* initialize LPC */
	/* find 'cpld-lpc' node */
	lpc_np = of_find_compatible_node(NULL, NULL, "imt,n830-cpld-lpc");
	cpld_lpc_base = of_iomap(lpc_np, 0);
	if (!cpld_lpc_base)
		return -ENODEV;

	w83627_init();

/* initialize Winbond LPC UARTA */
	lpc_uart_np = of_find_compatible_node(np/*NULL*/, NULL, "ns16550a");
	lpc_uart_base = of_iomap(lpc_uart_np, 0);
	if (!lpc_uart_base)
		return -ENODEV;

	/* to make possible "console=ttyS1,115200" do: */
	/* set MISC_CSR[UART_CAN_SEL]=1 => selects UART1 */
	cpldw(MISC_CSR, cpldr(MISC_CSR) | UART_CAN_SEL);

	/* set dev.of_node to the device tree node pointer */
	lpc_uart_pdev.dev.of_node = lpc_uart_np;
	/* register platform device - of_serial.c driver probe() will be call */
	ret = platform_device_register(&lpc_uart_pdev);

	/* register platform device - cpld_driver::cpld_probe() will be call */
	ret = platform_device_register(&cpld_access_dev);

	cpldw(SERIRQ_CTL, 0x31);	/* start (interrupt) frame, full speed*/
	cpldw(SIRQ_POL_0, SIRQ_IRQ4/*0x10*/);	/* invert IRQ4(UARTA) polarity*/

	return 0;
}

static int niagara_remove(struct platform_device *pdev)
{
	struct device_node *np;

	platform_device_unregister(&lpc_uart_pdev);
	np = pdev->dev.of_node;
	if (np == NULL)
		return -EINVAL;

	return 0;
}

static struct of_device_id niagara_of_match[] = {
	{ .compatible = "imt,n830-cpld-base",	},
	{},
};
MODULE_DEVICE_TABLE(of, niagara_of_match);

static struct platform_driver niagara_driver = {
	.probe		= niagara_probe,
	.remove		= niagara_remove,
	.driver = {
		.name	= "niagara",
		.owner	= THIS_MODULE,
		.of_match_table = niagara_of_match,
	},
};

module_platform_driver(niagara_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Interface Masters <support@interfacemasters.com>");
MODULE_DESCRIPTION("Niagara CPLD access driver");
