/*
 * OPV5XC SPI controller driver
 *
 * Author: Nikita Yushchenko <nyoushchenko@mvista.com>
 *
 * 2010 (c) MontaVista Software, LLC. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 */

#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <mach/opv5xc.h>
#include <mach/dma.h>

#ifdef CONFIG_PL330_DMA
#define DMA_SUPPORT
#include <linux/amba/pl330.h>
#define dma_filter		pl330_filter
#define dma_filter_param_tx	((void *)DMACH_SPI_TX)
#define dma_filter_param_rx	((void *)DMACH_SPI_RX)
#else
#undef DMA_SUPPORT
#endif

struct spi_opv5xc_regs {
	u32 spi_cfg;			/* 0x00 */
#define SPI_EN			BIT(31)
#define SPI_SWAP_EN		BIT(24)
#define SPI_CLKPOL		BIT(14)
#define SPI_CLKPHA		BIT(13)
#define SPI_MASTER_EN		BIT(11)
#define SPI_FFEN		BIT(10)
#define SPI_CHAR_LEN_MASK	3
#define SPI_CHAR_LEN(bytes)	(bytes - 1)
	u32 spi_stat;			/* 0x04 */
	u32 spi_bitrate;		/* 0x08 */
	u32 spi_tx_ctrl;		/* 0x0c */
#define SPI_TXCH_ACTIVE_SHIFT	4
#define SPI_TXDAT_EOF		BIT(2)
#define SPI_TXCH_NUM_MASK	3
#define SPI_TXCH_NUM(v)		(v & 3)
	u32 spi_tx_data;		/* 0x10 */
	u32 spi_rx_ctrl;		/* 0x14 */
	u32 spi_rx_data;		/* 0x18 */
	u32 spi_fifo_tx_cfg;		/* 0x1c */
#define TX_FIFO_WORDS(v)	(v & 0x1f)
#define TX_FIFO_WORDS_MAX	15		/* per manual */
	u32 spi_fifo_tx_ctrl;		/* 0x20 */
	u32 spi_fifo_rx_cfg;		/* 0x24 */
#define SPI_RXFF_THRED_MASK	(3 << 8)
#define SPI_RXFF_THRED_8	(1 << 8)
#define SPI_RXFF_THRED_4	(0 << 8)
#define RX_FIFO_WORDS(v)	(v & 0x1f)
	u32 spi_intr_stat;		/* 0x28 */
	u32 spi_intr_ena;		/* 0x2c */
#define SPI_RXBUF_FG		BIT(2)
#define SPI_RXFF_FG		BIT(0)
	u32 spi_boot_ctrl;		/* 0x30 */
	u32 spi_gdma_dbg;		/* 0x34 */
};

struct spi_opv5xc {
	struct spi_opv5xc_regs __iomem *regs;
	int irq;

	struct spi_message *msg;
	struct spi_transfer *xfer;
	unsigned tx_pos, rx_pos;
	bool deassert_cs;

	struct completion completion;

#ifdef DMA_SUPPORT
	bool use_dma;
	unsigned long regs_phys;
	unsigned bytes_for_dma;
	struct dma_chan *ch_tx, *ch_rx;
	struct page *page_tx, *page_rx;
#endif

	spinlock_t lock;
};

#define SPI_OPV5XC_MODE_BITS	(SPI_CPOL | SPI_CPHA | SPI_CS_HIGH)

#define SPI_OPV5XC_CLK_RATE	(100 * 1000 * 1000)
#define SPI_OPV5XC_MAX_SPEED	(SPI_OPV5XC_CLK_RATE / 2)
#define SPI_OPV5XC_MIN_SPEED	(SPI_OPV5XC_CLK_RATE / 128)

#define DEFAULT_BYTES_FOR_DMA	4096

#define NSEC_FOR_IRQ		10000		/* poll for smaller delay */

#define U32_AT_OFFSET(p, off)	(*(u32 *)((void *)p + off))
#define U8_AT_OFFSET(p, off)	(*(u8 *)((void *)p + off))

static int fifo_tx_available_words(struct spi_opv5xc *ospi)
{
	int words_in_fifo = TX_FIFO_WORDS(readl(&ospi->regs->spi_fifo_tx_cfg));
	return TX_FIFO_WORDS_MAX - words_in_fifo;
}

static void fifo_write_word(struct spi_opv5xc *ospi)
{
	struct spi_transfer *xfer = ospi->xfer;
	u32 word;

	if (xfer->tx_buf)
		word = be32_to_cpu(U32_AT_OFFSET(xfer->tx_buf, ospi->tx_pos));
	else
		word = 0;

	writel(word, &ospi->regs->spi_tx_data);

	ospi->tx_pos += 4;
}

static inline bool fifo_rx_available(struct spi_opv5xc *ospi)
{
	int words_in_fifo = RX_FIFO_WORDS(readl(&ospi->regs->spi_fifo_rx_cfg));
	return words_in_fifo >= 4;
}

static void fifo_read_word(struct spi_opv5xc *ospi)
{
	struct spi_transfer *xfer = ospi->xfer;
	u32 word;

	word = readl(&ospi->regs->spi_rx_data);
	if (xfer->rx_buf)
		U32_AT_OFFSET(xfer->rx_buf, ospi->rx_pos) = cpu_to_be32(word);

	ospi->rx_pos += 4;
}

static void raw_write_bytes(struct spi_opv5xc *ospi, int bytes)
{
	struct spi_transfer *xfer = ospi->xfer;
	u32 word;
	int i;

	if (xfer->tx_buf) {
		if (bytes == 4) {
			word = be32_to_cpu(U32_AT_OFFSET(xfer->tx_buf,
						ospi->tx_pos));
		} else {
			word = 0;
			for (i = 0; i < bytes; i++)
				word = (word << 8) | U8_AT_OFFSET(xfer->tx_buf,
						ospi->tx_pos + i);
		}
	} else
		word = 0;

	writel(word, &ospi->regs->spi_tx_data);

	ospi->tx_pos += bytes;
}

static inline bool raw_rx_available(struct spi_opv5xc *ospi)
{
	return (readl(&ospi->regs->spi_intr_stat) & SPI_RXBUF_FG) != 0;
}

static void raw_read_bytes(struct spi_opv5xc *ospi, int bytes)
{
	struct spi_transfer *xfer = ospi->xfer;
	u32 word;
	int i;

	word = readl(&ospi->regs->spi_rx_data);

	if (xfer->rx_buf) {
		if (bytes == 4) {
			U32_AT_OFFSET(xfer->rx_buf, ospi->rx_pos) =
				cpu_to_be32(word);
		} else {
			for (i = bytes - 1; i >= 0; i--) {
				U8_AT_OFFSET(xfer->rx_buf, ospi->rx_pos + i) =
					word & 0xff;
				word >>= 8;
			}
		}
	}

	ospi->rx_pos += bytes;
}

#ifdef DMA_SUPPORT

/* FIXME: spi_message.is_dma_mapped is not supported */

static int setup_sgt_for_buf(struct sg_table *sgt, void *buf,
		unsigned offset, unsigned int len, struct page *dummy)
{
	struct scatterlist *sg;
	int pages, chunk, i;
	int ret;

	if (buf) {
		buf += offset;
		pages = DIV_ROUND_UP(len + offset_in_page(buf), PAGE_SIZE);
	} else
		pages = DIV_ROUND_UP(len, PAGE_SIZE);

	memset(sgt, 0, sizeof(*sgt));	/* got crash on sg_alloc_table()'s
					   error path without this */
	ret = sg_alloc_table(sgt, pages, GFP_ATOMIC);
	if (ret)
		return ret;

	if (buf) {
		for_each_sg(sgt->sgl, sg, sgt->nents, i) {
			chunk = min_t(int, len,
					PAGE_SIZE - offset_in_page(buf));
			sg_set_page(sg, virt_to_page(buf), chunk,
					offset_in_page(buf));
			buf += chunk;
			len -= chunk;
		}
	} else {
		for_each_sg(sgt->sgl, sg, sgt->nents, i) {
			chunk = min_t(int, len, PAGE_SIZE);
			sg_set_page(sg, dummy, chunk, 0);
			len -= chunk;
		}
	}

	return 0;
}

static void dma_callback(void *data)
{
	struct spi_opv5xc *ospi = data;

	complete(&ospi->completion);
}

static int process_xfer_dma(struct spi_opv5xc *ospi, unsigned len)
{
	struct spi_transfer *xfer = ospi->xfer;
	struct sg_table sgt_tx, sgt_rx;
	struct dma_async_tx_descriptor *desc_tx, *desc_rx;
	int sglen_tx, sglen_rx, ret;
	u32 val;

	ret = setup_sgt_for_buf(&sgt_tx, (void *)xfer->tx_buf,
			ospi->tx_pos, len, ospi->page_tx);
	if (ret)
		goto sgt_tx_setup_failed;

	ret = setup_sgt_for_buf(&sgt_rx, (void *)xfer->rx_buf,
			ospi->rx_pos, len, ospi->page_rx);
	if (ret)
		goto sgt_rx_setup_failed;

	sglen_tx = dma_map_sg(ospi->ch_tx->device->dev, sgt_tx.sgl,
			sgt_tx.nents, DMA_TO_DEVICE);
	if (!sglen_tx) {
		ret = -ENOMEM;
		goto map_tx_failed;
	}

	sglen_rx = dma_map_sg(ospi->ch_rx->device->dev, sgt_rx.sgl,
			sgt_rx.nents, DMA_FROM_DEVICE);
	if (!sglen_tx) {
		ret = -ENOMEM;
		goto map_rx_failed;
	}

	desc_tx = dmaengine_prep_slave_sg(ospi->ch_tx, sgt_tx.sgl, sglen_tx,
			DMA_MEM_TO_DEV, 0);
	if (!desc_tx) {
		ret = -ENOMEM;
		goto prep_tx_failed;
	}

	desc_rx = dmaengine_prep_slave_sg(ospi->ch_rx, sgt_rx.sgl, sglen_rx,
			DMA_DEV_TO_MEM, DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
	if (!desc_rx) {
		dmaengine_terminate_all(ospi->ch_tx);
		ret = -ENOMEM;
		goto prep_rx_failed;
	}

	desc_rx->callback = dma_callback;
	desc_rx->callback_param = ospi;

	val = readl(&ospi->regs->spi_cfg);
	val |= SPI_EN | SPI_SWAP_EN | SPI_FFEN | SPI_CHAR_LEN(4);
	writel(val, &ospi->regs->spi_cfg);

	val = readl(&ospi->regs->spi_tx_ctrl);
	if (val & SPI_TXDAT_EOF) {
		val &= ~SPI_TXDAT_EOF;
		writel(val, &ospi->regs->spi_tx_ctrl);
	}

	init_completion(&ospi->completion);

	dmaengine_submit(desc_tx);
	dmaengine_submit(desc_rx);
	dma_async_issue_pending(ospi->ch_tx);
	dma_async_issue_pending(ospi->ch_rx);

	spin_unlock_irq(&ospi->lock);
	wait_for_completion(&ospi->completion);
	spin_lock_irq(&ospi->lock);

	ospi->rx_pos += len;
	ospi->tx_pos += len;
	ret = 0;

prep_rx_failed:
prep_tx_failed:
	dma_unmap_sg(ospi->ch_rx->device->dev, sgt_rx.sgl, sgt_rx.nents,
			DMA_TO_DEVICE);
map_rx_failed:
	dma_unmap_sg(ospi->ch_tx->device->dev, sgt_tx.sgl, sgt_tx.nents,
			DMA_TO_DEVICE);
map_tx_failed:
	sg_free_table(&sgt_rx);
sgt_rx_setup_failed:
	sg_free_table(&sgt_tx);
sgt_tx_setup_failed:
	return ret;
}
#endif

static void process_xfer(struct spi_opv5xc *ospi)
{
	struct spi_transfer *xfer = ospi->xfer;
	struct spi_message *msg = ospi->msg;
	struct spi_device *spi = msg->spi;
	unsigned requested_hz, actual_hz, bit_nsec, fifo_len, fifo_end;
	int words, bytes, div;
	bool use_irq;
	u32 val;
#ifdef DMA_SUPPORT
	unsigned dma_len;
	int ret;
#endif

	/* Register write order for things to operate correctly:
	 * - spi_cfg [if needed]
	 * - spi_tx_ctrl [if needed]
	 * - spi_tx_data [manually or from FIFO]
	 *
	 * To assert CS, need to clear SPI_TXDAT_EOF bit in spi_tx_ctrl
	 * To deassert CS, need to set SPI_TXDAT_EOF *before* writing last
	 * word to spi_tx_data. This means that complete handling of xfer
	 * using FIFO [this includes DMA] is not possible, unless CS is
	 * not deasserted after this transfer.
	 *
	 * At SPI subsystem interface layer, driver declares that only
	 * 8bit words are supported [which is what SPI flash requests].
	 * However, at HW communication level, driver tries to use wide words
	 * if possible. With FIFO/DMA, only 32bit words are used.
	 *
	 * FIFO progress can only be tracked per 4 words - it is threshold
	 * configuration resolution. Combined with "32bit words for FIFO"
	 * policy, this means that tail of xfer that is not 16-byte-aligned,
	 * is processed without FIFO. If xfer len is aligned but CS
	 * deassertion is needed after xfer, last 16 bytes have to be sent
	 * without FIFO.
	 *
	 * In middle of large xfer, FIFO threshold of 8 words is used.
	 * On fastest speed (50 MHz), 8 words take 5.12 usecs - which is
	 * too low for IRQ with it's overhead to be valuable. On 25 MHz
	 * and lower speeds, IRQ is used with FIFO.
	 *
	 * For FIFO-less operations, policy is the same, IRQ is used if
	 * operation duration is 10.24 usecs or more. Which means that
	 * - for 6.25 MHz and faster, IRQ is not used
	 * - for 3.125 MHz, IRQ is used for 32bit words but not for smaller
	 * - for 1.5625 MHz, IRQ is used for 16bit and larger words
	 * - for 781.250 KHz [lowest possible speed], IRQ is always used
	 */

	ospi->tx_pos = ospi->rx_pos = 0;

	/* Determine speed */

	requested_hz = xfer->speed_hz ? : spi->max_speed_hz;
	actual_hz = SPI_OPV5XC_MAX_SPEED;
	div = 0;
	while (actual_hz > SPI_OPV5XC_MIN_SPEED && actual_hz > requested_hz) {
		actual_hz /= 2;
		div++;
	}

	writel(div, &ospi->regs->spi_bitrate);

	bit_nsec = (1000000000 / actual_hz);

#ifdef DMA_SUPPORT
	if (ospi->use_dma) {

		/* in !ARCH_HAS_SG_CHAIN sg_alloc_table() has size limitation,
		 * have to split large requests here due to that.
		 *
		 * FIXME: proper fix for this should be elsewhere */

		while (xfer->len - ospi->rx_pos >= ospi->bytes_for_dma) {

			if (ospi->deassert_cs)
				dma_len = (xfer->len - ospi->rx_pos - 1) & ~3;
			else
				dma_len = (xfer->len - ospi->rx_pos) & ~3;

#ifndef ARCH_HAS_SG_CHAIN
			if (dma_len > (SG_MAX_SINGLE_ALLOC - 1) * PAGE_SIZE)
				dma_len = (SG_MAX_SINGLE_ALLOC - 1) * PAGE_SIZE;
#endif

			ret = process_xfer_dma(ospi, dma_len);
			if (ret) {
				dev_err_ratelimited(spi->master->dev.parent,
					"DMA failed, falling back to PIO\n");
				break;
			}
		}
	}
#endif

	/* Determine size of xfer to be processed via FIFO */

	if (ospi->deassert_cs)
		fifo_len = (xfer->len - ospi->rx_pos - 1) & ~15;
	else
		fifo_len = (xfer->len - ospi->rx_pos) & ~15;

	/* Process FIFO part */

	if (fifo_len) {

		use_irq = (8 * 32 * bit_nsec > NSEC_FOR_IRQ);

		val = readl(&ospi->regs->spi_cfg);
		val |= SPI_EN | SPI_FFEN | SPI_CHAR_LEN(4);
		val &= ~SPI_SWAP_EN;
		writel(val, &ospi->regs->spi_cfg);

		val = readl(&ospi->regs->spi_tx_ctrl);
		if (val & SPI_TXDAT_EOF) {
			val &= ~SPI_TXDAT_EOF;
			writel(val, &ospi->regs->spi_tx_ctrl);
		}

		if (use_irq) {
			val = readl(&ospi->regs->spi_fifo_rx_cfg);
			val &= SPI_RXFF_THRED_MASK;
			if (fifo_len == 16)
				val |= SPI_RXFF_THRED_4;
			else
				val |= SPI_RXFF_THRED_8;
			writel(val, &ospi->regs->spi_fifo_rx_cfg);
		}

		fifo_end = ospi->rx_pos + fifo_len;

		while (ospi->rx_pos < fifo_end) {

			words = fifo_tx_available_words(ospi);
			while (words && ospi->tx_pos < fifo_end) {
				fifo_write_word(ospi);
				words--;
				if (!words)
					words = fifo_tx_available_words(ospi);
			}

			if (use_irq) {
				init_completion(&ospi->completion);
				writel(SPI_RXFF_FG, &ospi->regs->spi_intr_ena);
				spin_unlock_irq(&ospi->lock);
				wait_for_completion(&ospi->completion);
				spin_lock_irq(&ospi->lock);
			} else {
				while (!fifo_rx_available(ospi)) {
					spin_unlock_irq(&ospi->lock);
					spin_lock_irq(&ospi->lock);
				}
			}

			while (fifo_rx_available(ospi)) {
				for (words = 0; words < 4; words++)
					fifo_read_word(ospi);
			}

			if (use_irq && ospi->rx_pos == fifo_end - 16) {
				val = readl(&ospi->regs->spi_fifo_rx_cfg);
				val &= SPI_RXFF_THRED_MASK;
				val |= SPI_RXFF_THRED_4;
				writel(val, &ospi->regs->spi_fifo_rx_cfg);
			}
		}
	}

	/* Process non-FIFO part */

	while (ospi->rx_pos < xfer->len) {

		bytes = min_t(int, 4, xfer->len - ospi->tx_pos);

		use_irq = (8 * bytes * bit_nsec > NSEC_FOR_IRQ);

		val = readl(&ospi->regs->spi_cfg);
		val &= ~(SPI_SWAP_EN | SPI_FFEN | SPI_CHAR_LEN_MASK);
		val |= SPI_EN | SPI_CHAR_LEN(bytes);
		writel(val, &ospi->regs->spi_cfg);

		val = readl(&ospi->regs->spi_tx_ctrl);
		if (ospi->tx_pos + bytes == xfer->len && ospi->deassert_cs)
			val |= SPI_TXDAT_EOF;
		else
			val &= ~SPI_TXDAT_EOF;
		writel(val, &ospi->regs->spi_tx_ctrl);

		raw_write_bytes(ospi, bytes);

		if (use_irq) {
			init_completion(&ospi->completion);
			writel(SPI_RXBUF_FG, &ospi->regs->spi_intr_ena);
			spin_unlock_irq(&ospi->lock);
			wait_for_completion(&ospi->completion);
			spin_lock_irq(&ospi->lock);
		} else {
			while (!raw_rx_available(ospi)) {
				spin_unlock_irq(&ospi->lock);
				spin_lock_irq(&ospi->lock);
			}
		}

		raw_read_bytes(ospi, bytes);
	}
}

static irqreturn_t spi_opv5xc_irq(int irq, void *param)
{
	struct spi_master *master = param;
	struct spi_opv5xc *ospi = spi_master_get_devdata(master);
	irqreturn_t ret;

	spin_lock(&ospi->lock);

	if (likely(ospi->xfer)) {
		writel(0, &ospi->regs->spi_intr_ena);
		complete(&ospi->completion);
		ret = IRQ_HANDLED;
	} else
		ret = IRQ_NONE;

	spin_unlock(&ospi->lock);

	return ret;
}

static int spi_opv5xc_setup(struct spi_device *spi)
{
	struct spi_opv5xc *ospi = spi_master_get_devdata(spi->master);
	u32 val, bit;

	spin_lock_irq(&ospi->lock);

	bit = 1 << (spi->chip_select + SPI_TXCH_ACTIVE_SHIFT);
	val = readl(&ospi->regs->spi_tx_ctrl);
	if (spi->mode & SPI_CS_HIGH)
		val |= bit;
	else
		val &= bit;
	writel(val, &ospi->regs->spi_tx_ctrl);

	spin_unlock_irq(&ospi->lock);

	return 0;
}

static int spi_opv5xc_transfer_one_message(struct spi_master *master,
		struct spi_message *msg)
{
	struct spi_opv5xc *ospi = spi_master_get_devdata(master);
	struct spi_device *spi = msg->spi;
	struct spi_transfer *xfer;
	bool last;
	u32 cfg, tx_ctrl;

	spin_lock_irq(&ospi->lock);

	ospi->msg = msg;

	/* It could happen that previous message requested to keep CS asserted.
	 * This can be detected by having SPI_EN active at this point.
	 *
	 * In this case, if we are talking to the same device, to not write
	 * to any registers here. If we are talking to different device,
	 * disable SPI_EN to "reset" it
	 */

	cfg = readl(&ospi->regs->spi_cfg);
	tx_ctrl = readl(&ospi->regs->spi_tx_ctrl);

	if ((cfg & SPI_EN) && SPI_TXCH_NUM(tx_ctrl) != spi->chip_select) {
		cfg &= ~SPI_EN;
		writel(cfg, &ospi->regs->spi_cfg);
	}

	if (!(cfg & SPI_EN)) {

		if (spi->mode & SPI_CPOL)
			cfg |= SPI_CLKPOL;
		else
			cfg &= ~SPI_CLKPOL;

		if (spi->mode & SPI_CPHA)
			cfg |= SPI_CLKPHA;
		else
			cfg &= ~SPI_CLKPHA;

		tx_ctrl &= ~SPI_TXCH_NUM_MASK;
		tx_ctrl |= SPI_TXCH_NUM(spi->chip_select);

		writel(cfg, &ospi->regs->spi_cfg);
		writel(tx_ctrl, &ospi->regs->spi_tx_ctrl);
	}

	list_for_each_entry(xfer, &msg->transfers, transfer_list) {

		last = (xfer == list_last_entry(&msg->transfers,
					typeof(*xfer), transfer_list));

		ospi->xfer = xfer;
		ospi->deassert_cs = ((last && !xfer->cs_change) ||
				     (!last && xfer->cs_change));
		process_xfer(ospi);
		ospi->xfer = NULL;

		msg->actual_length += xfer->len;

		if (xfer->delay_usecs)
			udelay(xfer->delay_usecs);
	}

	if (ospi->deassert_cs) {
		cfg = readl(&ospi->regs->spi_cfg);
		cfg &= ~SPI_EN;
		writel(cfg, &ospi->regs->spi_cfg);
	}

	ospi->msg = NULL;

	spin_unlock_irq(&ospi->lock);

	msg->status = 0;
	spi_finalize_current_message(master);
	return 0;
}

#ifdef DMA_SUPPORT
static ssize_t bytes_for_dma_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct spi_master *master = platform_get_drvdata(pdev);
	struct spi_opv5xc *ospi = spi_master_get_devdata(master);

	return snprintf(buf, PAGE_SIZE, "%d\n", ospi->bytes_for_dma);
}

static ssize_t bytes_for_dma_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct spi_master *master = platform_get_drvdata(pdev);
	struct spi_opv5xc *ospi = spi_master_get_devdata(master);
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	spin_lock_irq(&ospi->lock);
	ospi->bytes_for_dma = val;
	spin_unlock_irq(&ospi->lock);

	return len;
}

static DEVICE_ATTR(bytes_for_dma, S_IWUSR|S_IRUGO,
		bytes_for_dma_show, bytes_for_dma_store);

static void spi_opv5xc_setup_dma(struct platform_device *pdev,
		struct spi_opv5xc *ospi)
{
	dma_cap_mask_t mask;
	struct dma_slave_config conf;
	int ret;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	ospi->ch_tx = dma_request_channel(mask,
			dma_filter, dma_filter_param_tx);
	if (!ospi->ch_tx) {
		dev_err(&pdev->dev, "Tx DMA channel request failed\n");
		goto err_ch_tx;
	}

	ospi->ch_rx = dma_request_channel(mask,
			dma_filter, dma_filter_param_rx);
	if (!ospi->ch_rx) {
		dev_err(&pdev->dev, "Rx DMA channel request failed\n");
		goto err_ch_rx;
	}

	ospi->page_tx = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!ospi->page_tx) {
		dev_err(&pdev->dev, "Tx DMA zero page allocation failed\n");
		goto err_page_tx;
	}

	ospi->page_rx = alloc_pages(GFP_KERNEL, 0);
	if (!ospi->page_rx) {
		dev_err(&pdev->dev, "Rx DMA dummy page allocation failed\n");
		goto err_page_rx;
	}

	memset(&conf, 0, sizeof(conf));
	conf.direction = DMA_MEM_TO_DEV;
	conf.dst_addr = ospi->regs_phys +
				offsetof(struct spi_opv5xc_regs, spi_tx_data);
	conf.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	ret = dmaengine_slave_config(ospi->ch_tx, &conf);
	if (ret) {
		dev_err(&pdev->dev, "Tx DMA channel setup failed\n");
		goto err_setup_tx;
	}

	memset(&conf, 0, sizeof(conf));
	conf.direction = DMA_DEV_TO_MEM;
	conf.src_addr = ospi->regs_phys +
				offsetof(struct spi_opv5xc_regs, spi_rx_data);
	conf.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	ret = dmaengine_slave_config(ospi->ch_rx, &conf);
	if (ret) {
		dev_err(&pdev->dev, "Rx DMA channel setup failed\n");
		goto err_setup_rx;
	}

	ret = device_create_file(&pdev->dev, &dev_attr_bytes_for_dma);
	if (ret)
		dev_warn(&pdev->dev, "device attribute creation failed\n");

	ospi->use_dma = true;
	ospi->bytes_for_dma = DEFAULT_BYTES_FOR_DMA;
	dev_info(&pdev->dev, "DMA enabled\n");
	return;

err_setup_rx:
err_setup_tx:
	__free_pages(ospi->page_rx, 0);
err_page_rx:
	__free_pages(ospi->page_tx, 0);
err_page_tx:
	dma_release_channel(ospi->ch_rx);
err_ch_rx:
	dma_release_channel(ospi->ch_tx);
err_ch_tx:
	dev_info(&pdev->dev, "DMA disabled\n");
}

static void spi_opv5xc_unsetup_dma(struct platform_device *pdev,
		struct spi_opv5xc *ospi)
{
	if (ospi->use_dma) {
		device_remove_file(&pdev->dev, &dev_attr_bytes_for_dma);
		__free_pages(ospi->page_rx, 0);
		__free_pages(ospi->page_tx, 0);
		dma_release_channel(ospi->ch_rx);
		dma_release_channel(ospi->ch_tx);
	}
}
#endif

static int spi_opv5xc_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct spi_opv5xc *ospi;
	struct resource *res;
	int ret;

	master = spi_alloc_master(&pdev->dev, sizeof(*ospi));
	if (!master) {
		dev_err(&pdev->dev, "spi_master allocation failed\n");
		return -ENOMEM;
	}
	platform_set_drvdata(pdev, master);

	master->bus_num = pdev->id;
	master->num_chipselect = 4;
	master->mode_bits = SPI_OPV5XC_MODE_BITS;
	master->min_speed_hz = SPI_OPV5XC_MIN_SPEED;
	master->max_speed_hz = SPI_OPV5XC_MAX_SPEED;
	master->setup = spi_opv5xc_setup;
	master->transfer_one_message = spi_opv5xc_transfer_one_message;

	/* FIXME: current driver's data flow code assumes that byte streams
	 * are being transferred. To support bits_per_word other than 8,
	 * need to re-design data flow code */
	master->bits_per_word_mask = SPI_BPW_MASK(8);

	ospi = spi_master_get_devdata(master);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ospi->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ospi->regs)) {
		ret = PTR_ERR(ospi->regs);
		goto err_remap;
	}
#ifdef DMA_SUPPORT
	ospi->regs_phys = res->start;
#endif

	ospi->irq = platform_get_irq(pdev, 0);
	if (ospi->irq < 0) {
		dev_err(&pdev->dev, "IRQ not defined\n");
		ret = ospi->irq;
		goto err_get_irq;
	}

	ret = opv5xc_enable_peri(OPV5XC_PERI_SPI);
	if (ret < 0) {
		dev_err(&pdev->dev, "could not enable peripherial\n");
		goto err_peri;
	}

	writel(SPI_MASTER_EN, &ospi->regs->spi_cfg);
	writel(0, &ospi->regs->spi_intr_ena);

	spin_lock_init(&ospi->lock);

	ret = devm_request_irq(&pdev->dev, ospi->irq, spi_opv5xc_irq, 0,
			dev_name(&pdev->dev), master);
	if (ret < 0) {
		dev_err(&pdev->dev, "could not request IRQ\n");
		goto err_request_irq;
	}

#ifdef DMA_SUPPORT
	spi_opv5xc_setup_dma(pdev, ospi);
#endif

	ret = spi_register_master(master);
	if (ret) {
		dev_err(&pdev->dev, "could not register SPI master\n");
		goto err_register;
	}

	return 0;

err_register:
#ifdef DMA_SUPPORT
	spi_opv5xc_unsetup_dma(pdev, ospi);
#endif
err_request_irq:
	opv5xc_disable_peri(OPV5XC_PERI_SPI);
err_peri:
err_get_irq:
err_remap:
	spi_master_put(master);
	return ret;
}

static int spi_opv5xc_remove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct spi_opv5xc *ospi = spi_master_get_devdata(master);

	writel(0, &ospi->regs->spi_cfg);

#ifdef DMA_SUPPORT
	spi_opv5xc_unsetup_dma(pdev, ospi);
#endif
	spi_master_put(master);
	opv5xc_disable_peri(OPV5XC_PERI_SPI);
	return 0;
}

static struct platform_driver spi_opv5xc_driver = {
	.driver = {
		.name = "spi-opv5xc",
		.owner = THIS_MODULE,
		},
	.probe = spi_opv5xc_probe,
	.remove = spi_opv5xc_remove,
};

module_platform_driver(spi_opv5xc_driver);

MODULE_ALIAS("platform:spi-opv5xc");
MODULE_AUTHOR("Nikita Yushchenko <nyoushchenko@mvista.com>");
MODULE_DESCRIPTION("OPV5XC SPI driver");
MODULE_LICENSE("GPL");
