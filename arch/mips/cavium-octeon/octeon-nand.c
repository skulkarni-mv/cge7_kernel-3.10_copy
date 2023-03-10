/**
 * Driver for the Octeon NAND flash controller introduced in CN52XX pass 2.
 *
 * LICENSE:
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2008 - 2012 Cavium, Inc.
 */

#include <asm/octeon/cvmx.h>
#include <asm/octeon/cvmx-nand.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-bch.h>
#include <asm/octeon/cvmx-bch-defs.h>
#include <linux/ctype.h>

#include <linux/module.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/platform_device.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/mtd/nand_bch.h>
#include <linux/mtd/partitions.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <net/irda/parameters.h>


#define DRIVER_NAME "octeon-nand"

#define DEBUG_INIT		(1<<0)
#define DEBUG_READ		(1<<1)
#define DEBUG_READ_BUFFER	(1<<2)
#define DEBUG_WRITE		(1<<3)
#define DEBUG_WRITE_BUFFER	(1<<4)
#define DEBUG_CONTROL		(1<<5)
#define DEBUG_SELECT		(1<<6)
#define DEBUG_ALL		-1

#define MAX_NAND_NAME_LEN       20

static const char * const part_probes[] = { "cmdlinepart", NULL };

#define DEV_DBG(_level, _dev, _format, _arg...)	do {			\
	if (unlikely(debug & (_level)))					\
		dev_info((_dev) , "%s " _format , __func__, ## _arg);	\
	} while (0)

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug bit field. -1 will turn on all debugging.");


struct octeon_nand {
	struct mtd_info mtd;
	struct nand_chip nand;
	/* Temporary location to store read data, must be 64 bit aligned */
	uint8_t data[NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE] __aligned(8);
	uint8_t status;
	int use_status;
	int data_len;		/* Number of byte in the data buffer */
	int data_index;		/* Current read index. Equal to data_len when
					all data has been read */
	int selected_chip;	/* Currently selected NAND chip */
	int selected_page;	/* Last page chosen by SEQIN for PROGRAM */
	struct device *dev;	/* Pointer to the device */
	struct nand_ecclayout *ecclayout;
	unsigned char *eccmask;
};

enum nand_extended_section_type {
	NAND_EXTENDED_UNUSED = 0,
	NAND_EXTENDED_SECTION_TYPE = 1,
	NAND_EXTENDED_ECC = 2,
};

struct nand_extended_section_info {
	uint8_t type;
	uint8_t length;
};

struct nand_extended_ecc_info {
	uint8_t ecc_bits;       /** Number of bits ECC correctability */
	uint8_t ecc_size;       /** 1 << ecc_size */
	uint16_t max_lun_bad_blocks;    /** Max bad blocks per LUN */
	uint16_t block_endurance;
	uint16_t reserved;
};

struct nand_extended_param_page_hdr {
	uint16_t crc;
	char sig[4];    /* Should be 'EPPS' */
	uint8_t reserved0[10];
	struct nand_extended_section_info section_types[8];
};


static struct octeon_nand *octeon_nand_open_mtd[8];

static int octeon_nand_bch_correct(struct mtd_info *mtd, u_char *dat,
				   u_char *read_ecc, u_char *isnull);


/*
 * Read a single byte from the temporary buffer. Used after READID
 * to get the NAND information.
 */
static uint8_t octeon_nand_read_byte(struct mtd_info *mtd)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	if (priv->use_status) {
		DEV_DBG(DEBUG_READ, priv->dev,
			"returning status: 0x%x\n", priv->status);
		return priv->status;
	}
	if (priv->data_index < priv->data_len) {
		DEV_DBG(DEBUG_READ, priv->dev, "read of 0x%02x\n",
			0xff & priv->data[priv->data_index]);
		return priv->data[priv->data_index++];
	} else {
		dev_err(priv->dev, "No data to read\n");
		return 0xff;
	}
}

/*
 * Read two bytes from the temporary buffer. Used after READID to
 * get the NAND information on 16 bit devices.
 *
 */
static uint16_t octeon_nand_read_word(struct mtd_info *mtd)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	if (priv->use_status)
		return priv->status | (priv->status << 8);

	if (priv->data_index + 1 < priv->data_len) {
		uint16_t result = le16_to_cpup((uint16_t *)(priv->data +
			priv->data_index));
		priv->data_index += 2;
		DEV_DBG(DEBUG_READ, priv->dev, "read of 0x%04x\n",
			0xffff & result);
		return result;
	} else {
		dev_err(priv->dev, "No data to read\n");
		return 0xff;
	}
	return 0;
}

/*
 * Since we have a write page, I don't think this can ever be
 * called.
 */
static void octeon_nand_write_buf(struct mtd_info *mtd, const uint8_t *buf,
				int len)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	DEV_DBG(DEBUG_WRITE_BUFFER, priv->dev, "len=%d\n", len);
	if (len <= (sizeof(priv->data) - priv->data_len)) {
		memcpy(priv->data + priv->data_len, buf, len);
		priv->data_len += len;
		memset(priv->data + priv->data_len, 0xff,
			sizeof(priv->data) - priv->data_len);
	} else {
		dev_err(priv->dev, "Not enough data to write %d bytes\n", len);
	}
}

/*
 * Read a number of pending bytes from the temporary buffer. Used
 * to get page and OOB data.
 */
static void octeon_nand_read_buf(struct mtd_info *mtd, uint8_t *buf, int len)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	DEV_DBG(DEBUG_READ_BUFFER, priv->dev, "len=%d\n", len);

	if (len <= priv->data_len - priv->data_index) {
		memcpy(buf, priv->data + priv->data_index, len);
		priv->data_index += len;
	} else {
		dev_err(priv->dev,
			"Not enough data for read of %d bytes\n", len);
		priv->data_len = 0;
	}
}

#ifdef	__DEPRECATED_API
/*
 * Verify the supplied buffer matches the data we last read
 */
static int octeon_nand_verify_buf(struct mtd_info *mtd, const uint8_t *buf,
				int len)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	if (memcmp(buf, priv->data, len)) {
		dev_err(priv->dev, "Write verify failed\n");
		return -EFAULT;
	} else
		return 0;
}
#endif

static int octeon_nand_hw_bch_read_page(struct mtd_info *mtd,
					struct nand_chip *chip, uint8_t *buf,
					int oob_required, int page)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);
	int i, eccsize = chip->ecc.size;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	uint8_t *p;
	uint8_t *ecc_code = chip->buffers->ecccode;
	uint32_t *eccpos = chip->ecc.layout->eccpos;

	DEV_DBG(DEBUG_READ, priv->dev, "%s(%p, %p, %p, %d, %d)\n", __func__,
		mtd, chip, buf, oob_required, page);

	/* chip->read_buf() insists on sequential order, we do OOB first */
	memcpy(chip->oob_poi, priv->data + mtd->writesize, mtd->oobsize);

	/* Use private->data buffer as input for ECC correction */
	p = priv->data;

	for (i = 0; i < chip->ecc.total; i++)
		ecc_code[i] = chip->oob_poi[eccpos[i]];

	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int stat;

		DEV_DBG(DEBUG_READ, priv->dev,
			"Correcting block offset %ld, ecc offset %d\n",
			p - buf, i);
		stat = chip->ecc.correct(mtd, p, &ecc_code[i], NULL);

		if (stat < 0) {
			mtd->ecc_stats.failed++;
			DEV_DBG(DEBUG_ALL, priv->dev,
				"Cannot correct NAND page %d\n", page);
		} else {
			mtd->ecc_stats.corrected += stat;
		}
	}

	/* Copy corrected data to caller's buffer now */
	memcpy(buf, priv->data, mtd->writesize);

	return 0;
}

static int octeon_nand_hw_bch_write_page(struct mtd_info *mtd,
					 struct nand_chip *chip,
					 const uint8_t *buf, int oob_required, int page)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);
	int i, eccsize = chip->ecc.size;
	int eccbytes = chip->ecc.bytes;
	int eccsteps = chip->ecc.steps;
	const uint8_t *p;
	uint32_t *eccpos = chip->ecc.layout->eccpos;
	uint8_t *ecc_calc = chip->buffers->ecccalc;

	DEV_DBG(DEBUG_WRITE, priv->dev, "%s(%p, %p, %p, %d)\n", __func__, mtd,
		chip, buf, oob_required);
	for (i = 0; i < chip->ecc.total; i++)
		ecc_calc[i] = 0xFF;

	/* Copy the page data from caller's buffers to private buffer */
	chip->write_buf(mtd, buf, mtd->writesize);
	/* Use private date as source for ECC calculation */
	p = priv->data;

	/* Hardware ECC calculation */
	for (i = 0; eccsteps; eccsteps--, i += eccbytes, p += eccsize) {
		int ret;

		ret = chip->ecc.calculate(mtd, p, &ecc_calc[i]);

		if (ret < 0)
			DEV_DBG(DEBUG_WRITE, priv->dev,
				"calculate(mtd, p, &ecc_calc[i]) returned %d\n",
				ret);

		DEV_DBG(DEBUG_WRITE, priv->dev,
			"block offset %ld, ecc offset %d\n", p - buf, i);
	}

	for (i = 0; i < chip->ecc.total; i++)
		chip->oob_poi[eccpos[i]] = ecc_calc[i];

	/* Store resulting OOB into private buffer, will be sent to HW */
	chip->write_buf(mtd, chip->oob_poi, mtd->oobsize);

	return 0;
}

/**
 * nand_write_page_raw - [INTERN] raw page write function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @buf: data buffer
 * @oob_required: must write chip->oob_poi to OOB
 *
 * Not for syndrome calculating ECC controllers, which use a special oob layout.
 */
static int octeon_nand_write_page_raw(struct mtd_info *mtd,
				      struct nand_chip *chip,
				      const uint8_t *buf, int oob_required, int page)
{
	chip->write_buf(mtd, buf, mtd->writesize);
	if (oob_required)
		chip->write_buf(mtd, chip->oob_poi, mtd->oobsize);

	return 0;
}

/**
 * octeon_nand_write_oob_std - [REPLACEABLE] the most common OOB data write
 *                             function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @page: page number to write
 */
static int octeon_nand_write_oob_std(struct mtd_info *mtd,
				     struct nand_chip *chip,
				     int page)
{
	int status = 0;
	const uint8_t *buf = chip->oob_poi;
	int length = mtd->oobsize;

	chip->cmdfunc(mtd, NAND_CMD_SEQIN, mtd->writesize, page);
	chip->write_buf(mtd, buf, length);
	/* Send command to program the OOB data */
	chip->cmdfunc(mtd, NAND_CMD_PAGEPROG, -1, -1);

	status = chip->waitfunc(mtd, chip);

	return status & NAND_STATUS_FAIL ? -EIO : 0;
}

/**
 * octeon_nand_read_page_raw - [INTERN] read raw page data without ecc
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @buf: buffer to store read data
 * @oob_required: caller requires OOB data read to chip->oob_poi
 * @page: page number to read
 *
 * Not for syndrome calculating ECC controllers, which use a special oob layout.
 */
static int octeon_nand_read_page_raw(struct mtd_info *mtd,
				     struct nand_chip *chip,
				     uint8_t *buf, int oob_required, int page)
{
	chip->read_buf(mtd, buf, mtd->writesize);
	if (oob_required)
		chip->read_buf(mtd, chip->oob_poi, mtd->oobsize);
	return 0;
}

/**
 * octeon_nand_read_oob_std - [REPLACEABLE] the most common OOB data read function
 * @mtd: mtd info structure
 * @chip: nand chip info structure
 * @page: page number to read
 */
static int octeon_nand_read_oob_std(struct mtd_info *mtd,
				    struct nand_chip *chip,
				    int page)

{
	chip->cmdfunc(mtd, NAND_CMD_READOOB, 0, page);
	chip->read_buf(mtd, chip->oob_poi, mtd->oobsize);
	return 0;
}

/*
 * Select which NAND chip we are working on. A chip of -1
 * represents that no chip should be selected.
 */
static void octeon_nand_select_chip(struct mtd_info *mtd, int chip)
{
	/* We don't need to do anything here */
}

/*
 * Issue a NAND command to the chip. Almost all work is done here.
 */
static void octeon_nand_cmdfunc(struct mtd_info *mtd, unsigned command,
				int column, int page_addr)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);
	struct nand_chip *nand = &priv->nand;
	int status;

	down(&octeon_bootbus_sem);
	priv->use_status = 0;

	switch (command) {
	case NAND_CMD_READID:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "READID\n");
		priv->data_index = 0;
		/*
		 * Read length must be a multiple of 8, so read a
		 * little more than we require.
		 */
		priv->data_len = cvmx_nand_read_id(priv->selected_chip, (uint64_t)column,
						virt_to_phys(priv->data), 16);
		if (priv->data_len < 16) {
			dev_err(priv->dev, "READID failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_READOOB:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"READOOB page_addr=0x%x\n", page_addr);
		priv->data_index = 8;
		/*
		 * Read length must be a multiple of 8, so we start
		 * reading 8 bytes from the end of page.
		 */
		priv->data_len = cvmx_nand_page_read(priv->selected_chip,
					((uint64_t)page_addr << nand->page_shift) +
					(1 << nand->page_shift) -
					priv->data_index,
					virt_to_phys(priv->data),
					mtd->oobsize + priv->data_index);
		if (priv->data_len < mtd->oobsize + priv->data_index) {
			dev_err(priv->dev, "READOOB failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_READ0:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"READ0 page_addr=0x%x\n", page_addr);
		priv->data_index = 0;
		/* Here mtd->oobsize _must_ already be a multiple of 8 */
		priv->data_len = cvmx_nand_page_read(priv->selected_chip,
					column +
					((uint64_t)page_addr << nand->page_shift),
					virt_to_phys(priv->data),
					(1 << nand->page_shift) +
					mtd->oobsize);
		if (priv->data_len < (1 << nand->page_shift) + mtd->oobsize) {
			dev_err(priv->dev, "READ0 failed with %d\n",
				priv->data_len);
			priv->data_len = 0;
		}
		break;

	case NAND_CMD_ERASE1:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"ERASE1 page_addr=0x%x\n", page_addr);
		if (cvmx_nand_block_erase(priv->selected_chip,
			(uint64_t)page_addr << nand->page_shift)) {
			dev_err(priv->dev, "ERASE1 failed\n");
		}
		break;

	case NAND_CMD_ERASE2:
		/* We do all erase processing in the first command, so ignore
			this one */
		break;

	case NAND_CMD_STATUS:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "STATUS\n");
		priv->status = cvmx_nand_get_status(priv->selected_chip);
		priv->use_status = 1;

		break;

	case NAND_CMD_SEQIN:
		DEV_DBG(DEBUG_CONTROL, priv->dev,
			"SEQIN column=%d page_addr=0x%x\n", column, page_addr);
		/* If we don't seem to be doing sequential writes then erase
			all data assuming it is old */
		/* FIXME: if (priv->selected_page != page_addr) */
		if (priv->data_index != column)
			memset(priv->data, 0xff, sizeof(priv->data));
		priv->data_index = column;
		priv->data_len = column;
		priv->selected_page = page_addr;
		break;

	case NAND_CMD_PAGEPROG:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "PAGEPROG\n");
		status = cvmx_nand_page_write(priv->selected_chip,
			(uint64_t)priv->selected_page << nand->page_shift,
			virt_to_phys(priv->data));
		if (status)
			dev_err(priv->dev, "PAGEPROG failed with %d\n",	status);
		break;

	case NAND_CMD_RESET:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "RESET\n");
		priv->data_index = 0;
		priv->data_len = 0;
		memset(priv->data, 0xff, sizeof(priv->data));
		status = cvmx_nand_reset(priv->selected_chip);
		if (status)
			dev_err(priv->dev, "RESET failed with %d\n", status);
		break;

	case NAND_CMD_RNDOUT:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "RNDOUT\n");
		priv->data_index = column;
		break;

	case NAND_CMD_PARAM:
		DEV_DBG(DEBUG_CONTROL, priv->dev, "PARAM\n");
		priv->data_len = cvmx_nand_read_param_page(priv->selected_chip,
					virt_to_phys(priv->data), 2048);
		priv->data_index = column;
		break;

	default:
		dev_err(priv->dev, "Unsupported command 0x%x\n", command);
		break;
	}
	up(&octeon_bootbus_sem);
}

/*
 * Given a page, calculate the ECC code
 *
 * chip:	Pointer to NAND chip data structure
 * buf:		Buffer to calculate ECC on
 * code:	Buffer to hold ECC data
 *
 * Return 0 on success or -1 on failure
 */
static int octeon_nand_bch_calculate_ecc_internal(struct octeon_nand *priv,
						  const uint8_t *buf,
						  uint8_t *code)
{
	struct nand_chip *nand_chip = &priv->nand;
	static cvmx_bch_response_t response;
	int rc;
	int i;
	static uint8_t *ecc_buffer;

	/* Can only use logical or xkphys pointers */
	WARN_ON(is_vmalloc_or_module_addr(buf));
	WARN_ON(is_vmalloc_or_module_addr(code));

	if (!ecc_buffer)
		ecc_buffer = kmalloc(1024, GFP_KERNEL);
	if ((ulong)buf % 8)
		dev_err(priv->dev, "ECC buffer not aligned!");

	memset(ecc_buffer, 0, nand_chip->ecc.bytes);

	response.u16 = 0;
	barrier();

	rc = cvmx_bch_encode((void *)buf, nand_chip->ecc.size,
			     nand_chip->ecc.strength,
			     (void *)ecc_buffer, &response);

	if (rc) {
		dev_err(priv->dev, "octeon_bch_encode failed\n");
		return -1;
	}

	udelay(10);
	barrier();

	if (!response.s.done) {
		dev_err(priv->dev,
			"octeon_bch_encode timed out, response done: %d, "
			 "uncorrectable: %d, num_errors: %d, erased: %d\n",
			response.s.done, response.s.uncorrectable,
			response.s.num_errors, response.s.erased);
		cvmx_bch_shutdown();
		cvmx_bch_initialize();
		return -1;
	}

	memcpy(code, ecc_buffer, nand_chip->ecc.bytes);

	for (i = 0; i < nand_chip->ecc.bytes; i++)
		code[i] ^= priv->eccmask[i];

	return 0;
}

/*
 * Given a page, calculate the ECC code
 *
 * mtd:        MTD block structure
 * dat:        raw data (unused)
 * ecc_code:   buffer for ECC
 */
static int octeon_nand_bch_calculate(struct mtd_info *mtd,
		const uint8_t *dat, uint8_t *ecc_code)
{
	int ret;
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	ret = octeon_nand_bch_calculate_ecc_internal(
					priv, (void *)dat, (void *)ecc_code);

	return ret;
}
/*
 * Detect and correct multi-bit ECC for a page
 *
 * mtd:        MTD block structure
 * dat:        raw data read from the chip
 * read_ecc:   ECC from the chip (unused)
 * isnull:     unused
 *
 * Returns number of bits corrected or -1 if unrecoverable
 */
static int octeon_nand_bch_correct(struct mtd_info *mtd, u_char *dat,
		u_char *read_ecc, u_char *isnull)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);
	struct nand_chip *nand_chip = &priv->nand;
	static cvmx_bch_response_t response;
	int rc;
	int i = nand_chip->ecc.size + nand_chip->ecc.bytes;
	static uint8_t *data_buffer;
	static int buffer_size;
	int max_time = 100;

	/* Can only use logical or xkphys pointers */
	WARN_ON(is_vmalloc_or_module_addr(dat));

	if (i > buffer_size) {
		kfree(data_buffer);
		data_buffer = kmalloc(i, GFP_KERNEL);
		if (!data_buffer) {
			dev_err(priv->dev,
				"%s: Could not allocate %d bytes for buffer\n",
				__func__, i);
			goto error;
		}
	}

	memcpy(data_buffer, dat, nand_chip->ecc.size);
	memcpy(data_buffer + nand_chip->ecc.size, read_ecc,
							nand_chip->ecc.bytes);

	for (i = 0; i < nand_chip->ecc.bytes; i++)
		data_buffer[nand_chip->ecc.size + i] ^= priv->eccmask[i];

	response.u16 = 0;
	barrier();

	rc = cvmx_bch_decode(data_buffer, nand_chip->ecc.size,
			     nand_chip->ecc.strength, dat, &response);

	if (rc) {
		dev_err(priv->dev, "cvmx_bch_decode failed\n");
		goto error;
	}

	/* Wait for BCH engine to finsish */
	while (!response.s.done && max_time--) {
		udelay(1);
		barrier();
	}

	if (!response.s.done) {
		dev_err(priv->dev, "Error: BCH engine timeout\n");
		cvmx_bch_shutdown();
		cvmx_bch_initialize();
		goto error;
	}

	if (response.s.erased) {
		DEV_DBG(DEBUG_ALL, priv->dev, "Info: BCH block is erased\n");
		return 0;
	}

	if (response.s.uncorrectable) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"Cannot correct NAND block, response: 0x%x\n",
			response.u16);
		goto error;
	}

	return response.s.num_errors;

error:
	DEV_DBG(DEBUG_ALL, priv->dev, "Error performing bch correction\n");
	return -1;
}

void octeon_nand_bch_hwctl(struct mtd_info *mtd, int mode)
{
	/* Do nothing. */
}

/**
 * Calculates the ONFI CRC16 needed for the extended parameter page
 *
 * @param crc	starting CRC value
 * @param p	pointer to data to calculate CRC over
 * @param len	length in bytes
 *
 * @return crc result
 */
static uint16_t octeon_onfi_crc16(uint16_t crc, uint8_t const *p, size_t len)
{
	int i;
	while (len--) {
		crc ^= *p++ << 8;
		for (i = 0; i < 8; i++)
			crc = (crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0);
	}

	return crc;
}

/**
 * Given an extended parameter page, calculate the size of the data structure.
 * The size is variable and is made up based on whatever data is placed in it.
 *
 * @param hdr	pointer to extended parameter page header
 *
 * @return length of extended parameter block or -1 if error.
 *
 * NOTE: This function does not verify the CRC, only the signature.
 */
static int calc_ext_param_page_size(struct nand_extended_param_page_hdr *hdr)
{
	int i;
	int length = 0;
	int ext_table_offset = 0;
	int ext_table_size = 0;
	struct nand_extended_section_info *ext_table;

	if (hdr->sig[0] != 'E' ||
	    hdr->sig[1] != 'P' ||
	    hdr->sig[2] != 'P' ||
	    hdr->sig[3] != 'S')
		return -1;

	for (i = 0; i < 8; i++) {
		if (hdr->section_types[i].type == NAND_EXTENDED_UNUSED)
			goto done;
		if (hdr->section_types[i].length > 0)
			length += 16 * hdr->section_types[i].length;
		if (hdr->section_types[i].type == NAND_EXTENDED_SECTION_TYPE) {
			ext_table_offset = length + sizeof(*hdr);
			ext_table_size = 8 * hdr->section_types[i].length;
		}
	}
	if (ext_table_offset != 0) {
		ext_table = (struct nand_extended_section_info *)
			((uint8_t *)hdr + ext_table_offset);
		for (i = 0; i < ext_table_size; i++) {
			if (ext_table[i].type == NAND_EXTENDED_UNUSED)
				goto done;
			length += ext_table[i].length;
		}
	}
done:
	return length + sizeof(struct nand_extended_param_page_hdr);
}

/**
 * Given a pointer to a NAND extended parameter page, return a pointer to the
 * next extended parameter page even if the current block is corrupt.
 */
struct nand_extended_param_page_hdr *
calc_next_ext_page(struct nand_extended_param_page_hdr *hdr, int *offset)
{
	uint8_t *ptr = (uint8_t *)(hdr + 1);
	*offset += sizeof(*hdr);
	while (*offset < 1024 - sizeof(*hdr)) {
		hdr = (struct nand_extended_param_page_hdr *)ptr;
		if (hdr->sig[0] == 'E' &&
		    hdr->sig[1] == 'P' &&
		    hdr->sig[2] == 'P' &&
		    hdr->sig[3] == 'S')
			return hdr;
		*offset += 8;
		ptr += 8;
	}
	return NULL;
}

/**
 * Reads the extended parameter page looking for ECC data
 *
 * @param chip - NAND chip data structure
 *
 * @returns 0 for success, -1 if invalid or unavailable extended parameter page
 */
static int octeon_read_extended_parameters(struct octeon_nand *priv)
{
	struct nand_extended_param_page_hdr *hdr;
	struct nand_extended_ecc_info *ecc_info;
	int size;
	int i;
	int offset;

	down(&octeon_bootbus_sem);
	if (cvmx_nand_read_param_page(priv->selected_chip,
			      cvmx_ptr_to_phys(priv->data), 1024) != 1024) {
		dev_err(priv->dev,
			"Could not read extended parameters from NAND chip %d\n",
			priv->selected_chip);
		up(&octeon_bootbus_sem);
		return -1;
	}
	up(&octeon_bootbus_sem);

	offset = 768;
	hdr = (struct nand_extended_param_page_hdr *)&priv->data[offset];

	/* Look for a valid header */
	do {
		size = calc_ext_param_page_size(hdr);
		if (size < sizeof(*hdr))
			continue;

		if (octeon_onfi_crc16(ONFI_CRC_BASE,
			(uint8_t *)hdr->sig, size - 2) == le16_to_cpu(hdr->crc))
			break;
		hdr = calc_next_ext_page(hdr, &offset);
	} while (hdr);

	DEV_DBG(DEBUG_ALL, priv->dev,
		"Found valid extended parameter page at offset %d\n", offset);

	/* Since the types are always in order then section type 2 for
	 * extended ECC information must be within the first two entries.
	 */
	offset = 0;
	for (i = 0; i < 2; i++) {
		if (hdr->section_types[i].type == NAND_EXTENDED_ECC)
			break;
		if (hdr->section_types[i].type == NAND_EXTENDED_UNUSED) {
			dev_err(priv->dev,
				"%s: No ECC section found\n", __func__);
			return 0;
		}

		offset += hdr->section_types[i].length * 16;
	}

	ecc_info = (struct nand_extended_ecc_info *)
					(((uint8_t *)(hdr + 1)) + offset);

	DEV_DBG(DEBUG_ALL, priv->dev,
		"Found extended ecc header at offset %d in header\n", offset);
	priv->nand.ecc.strength = ecc_info->ecc_bits;
	priv->nand.ecc.size = 1 << ecc_info->ecc_size;
	if (priv->nand.ecc.strength < 0 || priv->nand.ecc.size > 2048) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"NAND ecc size of %d or strength %d not supported\n",
			ecc_info->ecc_bits, priv->nand.ecc.size);
		return -1;
	}
	DEV_DBG(DEBUG_ALL, priv->dev, "%s: ecc strength: %d, ecc size: %d\n",
		__func__, priv->nand.ecc.strength, priv->nand.ecc.size);

	return 0;
}

static int octeon_nand_scan_onfi(struct octeon_nand *priv)
{
	cvmx_nand_onfi_param_page_t *onfi_params;
	static const uint8_t revision_decode[17] = {
		0, 0, 10, 20, 21, 22, 23, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0 };

	down(&octeon_bootbus_sem);
	if (cvmx_nand_read_id(priv->selected_chip, 0x20,
			      cvmx_ptr_to_phys(priv->data), 8) < 8) {
		dev_err(priv->dev, "ONFI detection failed for chip %d\n",
				priv->selected_chip);
		up(&octeon_bootbus_sem);
		return -1;
	}

	if (priv->data[0] != 'O' ||
	    priv->data[1] != 'N' ||
	    priv->data[2] != 'F' ||
	    priv->data[3] != 'I') {
		dev_err(priv->dev, "ONFI not supported for chip %d\n",
			priv->selected_chip);
		dev_err(priv->dev, "Parameter header: %02x %02x %02x %02x\n",
			priv->data[0], priv->data[1], priv->data[2],
			priv->data[3]);
		goto out;
	}
	if (cvmx_nand_read_param_page(priv->selected_chip,
				      cvmx_ptr_to_phys(priv->data),
				      256 * 3) < 256 * 3) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"%s: Error reading ONFI parameter data for chip %d\n",
		       __func__, priv->selected_chip);
		goto out;
	}

	onfi_params =
		cvmx_nand_onfi_process(
			(cvmx_nand_onfi_param_page_t *)priv->data);
	if (!onfi_params) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"%s: Invalid ONFI parameter data for chip %d\n",
			__func__, priv->selected_chip);
		goto out;
	}

	up(&octeon_bootbus_sem);

	memcpy(&priv->nand.onfi_params, onfi_params,
	       sizeof(struct nand_onfi_params));

	priv->nand.onfi_version =
		revision_decode[
			fls(le16_to_cpu(priv->nand.onfi_params.revision))];
	DEV_DBG(DEBUG_ALL, priv->dev,
		"ONFI revision %d\n", priv->nand.onfi_version);

	priv->nand.page_shift =
		fls(le32_to_cpu(priv->nand.onfi_params.byte_per_page)) - 1;
	priv->nand.ecc.strength = priv->nand.onfi_params.ecc_bits;

	if (priv->nand.onfi_params.programs_per_page <= 1)
		priv->nand.options |= NAND_NO_SUBPAGE_WRITE;

	if (priv->nand.onfi_params.ecc_bits == 0) {
		priv->nand.ecc.mode = NAND_ECC_NONE;
		priv->nand.ecc.bytes = 0;
		priv->nand.ecc.strength = 0;
	} else if (priv->nand.onfi_params.ecc_bits == 1) {
		priv->nand.ecc.mode = NAND_ECC_SOFT;
		priv->nand.ecc.bytes = 3;
		priv->nand.ecc.size = 256;
		priv->nand.ecc.strength = 1;
		DEV_DBG(DEBUG_ALL, priv->dev,
			"NAND chip %d using single bit ECC\n",
		      priv->selected_chip);
	} else if (octeon_has_feature(OCTEON_FEATURE_BCH)) {
		DEV_DBG(DEBUG_ALL, priv->dev,
			"Using hardware ECC syndrome support\n");
		priv->nand.ecc.mode = NAND_ECC_HW_SYNDROME;
		priv->nand.ecc.strength = priv->nand.onfi_params.ecc_bits;
		priv->nand.ecc.read_page = octeon_nand_hw_bch_read_page;
		priv->nand.ecc.write_page = octeon_nand_hw_bch_write_page;
		priv->nand.ecc.read_page_raw = octeon_nand_read_page_raw;
		priv->nand.ecc.write_page_raw = octeon_nand_write_page_raw;
		priv->nand.ecc.read_oob = octeon_nand_read_oob_std;
		priv->nand.ecc.write_oob = octeon_nand_write_oob_std;
		if (priv->nand.onfi_params.ecc_bits == 0xff) {
			/* If 0xff then we need to access the extended parameter
			 * page.
			 */
			if (octeon_read_extended_parameters(priv))
				return -1;
		} else {
			priv->nand.ecc.size = 512;
		}

		{
		/*
		 * nand.ecc.strength will be used as ecc_level so
		 * it should be in {4, 8, 16, 24, 32, 40, 48, 56, 60, 64}
		 * needed ecc_bytes for m=15 (hardcoded in NAND controller)
		 */
		int ecc_lvls[]  = {4, 8, 16, 24, 32, 40, 48, 56, 60, 64};
		/* for our NAND (4k page, 24bits/1024bytes corrected) and
		 * NAND controller (hardcoded with m=15) ecc_totalbytes
		 * per above ecc_lvls {4,8, 16...64} are
		 */
		int ecc_bytes[] = {8, 15, 30, 45, 60, 75, 90, 105, 113, 120};
		int ecc_totalbytes[] = {
			32, 60, 120, 180, 240, 300, 360, 420, 452, 480};
		/* first set the desired ecc_level to match ecc_lvls[] */
		int index = /* 0..9 */
			(priv->nand.ecc.strength >= 64) ? 9/*64*/ :
			(priv->nand.ecc.strength > 56 &&
				priv->nand.ecc.strength <= 60) ? 8/*60*/ :
			(priv->nand.ecc.strength > 48 &&
				priv->nand.ecc.strength <= 56) ? 7/*56*/ :
			(priv->nand.ecc.strength > 40 &&
				priv->nand.ecc.strength <= 48) ? 6/*48*/ :
			(priv->nand.ecc.strength > 32 &&
				priv->nand.ecc.strength <= 40) ? 5/*40*/ :
			(priv->nand.ecc.strength > 48 &&
				priv->nand.ecc.strength <= 32) ? 4/*32*/ :
			(priv->nand.ecc.strength > 16 &&
				priv->nand.ecc.strength <= 24) ? 3/*24*/ :
			(priv->nand.ecc.strength >  8 &&
				priv->nand.ecc.strength <= 16) ? 2/*16*/ :
			(priv->nand.ecc.strength >  4 &&
				priv->nand.ecc.strength <=  8) ? 1/*8*/ :
			(priv->nand.ecc.strength >  1 &&
				priv->nand.ecc.strength <=  4) ? 0/*4*/: 0;
		/*
		 * ..then check if there is enough space in OOB to store
		 * ECC bytes and eventualy (if not) change ecc.strenght
		 * the the best possible value
		 */
		if (ecc_totalbytes[index] <=
			cvmx_nand_get_oob_size(priv->selected_chip) - 2) {
			priv->nand.ecc.strength = ecc_lvls[index];
			priv->nand.ecc.bytes = ecc_bytes[index];
		} else {
			int i = 9;
			while (ecc_totalbytes[i] >
				cvmx_nand_get_oob_size(priv->selected_chip))
				i--;
			priv->nand.ecc.strength = ecc_lvls[i];
			priv->nand.ecc.bytes = ecc_bytes[i];
		}

		/*
		 * strength=24 needs total of ecc.bytes=180 for 4k page
		 * strength=32 needs total of ecc.bytes=240 for 4k page
		 * Our NAND has only 224 bytes OOB so we should use max
		 * ecc.strength=24 ,ecc.bytes=45 and ecc_totalbytes=180
		 */
		}

		/* The number of ECC bits required is m * t
		 * where (2^m) - 1 > bits per ecc block and
		 * t is the number of correctible bits.  So if
		 * a block is 512 bytes and 4 bits of ECC are
		 * to be supported then m = 13 since
		 * (2^13) - 1 > (512 * 8).  This requires a
		 * total of 52 bits.  Rounding up this is 7
		 * bytes.
		 *
		 * OCTEON is hard coded for m=15.
		 * OCTEON requires ((15 * t) + 7) / 8
		 */
		priv->nand.ecc.bytes = ((15 * priv->nand.ecc.strength) + 7) / 8;

		priv->nand.ecc.steps = (1 << priv->nand.page_shift) /
							priv->nand.ecc.size;
		priv->nand.ecc.calculate = octeon_nand_bch_calculate;
		priv->nand.ecc.correct = octeon_nand_bch_correct;
		priv->nand.ecc.hwctl = octeon_nand_bch_hwctl;
		DEV_DBG(DEBUG_INIT, priv->dev,
			"NAND chip %d using hw_bch ECC for %d bits of "
			"correction per %d byte block.  ECC size is %d bytes\n",
		      priv->selected_chip,
		      priv->nand.ecc.strength,
		      priv->nand.ecc.size,
		      priv->nand.ecc.bytes);
	} else {
		priv->nand.ecc.mode = NAND_ECC_SOFT_BCH;
		priv->nand.ecc.strength = priv->nand.onfi_params.ecc_bits;
		if (priv->nand.onfi_params.ecc_bits == 0xff) {
			/* If 0xff then we need to access the extended parameter
			 * page.
			 */
			if (octeon_read_extended_parameters(priv)) {
				DEV_DBG(DEBUG_INIT, priv->dev,
					"%s: Error reading ONFI extended "
					"parameter data for chip %d\n",
				       __func__, priv->selected_chip);
				return -1;
			}
		} else {
			priv->nand.ecc.size = 512;
		}

		/* The number of ECC bits required is m * t
		 * where (2^m) - 1 > bits per ecc block and
		 * t is the number of correctible bits.  So if
		 * a block is 512 bytes and 4 bits of ECC are
		 * to be supported then m = 13 since
		 * (2^13) - 1 > (512 * 8).  This requires a
		 * total of 52 bits.  Rounding up this is 7
		 * bytes.
		 */
		priv->nand.ecc.bytes = (((fls(priv->nand.ecc.size) - 1 + 3 + 1)
					* priv->nand.ecc.strength) + 7) / 8;
		priv->nand.ecc.steps = (1 << priv->nand.page_shift) /
							priv->nand.ecc.size;
		DEV_DBG(DEBUG_INIT, priv->dev,
			"NAND chip %d using soft_bch ECC for %d bits of "
			"correction per %d byte block.  ECC size is %d bytes\n",
		      priv->selected_chip,
		      priv->nand.ecc.strength,
		      priv->nand.ecc.size,
		      priv->nand.ecc.bytes);
	}
	return 0;
out:
	up(&octeon_bootbus_sem);
	return -1;
}

/**
 * Calculate the ECC OOC layout
 *
 * @param chip	Chip to calculate layout for
 *
 * @return 0 for success, otherwise failure
 */
static int octeon_nand_calc_ecc_layout(struct octeon_nand *priv)
{
	struct nand_chip *chip = &priv->nand;
	struct nand_ecclayout *layout = priv->nand.ecc.layout;
	int oobsize;
	int i;
	int layout_alloc = 0;

	down(&octeon_bootbus_sem);
	oobsize = cvmx_nand_get_oob_size(priv->selected_chip);
	up(&octeon_bootbus_sem);

	if (!layout) {
		layout = kmalloc(sizeof(*layout), GFP_KERNEL);
		if (!layout) {
			dev_err(priv->dev, "%s: Out of memory\n", __func__);
			return -1;
		}
		chip->ecc.layout = layout;
		layout_alloc = 1;
	}
	memset(layout, 0, sizeof(*layout));
	layout->eccbytes = chip->ecc.steps * chip->ecc.bytes;
	/* Reserve 2 bytes for bad block marker */
	if (layout->eccbytes + 2 > oobsize) {
		DEV_DBG(DEBUG_INIT, priv->dev,
		"no suitable oob scheme available for oobsize %d eccbytes %u\n",
		oobsize, layout->eccbytes);
		goto fail;
	}
	/* put ecc bytes at oob tail */
	for (i = 0; i < layout->eccbytes; i++)
		layout->eccpos[i] = oobsize - layout->eccbytes + i;

	layout->oobfree[0].offset = 2;
	layout->oobfree[0].length = oobsize - 2 - layout->eccbytes;
	chip->ecc.layout = layout;
	priv->ecclayout = layout;

	DEV_DBG(DEBUG_INIT, priv->dev,
		"  layout eccbytes: %d, free offset: %d, free length: %d\n",
		layout->eccbytes, layout->oobfree[0].offset,
		layout->oobfree[0].length);

	return 0;

fail:
	if (layout_alloc)
		kfree(layout);

	return -1;
}

static int octeon_nand_hw_bch_init(struct octeon_nand *priv)
{
	struct nand_chip *chip = &priv->nand;
	int i, rc;
	unsigned char *erased_page = NULL;
	unsigned int eccsize = chip->ecc.size;
	unsigned int eccbytes = chip->ecc.bytes;
	uint8_t erased_ecc[eccbytes];

	/* Without HW BCH, the ECC callbacks would have not been installed */
	if (priv->nand.ecc.mode != NAND_ECC_HW_SYNDROME)
		return 0;

	priv->eccmask = NULL;

	if (octeon_nand_calc_ecc_layout(priv)) {
		dev_err(priv->dev, "Error calculating ECC layout\n");
		return -1;
	}

	rc = cvmx_bch_initialize();
	if (rc) {
		dev_err(priv->dev, "Error initializing BCH subsystem\n");
		goto fail;
	}

	priv->eccmask = kmalloc(eccbytes, GFP_KERNEL);
	if (!priv->eccmask) {
		dev_err(priv->dev, "eccmask: Out of memory\n");
		goto fail;
	}

	erased_page = kmalloc(eccsize, GFP_KERNEL);
	if (!erased_page) {
		dev_err(priv->dev, "erased_page: Out of memory\n");
		goto fail;
	}

	memset(erased_page, 0xff, eccsize);
	memset(priv->eccmask, 0, eccbytes);
	memset(erased_ecc, 0, eccbytes);

	if (octeon_nand_bch_calculate_ecc_internal(
		priv, erased_page, erased_ecc))
		goto fail;

	kfree(erased_page);

	for (i = 0; i < eccbytes; i++)
		priv->eccmask[i] = erased_ecc[i] ^ 0xff;

	return 0;

fail:
	kfree(priv->eccmask);
	priv->eccmask = NULL;

	kfree(erased_page);

	if (rc)
		cvmx_bch_shutdown();

	return -1;
}

/**
 * Get the size of oobsize, writesize and erasesize
 *
 * @param mtd	MTD data structure pointer
 * @param chip	NAND chip data structure pointer
 * @param id_data	Not used.
 *
 * @return	0 for success.
 */
static int octeon_nand_init_size(struct mtd_info *mtd, struct nand_chip *chip,
				 u8 *id_data)
{
	struct octeon_nand *priv = container_of(mtd, struct octeon_nand, mtd);

	down(&octeon_bootbus_sem);
	mtd->oobsize = cvmx_nand_get_oob_size(priv->selected_chip);
	mtd->writesize = cvmx_nand_get_page_size(priv->selected_chip);
	mtd->erasesize = cvmx_nand_get_pages_per_block(priv->selected_chip)
							* mtd->writesize;
	up(&octeon_bootbus_sem);
	pr_info("NAND %d OOB size: %d, write size: %d, erase size: %d\n",
		priv->selected_chip, mtd->oobsize, mtd->writesize,
		mtd->erasesize);
	/* OCTEON only supports 8-bit width */
	return 0;
}


/*
 * Determine what NAND devices are available
 */
static int octeon_nand_probe(struct platform_device *pdev)
{
	struct octeon_nand *priv;
	struct device_node *child_node;
	int rv;
	int chip;
	int active_chips = 0;
	char *name;
	int chip_num = 0; /* Count of detected chips, used for device naming */

	DEV_DBG(DEBUG_INIT, &pdev->dev, "called\n");

	for_each_child_of_node(pdev->dev.of_node, child_node) {
		u32 reg;
		rv = of_property_read_u32(child_node, "reg", &reg);
		if (rv)
			continue;
		active_chips |= (1 << reg);
	}
	if (!active_chips)
		return -ENODEV;

#if 0
	/*
	 * Optionally set defaults to be used for NAND chips that aren't
	 * recognized by cvmx_nand_initialize()
	 */
	cvmx_nand_set_defaults(2048, 64, 64, 2048, 2);
#endif

	down(&octeon_bootbus_sem);
	cvmx_nand_initialize(0 /* CVMX_NAND_INITIALIZE_FLAGS_DEBUG */
			       /*CVMX_NAND_INITIALIZE_FLAGS_DONT_PROBE */,
			     active_chips);
	up(&octeon_bootbus_sem);

	for (chip = 0; chip < 8; chip++) {
		/* Skip chip selects that don't have NAND */
		if ((active_chips & (1 << chip)) == 0)
			continue;

		/*
		 * Allocate and initialize mtd_info, nand_chip and private
		 * structures
		 */
		priv = devm_kzalloc(&pdev->dev,
				    sizeof(struct octeon_nand), GFP_KERNEL);
		if (!priv) {
			dev_err(&pdev->dev, "Unable to allocate structures\n");
			return -ENOMEM;
		}
		name = devm_kzalloc(&pdev->dev, MAX_NAND_NAME_LEN, GFP_KERNEL);
		if (!name) {
			dev_err(&pdev->dev, "Unable to allocate structures\n");
			return -ENOMEM;
		}

		priv->mtd.owner = THIS_MODULE;
		priv->mtd.priv = &priv->nand;
		memset(priv->data, 0xff, sizeof(priv->data));
		priv->dev = &pdev->dev;
		priv->selected_chip = chip;

		/* We always identify chips as 8 bit, as the Octeon NAND
		 * layer makes both 8 and 16 bit look the same.
		 * We never set the 16 bit buswidth option.
		 */

		priv->nand.read_byte = octeon_nand_read_byte;
		priv->nand.read_word = octeon_nand_read_word;
		priv->nand.write_buf = octeon_nand_write_buf;
		priv->nand.read_buf = octeon_nand_read_buf;
#ifdef	__DEPRECATED_API
		priv->nand.verify_buf = octeon_nand_verify_buf;
#endif
		priv->nand.select_chip = octeon_nand_select_chip;
		priv->nand.cmdfunc = octeon_nand_cmdfunc;
		priv->nand.init_size = octeon_nand_init_size;

		rv = octeon_nand_scan_onfi(priv);
		if (rv) {
			dev_err(&pdev->dev, "Failed to scan NAND device\n");
			return -1;
		}
		rv = octeon_nand_hw_bch_init(priv);
		if (rv) {
			dev_err(&pdev->dev, "Failed to initialize BCH for NAND\n");
			return -ENXIO;
		}

		if (nand_scan(&priv->mtd, 1) != 0) {
			dev_err(&pdev->dev, "NAND scan failed\n");
			return -ENXIO;
		}

		/* Disable subpage support, as it is not properly supported
		 * in this octeon-nand driver. Subpage support is assumed by
		 * nand_base.c for all large-page NAND flashes that use soft
		 * ECC.
		 */
		priv->nand.options &= ~NAND_SUBPAGE_READ;

		/* We need to override the name, as the default names
		 * have spaces in them, and this prevents the passing
		 * of partitioning information on the kernel command line.
		 */
		snprintf(name, MAX_NAND_NAME_LEN, "octeon_nand%d", chip_num);
		priv->mtd.name = name;
		priv->mtd.dev.parent = &pdev->dev;

		mtd_device_parse_register(&priv->mtd, part_probes,
					  NULL, NULL, 0);
		octeon_nand_open_mtd[chip] = priv;
		chip_num++;
	}
	return 0;
}

/*
 * Called when the driver is unloaded. It must clean up all
 * created devices.
 */
static int octeon_nand_remove(struct platform_device *pdev)
{
	struct octeon_nand *priv;
	int chip;

	DEV_DBG(DEBUG_INIT, &pdev->dev, "called\n");
	for (chip = 0; chip < 8; chip++) {
		priv = octeon_nand_open_mtd[chip];
		if (priv) {
			mtd_device_unregister(&priv->mtd);
			octeon_nand_open_mtd[chip] = NULL;
		}
	}
	return 0;
}

static struct of_device_id octeon_nand_match[] = {
	{
		.compatible = "cavium,octeon-5230-nand",
	},
	{},
};

static struct platform_driver octeon_nand_driver = {
	.probe = octeon_nand_probe,
	.remove = octeon_nand_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = DRIVER_NAME,
		.of_match_table = octeon_nand_match,
	},
};

static int __init octeon_nand_driver_init(void)
{
	return platform_driver_register(&octeon_nand_driver);
}
/*
 * We need to call octeon_nand_driver_init late enough that the MTD
 * core is already registered.  If built into the kernel , use a late
 * initcall.
 */
late_initcall(octeon_nand_driver_init);

static void __exit octeon_nand_driver_exit(void)
{
	platform_driver_unregister(&octeon_nand_driver);
}
module_exit(octeon_nand_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. OCTEON NAND driver.");
