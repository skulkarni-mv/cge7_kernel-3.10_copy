/*
 * Copyright (C) 2014 MontaVista, Software, Inc.
 * An I2C driver for the Maxim DS1341 RTC
 *
 * Modified by : Niyas Ahamed Mydeen
 * Author: Anna Ciantelli
 *
 * based on the other drivers in this same directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/i2c.h>
#include <linux/bcd.h>
#include <linux/rtc.h>
#include <linux/slab.h>
#include <linux/module.h>
#define DRV_VERSION "0.0.1"

#define DS1341_REG_SC                 0x00
#define DS1341_REG_MN                 0x01
#define DS1341_REG_HR                 0x02
#define DS1341_REG_DW                 0x03
#define DS1341_REG_DM                 0x04
#define DS1341_REG_MO                 0x05
#define DS1341_REG_YR                 0x06
#define DS1341_REG_ALARM1_SECS        0x07
#define DS1341_REG_ALARM1_MIN         0x08
#define DS1341_REG_ALARM1_HOUR        0x09
#define DS1341_REG_ALARM1_DAY_DATE    0x0A
#define DS1341_REG_ALARM2_MIN         0x0B
#define DS1341_REG_ALARM2_HOUR        0x0C
#define DS1341_REG_ALARM2_DAY_DATE    0x0D
#define DS1341_REG_CONTROL            0x0E
#define DS1341_REG_CONTROL_STATUS     0x0F

#define DS1341_BIT_MO_C               0x80 /* Century, bit 8 in DS1341_REG_MO */
#define DS1341_BIT_OSF                0x80 /* Oscillator Stop Flag, bit 8 in DS1341_REG_CONTROL_STATUS */
#define BCD2BIN(val)    bcd2bin(val)
#define BIN2BCD(val)    bin2bcd(val)

/* backwards compat */
#define BCD_TO_BIN(val) ((val)=BCD2BIN(val))
#define BIN_TO_BCD(val) ((val)=BIN2BCD(val))

static struct i2c_driver ds1341_driver;

struct ds1341 {
	struct rtc_device *rtc;
	/*
	 * From DS1341 datasheet: this bit is toggled when the years
	 * register overflows from 99 to 00
	 *   0 indicates the century is 20xx
	 *   1 indicates the century is 19xx
	 * There seems no reliable way to know how the system use this
	 * bit.  So let's do it heuristically, assuming we are live in
	 * 1970...2069.
	 */
	int c_polarity;	/* 0: CENT=1 means 19xx, otherwise CENT=1 means 20xx */
};

/*
 * In the routines that deal directly with the ds1341 hardware, we use
 * rtc_time -- month 0-11, hour 0-23, yr = calendar year-epoch.
 */
static int ds1341_get_datetime(struct i2c_client *client, struct rtc_time *tm)
{
	struct ds1341 *ds1341 = i2c_get_clientdata(client);
	unsigned char buf[16] = { DS1341_REG_SC };

	struct i2c_msg msgs[] = {
		{ client->addr, 0, 1, buf },	/* setup read ptr */
		{ client->addr, I2C_M_RD, 16, buf },	/* read status + date */
	};

	/* read registers */
	if ((i2c_transfer(client->adapter, msgs, 2)) != 2) {
		dev_err(&client->dev, "%s: read error\n", __func__);
		return -EIO;
	}

	/* Is Oscillator Stop Flag active? (probably means the battery backup has died) */
	if (buf[DS1341_REG_CONTROL_STATUS] & DS1341_BIT_OSF) {

		/* address, registry with flipped OSF, and final byte with LSB set for STP condition */
		unsigned char data[3] = { DS1341_REG_CONTROL_STATUS,
					buf[DS1341_REG_CONTROL_STATUS] & ~DS1341_BIT_OSF,
					0x1
		};

		dev_info(&client->dev, "RTC Oscillator Stop Flag is active, trying to clear.\n");

		/* write control register's data */
		i2c_master_send(client, data, sizeof(data));
	}

	dev_dbg(&client->dev,
		"%s: raw data is sec=%02x, min=%02x, hr=%02x, "
		"wday=%02x, mday=%02x, mon=%02x, year=%02x\n",
		__func__,
		buf[0], buf[1], buf[2], buf[3],
		buf[4], buf[5], buf[6]);

	tm->tm_sec = BCD2BIN(buf[DS1341_REG_SC] & 0x7F);
	tm->tm_min = BCD2BIN(buf[DS1341_REG_MN] & 0x7F);
	tm->tm_hour = BCD2BIN(buf[DS1341_REG_HR] & 0x3F); /* rtc hr 0-23 */
	tm->tm_mday = BCD2BIN(buf[DS1341_REG_DM] & 0x3F);
	tm->tm_wday = buf[DS1341_REG_DW] & 0x07;
	tm->tm_mon = BCD2BIN(buf[DS1341_REG_MO] & 0x1F) - 1; /* rtc mn 1-12 */
	tm->tm_year = BCD2BIN(buf[DS1341_REG_YR]);
	if (tm->tm_year < 70)
		tm->tm_year += 100;	/* assume we are in 1970...2069 */
	/* detect the polarity heuristically. see note above. */
	ds1341->c_polarity = (buf[DS1341_REG_MO] & DS1341_BIT_MO_C) ?
		(tm->tm_year >= 100) : (tm->tm_year < 100);

	dev_dbg(&client->dev, "%s: tm is secs=%d, mins=%d, hours=%d, "
		"mday=%d, mon=%d, year=%d, wday=%d\n",
		__func__,
		tm->tm_sec, tm->tm_min, tm->tm_hour,
		tm->tm_mday, tm->tm_mon, tm->tm_year, tm->tm_wday);

	/* the clock can give out invalid datetime, but we cannot return
	 * -EINVAL otherwise hwclock will refuse to set the time on bootup.
	 */
	if (rtc_valid_tm(tm) < 0)
		dev_err(&client->dev, "retrieved date/time is not valid.\n");

	return 0;
}

static int ds1341_set_datetime(struct i2c_client *client, struct rtc_time *tm)
{
	struct ds1341 *ds1341 = i2c_get_clientdata(client);
	int i, err;
	unsigned char buf[9];

	dev_dbg(&client->dev, "%s: secs=%d, mins=%d, hours=%d, "
		"mday=%d, mon=%d, year=%d, wday=%d\n",
		__func__,
		tm->tm_sec, tm->tm_min, tm->tm_hour,
		tm->tm_mday, tm->tm_mon, tm->tm_year, tm->tm_wday);

	/* hours, minutes and seconds */
	buf[DS1341_REG_SC] = BIN2BCD(tm->tm_sec);
	buf[DS1341_REG_MN] = BIN2BCD(tm->tm_min);
	buf[DS1341_REG_HR] = BIN2BCD(tm->tm_hour);

	buf[DS1341_REG_DM] = BIN2BCD(tm->tm_mday);

	/* month, 1 - 12 */
	buf[DS1341_REG_MO] = BIN2BCD(tm->tm_mon + 1);

	/* year and century */
	buf[DS1341_REG_YR] = BIN2BCD(tm->tm_year % 100);
	if (ds1341->c_polarity ? (tm->tm_year >= 100) : (tm->tm_year < 100))
		buf[DS1341_REG_MO] |= DS1341_BIT_MO_C;

	buf[DS1341_REG_DW] = tm->tm_wday & 0x07;

	/* write register's data */
	for (i = 0; i < 7; i++) {
		unsigned char data[2] = { DS1341_REG_SC + i,
						buf[DS1341_REG_SC + i] };

		err = i2c_master_send(client, data, sizeof(data));
		if (err != sizeof(data)) {
			dev_err(&client->dev,
				"%s: err=%d addr=%02x, data=%02x\n",
				__func__, err, data[0], data[1]);
			return -EIO;
		}
	};

	return 0;
}

struct ds1341_limit
{
	unsigned char reg;
	unsigned char mask;
	unsigned char min;
	unsigned char max;
};

static int ds1341_validate_client(struct i2c_client *client)
{
	int i;

	static const struct ds1341_limit pattern[] = {
		/* register, mask, min, max */
		{ DS1341_REG_SC,	0x7F,	0,	59	},
		{ DS1341_REG_MN,	0x7F,	0,	59	},
		{ DS1341_REG_HR,	0x3F,	0,	23	},
		{ DS1341_REG_DM,	0x3F,	0,	31	},
		{ DS1341_REG_MO,	0x1F,	0,	12	},
	};

	/* check limits (only registers with bcd values) */
	for (i = 0; i < ARRAY_SIZE(pattern); i++) {
		int xfer;
		unsigned char value;
		unsigned char buf = pattern[i].reg;

		struct i2c_msg msgs[] = {
			{ client->addr, 0, 1, &buf },
			{ client->addr, I2C_M_RD, 1, &buf },
		};

		xfer = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));

		if (xfer != ARRAY_SIZE(msgs)) {
			dev_err(&client->dev,
				"%s: could not read register 0x%02X\n",
				__func__, pattern[i].reg);

			return -EIO;
		}

		value = BCD2BIN(buf & pattern[i].mask);

		if (value > pattern[i].max ||
			value < pattern[i].min) {
			dev_dbg(&client->dev,
				"%s: pattern=%d, reg=%x, mask=0x%02x, min=%d, "
				"max=%d, value=%d, raw=0x%02X\n",
				__func__, i, pattern[i].reg, pattern[i].mask,
				pattern[i].min, pattern[i].max,
				value, buf);

//			return -ENODEV;
		}
	}

	return 0;
}

static int ds1341_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	return ds1341_get_datetime(to_i2c_client(dev), tm);
}

static int ds1341_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	return ds1341_set_datetime(to_i2c_client(dev), tm);
}

static const struct rtc_class_ops ds1341_rtc_ops = {
	.read_time	= ds1341_rtc_read_time,
	.set_time	= ds1341_rtc_set_time,
};

static int ds1341_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{

	struct ds1341 *ds1341;

	int err = 0;

	dev_dbg(&client->dev, "%s\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
		return -ENODEV;

	ds1341 = kzalloc(sizeof(struct ds1341), GFP_KERNEL);
	if (!ds1341)
		return -ENOMEM;

	i2c_set_clientdata(client, ds1341);

	/* Verify the chip is really an DS1341 */
	if (ds1341_validate_client(client) < 0) {
		err = -ENODEV;
		goto exit_kfree;
	}

	dev_info(&client->dev, "chip found, driver version " DRV_VERSION "\n");

	ds1341->rtc = rtc_device_register(ds1341_driver.driver.name,
				&client->dev, &ds1341_rtc_ops, THIS_MODULE);

	if (IS_ERR(ds1341->rtc)) {
		err = PTR_ERR(ds1341->rtc);
		goto exit_kfree;
	}


	return 0;

exit_kfree:
	kfree(ds1341);

	return err;
}

static int ds1341_remove(struct i2c_client *client)
{
	struct ds1341 *ds1341 = i2c_get_clientdata(client);

	if (ds1341->rtc)
		rtc_device_unregister(ds1341->rtc);

	kfree(ds1341);

	return 0;
}

static const struct i2c_device_id ds1341_id[] = {
	{ "ds1341", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, ds1341_id);

static struct i2c_driver ds1341_driver = {
	.driver		= {
		.name	= "rtc-ds1341",
	},
	.probe		= ds1341_probe,
	.remove		= ds1341_remove,
	.id_table	= ds1341_id,
};
module_i2c_driver(ds1341_driver);

MODULE_AUTHOR("Anna Ciantelli <anna.ciantelli@ericsson.com>");
MODULE_DESCRIPTION("Maxim DS1341 RTC driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
