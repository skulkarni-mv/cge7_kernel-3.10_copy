/*
 * I2C multiplexer
 *
 * Copyright (c) 2008-2009 Rodolfo Giometti <giometti@linux.it>
 * Copyright (c) 2008-2009 Eurotech S.p.A. <info@eurotech.it>
 *
 * This module supports the PCA954x series of I2C multiplexer/switch chips
 * made by Philips Semiconductors.
 * This includes the:
 *	 PCA9540, PCA9542, PCA9543, PCA9544, PCA9545, PCA9546, PCA9547
 *	 and PCA9548.
 *
 * These chips are all controlled via the I2C bus itself, and all have a
 * single 8-bit register. The upstream "parent" bus fans out to two,
 * four, or eight downstream busses or channels; which of these
 * are selected is determined by the chip type and register contents. A
 * mux can select only one sub-bus at a time; a switch can select any
 * combination simultaneously.
 *
 * Based on:
 *	pca954x.c from Kumar Gala <galak@kernel.crashing.org>
 * Copyright (C) 2006
 *
 * Based on:
 *	pca954x.c from Ken Harrenstien
 * Copyright (C) 2004 Google, Inc. (Ken Harrenstien)
 *
 * Based on:
 *	i2c-virtual_cb.c from Brian Kuschak <bkuschak@yahoo.com>
 * and
 *	pca9540.c from Jean Delvare <khali@linux-fr.org>.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/i2c-mux.h>
#include <linux/of.h>

#include <linux/i2c/pca954x.h>

#define PCA954X_MAX_NCHANS 8

enum pca_type {
	pca_9540,
	pca_9542,
	pca_9543,
	pca_9544,
	pca_9545,
	pca_9546,
	pca_9547,
	pca_9548,
};

struct pca954x {
	enum pca_type type;
	struct i2c_adapter *virt_adaps[PCA954X_MAX_NCHANS];

	u8 last_chan;		/* last register value */
	u8 disable_mux;		/* do not disable mux if val not 0 */

	struct i2c_op_q_entry op_e;
	union i2c_smbus_data op_data;
	bool in_select;
	u8 pending_chan;
	void *cb_data;
	void (*cb)(void *, int);
};

struct chip_desc {
	u8 nchans;
	u8 enable;	/* used for muxes only */
	enum muxtype {
		pca954x_ismux = 0,
		pca954x_isswi
	} muxtype;
};

/* Provide specs for the PCA954x types we know about */
static const struct chip_desc chips[] = {
	[pca_9540] = {
		.nchans = 2,
		.enable = 0x4,
		.muxtype = pca954x_ismux,
	},
	[pca_9543] = {
		.nchans = 2,
		.muxtype = pca954x_isswi,
	},
	[pca_9544] = {
		.nchans = 4,
		.enable = 0x4,
		.muxtype = pca954x_ismux,
	},
	[pca_9545] = {
		.nchans = 4,
		.muxtype = pca954x_isswi,
	},
	[pca_9547] = {
		.nchans = 8,
		.enable = 0x8,
		.muxtype = pca954x_ismux,
	},
	[pca_9548] = {
		.nchans = 8,
		.muxtype = pca954x_isswi,
	},
};

static const struct i2c_device_id pca954x_id[] = {
	{ "pca9540", pca_9540 },
	{ "pca9542", pca_9540 },
	{ "pca9543", pca_9543 },
	{ "pca9544", pca_9544 },
	{ "pca9545", pca_9545 },
	{ "pca9546", pca_9545 },
	{ "pca9547", pca_9547 },
	{ "pca9548", pca_9548 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pca954x_id);

/* Write to mux register. Don't use i2c_transfer()/i2c_smbus_xfer()
   for this as they will try to lock adapter a second time */
static int pca954x_reg_write(struct i2c_adapter *adap,
			     struct i2c_client *client, u8 val)
{
	return i2c_smbus_xfer_nolock(adap, client->addr, client->flags,
				     I2C_SMBUS_WRITE, val,
				     I2C_SMBUS_BYTE, NULL);
}

static int pca954x_d_reg_write(struct pca954x *data, struct i2c_adapter *adap,
			       struct i2c_client *client, u8 val,
			       void *cb_data,
			       void (*cb)(void *, int))
{
	data->cb = cb;
	data->cb_data = cb_data;
	data->op_e.smbus.read_write = I2C_SMBUS_WRITE;
	data->op_e.smbus.command = val;
		
	return i2c_non_blocking_op_head(client, &data->op_e);
}

static int pca954x_select_chan(struct i2c_adapter *adap,
			       void *client, u32 chan)
{
	struct pca954x *data = i2c_get_clientdata(client);
	const struct chip_desc *chip = &chips[data->type];
	u8 regval;
	int ret = 0;

	/* we make switches look like muxes, not sure how to be smarter */
	if (chip->muxtype == pca954x_ismux)
		regval = chan | chip->enable;
	else
		regval = 1 << chan;

	/* Only select the channel if its different from the last channel */
	if (data->last_chan != regval) {
		ret = pca954x_reg_write(adap, client, regval);
		data->last_chan = regval;
	}

	return ret;
}

static int pca954x_deselect_mux(struct i2c_adapter *adap,
				void *client, u32 chan)
{
	struct pca954x *data = i2c_get_clientdata(client);

	if (data->disable_mux != 0)
		data->last_chan = chips[data->type].nchans;
	else
		data->last_chan = 0;	/* Deselect active channel */
	return pca954x_reg_write(adap, client, data->disable_mux);
}

static void pca954x_op_done(struct i2c_op_q_entry *entry)
{
	struct pca954x *data = entry->handler_data;

	if (data->in_select) {
		if (entry->result == 0)
			data->last_chan = data->pending_chan;
		else
			data->last_chan = 0; /* invalidate */
	}
	data->cb(data->cb_data, entry->result);
}

static int pca954x_d_select_chan(struct i2c_adapter *adap,
				 void *client, u32 chan,
				 void *cb_data,
				 void (*cb)(void *, int))
{
	struct pca954x *data = i2c_get_clientdata(client);
	const struct chip_desc *chip = &chips[data->type];
	u8 regval;
	int ret = 1; /* Positive means we selected immediately. */

	/* we make switches look like muxes, not sure how to be smarter */
	if (chip->muxtype == pca954x_ismux)
		regval = chan | chip->enable;
	else
		regval = 1 << chan;

	/* Only select the channel if its different from the last channel */
	if (data->last_chan != regval) {
		data->pending_chan = regval;
		data->in_select = true;
		ret = pca954x_d_reg_write(data, adap, client, regval,
					  cb_data, cb);
	}

	return ret;
}

static int pca954x_d_deselect_mux(struct i2c_adapter *adap,
				  void *client, u32 chan,
				  void *cb_data,
				  void (*cb)(void *, int))
{
	struct pca954x *data = i2c_get_clientdata(client);

	data->last_chan = 0;
	data->in_select = false;
	return pca954x_d_reg_write(data, adap, client, data->last_chan,
				   cb_data, cb);
}

static struct i2c_adapter *pca954x_add_mux_adapter(struct i2c_adapter *adap,
						   struct i2c_client *client,
						   int force, int num,
						   int class, bool deselect)
{
	if (adap->algo->master_start || adap->algo->smbus_start)
		return i2c_add_mux_adapter_delayed_select(adap, &client->dev,
				client, force, num, class,
				pca954x_d_select_chan,
				deselect ? pca954x_d_deselect_mux : NULL);
	else
		return i2c_add_mux_adapter(adap, &client->dev, client,
				force, num, class, pca954x_select_chan,
				deselect ? pca954x_deselect_mux : NULL);
}

/*
 * I2C init/probing/exit functions
 */
static int pca954x_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct i2c_adapter *adap = to_i2c_adapter(client->dev.parent);
	struct pca954x_platform_data *pdata = client->dev.platform_data;
	struct device_node *of_node = client->dev.of_node;
	bool idle_disconnect_dt;
	int num, force, class;
	struct pca954x *data;
	int ret = -ENODEV;

	if (!i2c_check_functionality(adap, I2C_FUNC_SMBUS_BYTE))
		goto err;

	data = kzalloc(sizeof(struct pca954x), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto err;
	}

	/* The point here is that you must not disable a mux if there
	 * are no pullups on the input or you mess up the I2C. This
	 * needs to be put into the DTS really as the kernel cannot
	 * know this otherwise.
	 */
	data->type = id->driver_data;
	data->disable_mux = of_node &&
		of_property_read_bool(of_node, "i2c-mux-never-disable") &&
		chips[data->type].muxtype == pca954x_ismux ?
		chips[data->type].enable : 0;
	/* force the first selection */
	if (data->disable_mux != 0)
		data->last_chan = chips[data->type].nchans;
	else
		data->last_chan = 0;		   /* force the first selection */

	i2c_set_clientdata(client, data);

	/* Write the mux register at addr to verify
	 * that the mux is in fact present. This also
	 * initializes the mux to disconnected state.
	 */
	if (i2c_smbus_write_byte(client, data->disable_mux) < 0) {
		dev_warn(&client->dev, "probe failed\n");
		goto exit_free;
	}

	idle_disconnect_dt = of_node &&
		of_property_read_bool(of_node, "i2c-mux-idle-disconnect");

	data->op_e.xfer_type = I2C_OP_SMBUS;
	data->op_e.handler = pca954x_op_done;
	data->op_e.handler_data = data;
	data->op_e.smbus.addr = client->addr;
	data->op_e.smbus.flags = client->flags;
	data->op_e.smbus.data = &data->op_data;
	data->op_e.smbus.size = I2C_SMBUS_BYTE;

	/* Now create an adapter for each channel */
	for (num = 0; num < chips[data->type].nchans; num++) {
		bool idle_disconnect_pd = false;

		force = 0;			  /* dynamic adap number */
		class = 0;			  /* no class by default */
		if (pdata) {
			if (num < pdata->num_modes) {
				/* force static number */
				force = pdata->modes[num].adap_id;
				class = pdata->modes[num].class;
			} else
				/* discard unconfigured channels */
				break;
			idle_disconnect_pd = pdata->modes[num].deselect_on_exit;
		}

		data->virt_adaps[num] =
			pca954x_add_mux_adapter(adap, client,
				force, num, class,
				(idle_disconnect_pd || idle_disconnect_dt));

		if (data->virt_adaps[num] == NULL) {
			ret = -ENODEV;
			dev_err(&client->dev,
				"failed to register multiplexed adapter"
				" %d as bus %d\n", num, force);
			goto virt_reg_failed;
		}
	}

	dev_info(&client->dev,
		 "registered %d multiplexed busses for I2C %s %s\n",
		 num, chips[data->type].muxtype == pca954x_ismux
				? "mux" : "switch", client->name);

	return 0;

virt_reg_failed:
	for (num--; num >= 0; num--)
		i2c_del_mux_adapter(data->virt_adaps[num]);
exit_free:
	kfree(data);
err:
	return ret;
}

static int pca954x_remove(struct i2c_client *client)
{
	struct pca954x *data = i2c_get_clientdata(client);
	const struct chip_desc *chip = &chips[data->type];
	int i;

	for (i = 0; i < chip->nchans; ++i)
		if (data->virt_adaps[i]) {
			i2c_del_mux_adapter(data->virt_adaps[i]);
			data->virt_adaps[i] = NULL;
		}

	kfree(data);
	return 0;
}

static struct i2c_driver pca954x_driver = {
	.driver		= {
		.name	= "pca954x",
		.owner	= THIS_MODULE,
	},
	.probe		= pca954x_probe,
	.remove		= pca954x_remove,
	.id_table	= pca954x_id,
};

module_i2c_driver(pca954x_driver);

MODULE_AUTHOR("Rodolfo Giometti <giometti@linux.it>");
MODULE_DESCRIPTION("PCA954x I2C mux/switch driver");
MODULE_LICENSE("GPL v2");
