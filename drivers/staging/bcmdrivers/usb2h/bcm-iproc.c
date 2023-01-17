/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
 
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <linux/version.h>
#include <mach/iproc_regs.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
/*
#include <linux/clk.h>
#include <linux/usb/phy.h>
*/

#define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, args...) printk(KERN_INFO "%s: " fmt, __func__, ## args)
#else
#define dbg_printk(fmt, args...)
#endif

extern void __iomem *get_iproc_wrap_ctrl_base(void);

#define USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET	0x408
#define IPROC_IDM_USB2_RESET_CONTROL_OFFSET		0x800

/* HX4/KT2 */
#define IPROC_WRAP_USBPHY_CTRL_HX4_OFFSET 	0x14
#define IPROC_WRAP_USBPHY_CTRL_KT2_OFFSET 	0x0
#define IPROC_WRAP_MISC_STATUS_HX4_OFFSET 	0x8
#define IPROC_XGPLL_HX4_OFFSET 				0xC
#define IPROC_CLK_NDIV_40                   0x80
#define IPROC_CLK_NDIV_20                   0x8C
#define USB_CLK_NDIV_MASK                   0xFE7FFE00
#define USB_CLK_PLL_RESET_MASK              0xFF7FFE00
#define USB_CLK_PHY_RESET_MASK              0xFFFFFE00
#define USB_CLK_NDIV_40                     0x30
#define USB_CLK_NDIV_20                     0x60
#define SUPPLY_USBD_POWER                   0xfffffffd

/* GH/HR3/SB2*/
#define USBH_Phy_Ctrl_P0_OFFSET 				0x200 /* based on 0x18049000 */
#define IPROC_WRAP_USBPHY_CTRL_0__PHY_IDDQ      26 /* Port 0 */
#define IPROC_WRAP_USBPHY_CTRL_0__PLL_RESETB    25
#define IPROC_WRAP_USBPHY_CTRL_0__RESETB        24
#define IPROC_WRAP_MISC_STATUS__USBPHY_PLL_LOCK     1

/* GH/HR3 */
#define IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET 		0x4
#define IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET 		0xC
#define IPROC_WRAP_MISC_STATUS_GH_OFFSET 		0x18
#define IPROC_WRAP_USBPHY_CTRL_2__PHY_ISO       17
#define IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B0      0
#define IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B11     11
#define IPROC_WRAP_MISC_STATUS__USBPHY_LDO_ON_FLAG  2
/* based on 0x1800fc00 */
#define IPROC_WRAP_STRAP_STATUS_GH_OFFSET		0xA4

                      
/* SB2 */
#define IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET 	0x8
#define IPROC_WRAP_USBPHY_CTRL_2_SB2_OFFSET 	0x10
#define IPROC_WRAP_USBPHY_CTRL_5_OFFSET 		0x1C
#define IPROC_WRAP_MISC_STATUS_SB2_OFFSET 		0x24
#define IPROC_WRAP_USBPHY_CTRL_5__P1CTL_B0      0
#define IPROC_WRAP_USBPHY_CTRL_5__P1CTL_B11     11
/* based on 0x1800fc00 */
#define IPROC_WRAP_STRAP_STATUS_SB2_OFFSET		0x70
/* based on 0x18049000 */
#define USBH_Utmi_p0Ctl_OFFSET 					0X510

#define USBH_NUM_PORTS 3
struct usbh_ctrl_regs {
    u32 mode;
#define MODE_ULPI_TTL                       (1<<0)
#define MODE_ULPI_PHY                       (1<<1)
#define MODE_UTMI_TTL                       (1<<2)
#define MODE_UTMI_PHY                       (1<<3)
#define MODE_PORT_CFG(port, mode) ((mode) << (4 * port))

    u32 strap_q;
#define STRAP_PWR_STATE_VALID               (1 << 7)    /* ss_power_state_valid */
#define STRAP_SIM_MODE                      (1 << 6)    /* ss_simulation_mode */
#define STRAP_OHCI_CNTSEL_SIM               (1 << 5)    /* ohci_0_cntsel_i_n */
#define STRAP_PWR_STATE_NXT_VALID           (1 << 4)    /* ss_nxt_power_state_valid_i */
#define STRAP_PWR_STATE_NXT_SHIFT           2           /* ss_next_power_state_i */
#define STRAP_PWR_STATE_NXT_MASK            (3 << STRAP_PWR_STATE_NXT_SHIFT)
#define STRAP_PWR_STATE_SHIFT               0           /* ss_power_state_i */
#define STRAP_PWR_STATE_MASK                (3 << STRAP_PWR_STATE_SHIFT)

    u32 framelen_adj_q;
    u32 framelen_adj_qx[USBH_NUM_PORTS];       
    u32 misc;
#define MISC_RESUME_R23_ENABLE              (1 << 4) /* ss_utmi_backward_enb_i */
#define MISC_RESUME_R23_UTMI_PLUS_DISABLE   (1 << 3) /* ss_resume_utmi_pls_dis_i */
#define MISC_ULPI_BYPASS_ENABLE             (1 << 2) /* ulpi_bypass_en_i */
#define MISC_PORT_PWRDWN_OVERCURRENT        (1 << 1) /* ss_autoppd_on_overcur_en_i */
#define MISC_OHCI_CLK_RESTART               (1 << 0) /* app_start_clk_i */
};


struct usbh_priv {
    atomic_t probe_done;
    volatile int init_cnt;
    struct mutex lock;
    struct device *dev;
/*    struct usbh_cfg hw_cfg;*/
    struct clk *peri_clk;
    struct clk *ahb_clk;
    struct clk *opt_clk;
    struct usbh_ctrl_regs __iomem *ctrl_regs;   
    void *base_addr, *base_addr1, *base_addr2;
/*	struct usb_phy phy;*/
};

static struct usbh_priv usbh_data;

int InUSBDMode(void)
{
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	int usbd_detect;
	unsigned int gpio_pin;
	int err=0;
	
	/* gpio pin 4 to control host/device mode */
	gpio_pin = 4;
	err = gpio_request(gpio_pin, "USB2H");
    if (err) {
        printk("request gpio pin %d fail in %s\n", gpio_pin, __FUNCTION__);
        return err;
    }                           

	usbd_detect = __gpio_get_value(gpio_pin);
	if (usbd_detect & 1) {
		printk("%s: %d gpioin val %08x, ohci host mode will not be functional since in USBD mode\n", __FUNCTION__, __LINE__, usbd_detect);
		printk("%s: %d to make ohci host mode work, appropriate jumper is needed on the board. Please refer to board schematics.\n",
			__FUNCTION__, __LINE__);
	}
    
    gpio_free(gpio_pin);
	return (usbd_detect & 1);
#elif defined(CONFIG_MACH_SB2)
    /* u-boot enable this bit to indicate usb in host mode */
    if ((readl_relaxed(get_iproc_wrap_ctrl_base() + IPROC_WRAP_STRAP_STATUS_SB2_OFFSET) & (1 << 10)) == 0)
		return 1;
	else
		return 0;
		
#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3))
	if ((readl_relaxed(get_iproc_wrap_ctrl_base() + IPROC_WRAP_STRAP_STATUS_GH_OFFSET) & (1 << 17)) == 0)
		return 1;
	else
		return 0;

#else /* the same as GH/HR3 ?? */
	
	if ((readl_relaxed(get_iproc_wrap_ctrl_base() + IPROC_WRAP_STRAP_STATUS_GH_OFFSET) & (1 << 17)) == 0)
		return 1;
	else 
		return 0;
		
#endif
}

int bcm_usbh_suspend(unsigned int host_index)
{
    return 0;
}
EXPORT_SYMBOL(bcm_usbh_suspend);

int bcm_usbh_resume(unsigned int host_index)
{
    return 0;
}
EXPORT_SYMBOL(bcm_usbh_resume);

static
void bcm_sb2_usbphy_init(void __iomem *base_addr, void __iomem *base_addr1)
{
    unsigned long val, mask;
    int count = 0;
    val = readl_relaxed(base_addr1 + USBH_Utmi_p0Ctl_OFFSET);
    val &= ~0x00000800;     /* 11:dfe_powerup_fsm = 0 */
    writel_relaxed(val, base_addr1 + USBH_Utmi_p0Ctl_OFFSET);
    val |= 0x00000001;      /* 0:afe_non_driving = 1 */
    writel_relaxed(val, base_addr1 + USBH_Utmi_p0Ctl_OFFSET);

    val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    val |= 0x0c000000;      /* 27:PHY_ISO & 26:PLL_SUSPEND_EN = 1 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    val &= ~0x03000000;     /* 25:PLL_RESETB & 24:RESETB = 0 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);

    val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_SB2_OFFSET);
    val &= ~0x03000000;     /* 25:AFE_BG_PWRDWNB & 24:AFE_LDO_PWRDWNB = 0 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_SB2_OFFSET);
    udelay(10);
    val |= 0x02000000;      /* 25:AFE_BG_PWRDWNB = 1 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_SB2_OFFSET);
    udelay(150);
    val |= 0x01000000;      /* 24:AFE_LDO_PWRDWNB = 1 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_SB2_OFFSET);
    udelay(160);

    val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    val &= ~0x08000000;     /* 27:PHY_ISO = 0 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    udelay(20);
    val |= 0x02000000;      /* 25:PLL_RESETB = 1 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);

    mdelay(20);

    /* check pll_lock */
    mask = (1 << IPROC_WRAP_MISC_STATUS__USBPHY_PLL_LOCK);
    do {
        val = readl_relaxed(base_addr + IPROC_WRAP_MISC_STATUS_SB2_OFFSET);
        if ((val & mask) == mask)
            break;
        else {
            udelay(10);
            count ++;
        }
    } while(count <= 10);

    if (count > 10)
    {
        printk(KERN_WARNING "%s : PLL not lock! IPROC_WRAP_MISC_STATUS = 0x%08lx\n", 
               __FUNCTION__, val);
    }

    val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    val |= 0x01000000;      /* 24:RESETB = 1 */
    writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_SB2_OFFSET);
    udelay(2);

    val = readl_relaxed(base_addr1 + USBH_Utmi_p0Ctl_OFFSET);
    val &= ~0x00000001;     /* 0:afe_non_driving = 0 */
    writel_relaxed(val, base_addr1 + USBH_Utmi_p0Ctl_OFFSET);
}


static
void bcm_gh_usbphy_init(void __iomem *base_addr)
{
	unsigned long val, mask;
	int count = 0;
	/* set phy_iso to 1, phy_iddq to 1, non_driving to 1 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__PHY_ISO);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);

	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__PHY_IDDQ);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);

	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B0);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);

	/* set phy_resetb to 0, pll_resetb to 0 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__RESETB);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);

	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__PLL_RESETB);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	
	/* set p1ctl[11] to 0 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B11);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);

    /* set phy_iso to 0 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__PHY_ISO);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);

	/* set phy_iddq to 0 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__PHY_IDDQ);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	mdelay(1);

	/* set pll_resetb to 1, phy_resetb to 1 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__PLL_RESETB);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);

	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__RESETB);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_0_GH_OFFSET);

	mdelay(20);
	
	/* check pll_lock */
	mask = (1 << IPROC_WRAP_MISC_STATUS__USBPHY_PLL_LOCK);
	do {
		val = readl_relaxed(base_addr + IPROC_WRAP_MISC_STATUS_GH_OFFSET);
		if ((val & mask) == mask) {
			break;
		} else {
			udelay(10);
			count ++;
		}
	} while(count <= 10);
	
	if (count > 10) {
		printk(KERN_WARNING "%s : PLL not lock! IPROC_WRAP_MISC_STATUS = 0x%08lx\n", 
					__FUNCTION__, val);
	}
	
	/* set non_drving to 0 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B0);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);

    /* set p1ctl[11] to 1 */
	val = readl_relaxed(base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
	val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B11);
	writel_relaxed(val, base_addr + IPROC_WRAP_USBPHY_CTRL_2_GH_OFFSET);
}


static const struct of_device_id usb_phy_iproc_dt_ids[] = {
    { .compatible = "brcm,usb-phy,hx4", },
    { .compatible = "brcm,usb-phy,kt2", },
    { .compatible = "brcm,usb-phy,gh", },
    { .compatible = "brcm,usb-phy,sb2", },
    { .compatible = "brcm,usb-phy,hr3", },
    { }
};
MODULE_DEVICE_TABLE(of, usb_phy_iproc_dt_ids);


static int bcm_usbh_probe(struct platform_device *pdev)
{
    const struct of_device_id *match;
    struct device_node *dn = pdev->dev.of_node;
    unsigned int gpio_pin;
    const char *gpio_active="high";
    void __iomem *base_addr, *base_addr1, *base_addr2;
    unsigned int clk_enable, usb2_reset_state;
    int err=0;
    
	if (!of_device_is_available(dn))
        return -ENODEV;
    
    if ( InUSBDMode() )
    	return -ENODEV;
               
    match = of_match_device(usb_phy_iproc_dt_ids, &pdev->dev);
    if (!match) {
        dev_err(&pdev->dev, "Failed to find USB PHY in DT\n");
        return -ENODEV;
    }

  	if (of_property_read_u32(dn, "gpio-pin-usb-power", &gpio_pin)) {
        dev_warn(&pdev->dev, "missing gpio-pin-usb-power property (default to 5)\n");
        gpio_pin = 5;
    }
    if (of_property_read_string(dn, "gpio-active-usb-power", &gpio_active)) {
        dev_warn(&pdev->dev, "missing gpio-active-usb-power property (default to low)\n");
    }
    err = gpio_request(gpio_pin, "USB2H");
    if (err) {
        printk("request gpio pin %d fail in %s\n",gpio_pin, __FUNCTION__);
        return err;
    }                           
    else        
        gpio_direction_output(gpio_pin, 1);
    
    /* turn off the power: if active high for power, then set 0 to turn off*/
    if (strcmp(gpio_active, "high") == 0)
        __gpio_set_value(gpio_pin, 0);   
    else
        __gpio_set_value(gpio_pin, 1);
    
    base_addr = of_iomap(dn, 0);
    if (!base_addr) {
        dev_err(&pdev->dev, "can't iomap USB PHY base address\n");
        return -ENOMEM;
    }
    base_addr1 = of_iomap(dn, 1);
    if (!base_addr1) {
        dev_err(&pdev->dev, "can't iomap USB PHY base address 1\n");
        return -ENOMEM;
    }
    memset(&usbh_data, 0, sizeof(usbh_data));
    usbh_data.base_addr = base_addr;
    usbh_data.base_addr1 = base_addr1;
    
	if (strstr(match->compatible, "hx4") || strstr(match->compatible, "kt2")) {/*HX4/KT2 init */
        unsigned int reg_offset;
        unsigned int USBClk, pllStatus;
        unsigned iClk;
        int k;
            
        /* Do USB PHY reset */
        mdelay(100);
        if (strstr(match->compatible, "hx4"))
            reg_offset = IPROC_WRAP_USBPHY_CTRL_HX4_OFFSET;
        else    
        	reg_offset = IPROC_WRAP_USBPHY_CTRL_KT2_OFFSET;    
        USBClk = readl_relaxed(base_addr + reg_offset);
        
        /* bring phy pll out of reset if not done already */
        if ((USBClk & 0x01000000) == 0 ) {
            USBClk |= 0x01000000;
            writel_relaxed(USBClk, base_addr + reg_offset);
            pllStatus = readl_relaxed(base_addr + IPROC_WRAP_MISC_STATUS_HX4_OFFSET);
            for (k = 0; k < 100000; k++) {
                if ((pllStatus & 2) == 2) {
                    printk("USB phy pll locked\n");
                    break;
                }   
                pllStatus = readl_relaxed(base_addr + IPROC_WRAP_MISC_STATUS_HX4_OFFSET);
            }
        }
        writel_relaxed(USBClk & (~(1<<23)), base_addr + reg_offset);
        
        clk_enable = readl_relaxed(base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);
        printk("Initial usb2h clock is: %08x\n", clk_enable);
        clk_enable |= 1;
        writel_relaxed(clk_enable, base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);
        clk_enable = readl_relaxed(base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);
        printk("Initial usb2h clock now is: %08x\n", clk_enable);
        
        if (strstr(match->compatible, "hx4")) {
            iClk = readl_relaxed(base_addr + IPROC_XGPLL_HX4_OFFSET);
            USBClk = readl_relaxed(base_addr + reg_offset);
            printk("iClk = %08x, USBClk = %08x\n", iClk, USBClk);
            if ((iClk & 0xff) == IPROC_CLK_NDIV_40) {
                writel_relaxed((USBClk & USB_CLK_NDIV_MASK) | USB_CLK_NDIV_40, base_addr + reg_offset);
                udelay(10);
                writel_relaxed((USBClk & USB_CLK_PLL_RESET_MASK) | USB_CLK_NDIV_40, base_addr + reg_offset);
                udelay(10);
                writel_relaxed((USBClk & USB_CLK_PHY_RESET_MASK) | USB_CLK_NDIV_40, base_addr + reg_offset);
                udelay(10);
                USBClk = readl_relaxed(base_addr + reg_offset);
                printk("iClk = %08x, USBClk = %08x\n", iClk, USBClk);
            } else if ((iClk & 0xff) == IPROC_CLK_NDIV_20) {
                writel_relaxed((USBClk & USB_CLK_NDIV_MASK) | USB_CLK_NDIV_20, base_addr + reg_offset);
                udelay(10);
                writel_relaxed((USBClk & USB_CLK_PLL_RESET_MASK) | USB_CLK_NDIV_20, base_addr + reg_offset);
                udelay(10);
                writel_relaxed((USBClk & USB_CLK_PHY_RESET_MASK) | USB_CLK_NDIV_20, base_addr + reg_offset);
                udelay(10);
                USBClk = readl_relaxed(base_addr + reg_offset);
                printk("iClk = %08x, USBClk = %08x\n", iClk, USBClk);
            }
        }
        mdelay(100);
        writel_relaxed(USBClk | (1<<23), base_addr + reg_offset);
        udelay(100);
      
        usb2_reset_state = readl_relaxed(base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
        printk("Initial usb2_reset_state is: %08x\n", usb2_reset_state);
        if ((usb2_reset_state & 1) == 1) {
            writel_relaxed(0x0, base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
            usb2_reset_state = readl_relaxed(base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
            printk("usb2_reset_state is set and now it is: %08x\n", usb2_reset_state);
        }
        mdelay(100);    
    }
    else /*if (strstr(match->compatible, "hr3") || strstr(match->compatible, "gh") || strstr(match->compatible, "sb2")) */ {
    	base_addr2 = of_iomap(dn, 2); /* 0x18049000 */
    	if (!base_addr2) {
        	dev_err(&pdev->dev, "can't iomap USB PHY base address 2\n");
        	return -ENOMEM;
    	}
    	usbh_data.base_addr2 = base_addr2;
    	if (strstr(match->compatible, "sb2"))
    		bcm_sb2_usbphy_init(base_addr, base_addr2);
    	else
    		bcm_gh_usbphy_init(base_addr);
    			
        /* USB Host clock enable */
        clk_enable = readl_relaxed(base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);
        clk_enable |= 1;
        writel_relaxed(clk_enable, base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);
        clk_enable = readl_relaxed(base_addr1 + USB2_IDM_IDM_IO_CONTROL_DIRECT_OFFSET);

    	/* Bring USB Host out of reset */
    	usb2_reset_state = readl_relaxed(base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
    	usb2_reset_state |= 1;
    	writel_relaxed(usb2_reset_state, base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
    	usb2_reset_state &= ~1;
    	writel_relaxed(usb2_reset_state, base_addr1 + IPROC_IDM_USB2_RESET_CONTROL_OFFSET);
    	
    	writel_relaxed(0x3ff, base_addr2 + USBH_Phy_Ctrl_P0_OFFSET);
    	mdelay(100);
	}

/*  Not well supported currently */
    
    platform_set_drvdata(pdev, &usbh_data);
    
    /* supply power for USB device connected to the host */
    if (strcmp(gpio_active, "high") == 0)
    	__gpio_set_value(gpio_pin, 1);   
	else
    	__gpio_set_value(gpio_pin, 0);
  
    gpio_free(gpio_pin);
    
    return 0;
}

static int bcm_usbh_remove(struct platform_device *pdev) 
{
    struct usbh_priv *drv_data = platform_get_drvdata(pdev);

    atomic_set(&drv_data->probe_done, 0);
    platform_set_drvdata(pdev, NULL);
    if (drv_data->base_addr)
    	iounmap(drv_data->base_addr);
    if (drv_data->base_addr1)	
    	iounmap(drv_data->base_addr1);
    if (drv_data->base_addr2)
    	iounmap(drv_data->base_addr2);	
    memset(&usbh_data, 0, sizeof(usbh_data));

    return 0;      
}

static struct platform_driver usbh_phy_driver = 
{
    .driver = {
        .name = "usb-phy",
        .owner = THIS_MODULE,
        .of_match_table = of_match_ptr(usb_phy_iproc_dt_ids),
    },
    .probe   = bcm_usbh_probe,
    .remove  = bcm_usbh_remove,
};

module_platform_driver(usbh_phy_driver);

MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Broadcom USB host low-level driver");
MODULE_LICENSE("GPL");
