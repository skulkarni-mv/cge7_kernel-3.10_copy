/*****************************************************************************
* Copyright 2006 - 2010 Broadcom Corporation.  All rights reserved.
*
* Unless you and Broadcom execute a separate written software license
* agreement governing use of this software, this software is licensed to you
* under the terms of the GNU General Public License version 2, available at
* http://www.broadcom.com/licenses/GPLv2.php (the "GPL").
*
* Notwithstanding the above, under no circumstances may you combine this
* software in any way with any other Broadcom software provided under a
* license other than the GPL, without Broadcom's express prior written
* consent.
*****************************************************************************/

/****************************************************************************/
/**
*  @file    bcm_dwc_udc.c
*
*  @brief   Broadcom Linux driver for DWC USB 2.0 Device Controller (UDC)
*
*  This driver implements the Linux Gadget driver API as defined in usb_gadget.h
*
*  @note
*
*  This driver was written with the intent of being able to support any
*  variations on how this block is integrated into different Broadcom chips.
*
*  There is a requirement on how the DWC UDC is configured. In particular, this
*  driver requires that the following options be defined and enabled in the
*  UDC core.
*
*       UDC20AHB_CNAK_CLR_ENH_CC
*       UDC20AHB_STALL_SET_ENH_CC
*       UDC20AHB_SNAK_ENH_CC
*
*  Some other UDC attributes can be supported by setting compile time options
*  or with some minor modifications to the source code. Ideally these would
*  be run-time info that is provided by the device instance to the driver.
*  These attributes include the following.
*
*       BCM_UDC_EP_CNT
*       BCM_UDC_EP_MAX_PKT_SIZE
*       BCM_UDC_OUT_RX_FIFO_MEM_SIZE
*       BCM_UDC_IN_TX_FIFO_MEM_SIZE
*       BCM_UDC_IRQ
*       Type of each endpoint: Control, IN, OUT, or Bidirectional
*/
/****************************************************************************/
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/gpio.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>

#include "usbDevHw.h"

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#endif

#define BCM_UDC_EP_CNT                          10
#define BCM_UDC_EP_MAX_PKT_SIZE                 512
#define BCM_UDC_OUT_RX_FIFO_MEM_SIZE            4096
#define BCM_UDC_IN_TX_FIFO_MEM_SIZE             4096
#define BCM_UDC_IN_TX_MAX                       512

#include "bcm_udc_dwc.h"

/*
 * Name definitions for use with driver and devices. Device names will have
 * a digit appended. Note the correlation to the BCM_USBEHCI_HCD_MAX value
 * (max value is a single digit, hence the sizeof() + 1). Since this name
 * has to be the same in the device and the driver, really should have it
 * defined in some common include file used by both device and driver.
 */
#define BCM_UDC_NAME                        "iproc-udc"
#ifndef BCM_UDC_KMARKER
#define BCM_UDC_KMARKER                     BCM_UDC_NAME": "
#endif

/* #define DEBUG */
#define DEBUG_DEV                           0x00000001
#define DEBUG_EP                            0x00000002
#define DEBUG_MEM                           0x00000004
#define DEBUG_REQ                           0x00000008
#define DEBUG_IRQ                           0x00000010
#define DEBUG_DMA                           0x00000020
#define DEBUG_ISOC                          0x00000040
#define DEBUG_CTRL                          0x00000080
#define DEBUG_SOF                           0x00000100

#define DEBUG_EVENT                         0x80000000
#define DEBUG_TRACE                         0x40000000
#define DEBUG_CNT                           0x20000000

#ifdef DEBUG
static unsigned debug = DEBUG_TRACE | (0x1FF);

static void DmaDump(BCM_UDC_t *udcP);
static void DmaDumpDesc(char *label, BCM_UDC_DMA_DESC_t *virt, BCM_UDC_DMA_DESC_t *phys);
static void DmaDumpEp(BCM_UDC_EP_t *udcEpP);

/*
 * Add any normal log messages (syslogd) to the kernel log as well. Makes things easier
 * to interpret if the two are interleaved.
 */
#define BCM_KERROR(fmt, args...)        printk(KERN_ERR fmt, ## args)
#define BCM_KWARN(fmt, args...)         printk(KERN_WARNING fmt, ## args)
#define BCM_KNOTICE(fmt, args...)       printk(KERN_NOTICE fmt, ## args)
#define BCM_KINFO(fmt, args...)         printk(KERN_INFO fmt, ## args)

/*
 * Debug output is controlled by areas as opposed to levels. It makes things more flexible
 * wrt the amount and type of output.
 *
 * NOTE: The kernel log utility only allows 6 parameters for a format string. If you have
 * a BCM_DEBUG_xxx() that uses more than this, you will need to change the appropriate
 * knllog parameter before you start this driver. See include/linux/broadcom/knllog.h
 * and drivers/char/broadcom/knllog.c for more details on the appropriate /proc/sys/knllog
 * entry to use. Currently this is maxargs. Probably easier / safer to use more than one
 * BCM_DEBUG_xxx() statement if need to output more than 6 parameters.
 */
#define BCM_DEBUG_DEV                   if(debug & DEBUG_DEV) printk
#define BCM_DEBUG_EP                    if(debug & DEBUG_EP) printk
#define BCM_DEBUG_MEM                   if(debug & DEBUG_MEM) printk
#define BCM_DEBUG_REQ                   if(debug & DEBUG_MEM) printk
#define BCM_DEBUG_IRQ                   if(debug & DEBUG_IRQ) printk
#define BCM_DEBUG_DMA                   if(debug & DEBUG_DMA) printk
#define BCM_DEBUG_ISOC                  if(debug & DEBUG_ISOC) printk
#define BCM_DEBUG_CTRL                  if(debug & DEBUG_CTRL) printk
#define BCM_DEBUG_SOF                   if(debug & DEBUG_SOF) printk

#ifdef DEBUG_VERBOSE
#define BCM_DEBUG_TRACE                 if(debug & DEBUG_TRACE) printk
#else
#define BCM_DEBUG_TRACE(fmt...)
#endif /* DEBUG_VERBOSE */
#else /* !DEBUG */
#define BCM_KERROR(fmt, args...)        printk(KERN_ERR fmt, ## args)
#define BCM_KWARN(fmt, args...)         printk(KERN_WARNING fmt, ## args)
#define BCM_KNOTICE(fmt, args...)       printk(KERN_NOTICE fmt, ## args)
#define BCM_KINFO(fmt, args...)         printk(KERN_INFO fmt, ## args)
#define BCM_DEBUG_DEV(fmt...)
#define BCM_DEBUG_EP(fmt...)
#define BCM_DEBUG_MEM(fmt...)
#define BCM_DEBUG_REQ(fmt...)
#define BCM_DEBUG_IRQ(fmt...)
#define BCM_DEBUG_DMA(fmt...)
#define BCM_DEBUG_ISOC(fmt...)
#define BCM_DEBUG_CTRL(fmt...)
#define BCM_DEBUG_SOF(fmt...)
#define BCM_DEBUG_TRACE(fmt...)
#endif /* DEBUG */

/*
 * Uncomment the following REG_DEBUG and REG_DEBUG_PRINT if it is desired to have
 * the register modification routines defined in usbDevHw_def.h and usbPhyHw_def.h
 * output debug info.
 *
 * #define usbDevHw_DEBUG_REG
 * #define usbDevHw_DEBUG_REG_PRINT         printk
 * #define usbPhyHw_DEBUG_REG
 * #define usbPhyHw_DEBUG_REG_PRINT         printk
 */

/*
 * Define and set DMA_BURST_LEN_32BIT if it is desired to use a DMA burst length
 * other than the default which is 16 (INCR16). Set to 0 to disable burst mode
 * and use INCR.
 *
 * #define usbDevHw_DMA_BURST_LEN_32BIT     0
 */

#ifdef CONFIG_OF
#define IPROC_WRAP_CTRL_COMPATIBLE                  "brcm,iproc-wrap-ctrl"
#define IPROC_CCB_MDIO_COMPATIBLE                   "brcm,iproc-ccb-mdio"
#endif /* CONFIG_OF */

#define BCM_UDC_IRQ                                 IPROC_USB2D_IRQ

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
#define USB2D_IDM_IDM_BASE                          0x18116000
#define USB2D_IDM_IDM_REG_SIZE                      0x1000
#define USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(base)  (base + 0x408)
#define USB2D_IDM_IDM_RESET_CONTROL_ADDR(base)      (base + 0x800)
#define IPROC_WRAP_BASE                             0x1803fc00
#define IPROC_WRAP_REG_SIZE                         0x100
#define IPROC_WRAP_USBPHY_CTRL_ADDR(base)           (base + 0x34)
#if defined(CONFIG_MACH_HX4)
#define IPROC_WRAP_IPROC_XGPLL_CTRL_0_ADDR(base)    (base + 0x1c)
#define IPROC_WRAP_IPROC_XGPLL_CTRL_4_ADDR(base)    (base + 0x2c)
#elif defined(CONFIG_MACH_KT2)
#define IPROC_DDR_PLL_CTRL_REGISTER_3_ADDR(base)    (base + 0x0c)
#define IPROC_DDR_PLL_CTRL_REGISTER_5_ADDR(base)    (base + 0x14)
#endif
#define IPROC_CCB_MDIO_BASE                         0x18032000
#define IPROC_CCB_MDIO_REG_SIZE                     0x1000
#define IPROC_CCB_MDIO_MII_CTRL_ADDR(base)          (base + 0x0)
#define IPROC_CCB_MDIO_MII_DATA_ADDR(base)          (base + 0x4)
#define USBD_VBUS_GPIO                              4
#elif defined(CONFIG_MACH_SB2)
#define USB2D_IDM_IDM_BASE                          0x18111000
#define USB2D_IDM_IDM_REG_SIZE                      0x1000
#define USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(base)  (base + 0x408)
#define USB2D_IDM_IDM_RESET_CONTROL_ADDR(base)      (base + 0x800)
#define IPROC_WRAP_BASE                             0x1800fc00
#define IPROC_WRAP_REG_SIZE                         0x100
#define IPROC_WRAP_USBPHY_CTRL_0_ADDR(base)         (base + 0x28)
#define IPROC_WRAP_USBPHY_CTRL_2_ADDR(base)         (base + 0x30)
#define IPROC_WRAP_MISC_STATUS_ADDR(base)           (base + 0x44)
#define IPROC_WRAP_IPROC_STRAP_CTRL_ADDR(base)      (base + 0x70)
#define ICFG_USB2D_CONFIG_BASE                      0x18000370
#define ICFG_USB2D_CONFIG_REG_SIZE                  0xc
#define ICFG_USB2D_CONFIG_0_ADDR(base)              (base + 0x0)
#define ICFG_USB2D_CONFIG_1_ADDR(base)              (base + 0x4)
#define ICFG_USB2D_CONFIG_2_ADDR(base)              (base + 0x8)
#define USBD_VBUS_GPIO                              1
#define USB2D_DEVCONFIG_ADDR(base)                  (base + 0x400)
#define USB2D_DEVCTRL_ADDR(base)                    (base + 0x404)

#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2))
#define USB2D_IDM_IDM_BASE                          0x18111000
#define USB2D_IDM_IDM_REG_SIZE                      0x1000
#define USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(base)  (base + 0x408)
#define USB2D_IDM_IDM_RESET_CONTROL_ADDR(base)      (base + 0x800)
#define IPROC_WRAP_BASE                             0x1804fc00
#define IPROC_WRAP_REG_SIZE                         0x100
#define IPROC_WRAP_USBPHY_CTRL_0_ADDR(base)         (base + 0x44)
#define IPROC_WRAP_USBPHY_CTRL_2_ADDR(base)         (base + 0x4c)
#define IPROC_WRAP_MISC_STATUS_ADDR(base)           (base + 0x58)
#ifdef CONFIG_MACH_HR3
#define USBD_VBUS_GPIO                              7
#else
#define USBD_VBUS_GPIO                              10
#endif
#endif


#define DIR_STR(dir)                        ((dir) == USB_DIR_IN ? "IN" : "OUT")
/* Would be nice if DMA_ADDR_INVALID or similar was defined in dma-mapping.h */
#define DMA_ADDR_INVALID                    (~(dma_addr_t)0)
/* Would be nice if ENOERROR or similar was defined in errno.h */
#define ENOERROR                            0
/* Would be nice if USB_DIR_MASK was defined in usb/ch9.h */
#define USB_DIR_MASK                        USB_ENDPOINT_DIR_MASK
#define USB_DIR_UNKNOWN                     ~USB_DIR_MASK
#define USB_CONTROL_MAX_PACKET_SIZE         64

/* ---- External Variable Declarations ----------------------------------- */
/* ---- External Function Prototypes ------------------------------------- */
/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */
#define BCM_UDC_MODULE_DESCRIPTION          "Broadcom USB Device Controller (UDC) driver"
#define BCM_UDC_MODULE_VERSION              "1.0.0"
#define BCM_DRIVER_DESC                     BCM_UDC_MODULE_DESCRIPTION
#define BCM_DRIVER_VERSION                  BCM_UDC_MODULE_VERSION

/*
 * Definitions for the number of USB Device Controllers (UDC's) supported. Usually there's
 * just 1. Note that numbering is 0 .. (BCM_UDC_CNT_MAX - 1)
 */
#define BCM_UDC_CNT_MAX                     9

/*
 * FRAME_NUM_INVALID is used for ISOC IN transfers for frame alignment.
 * The device specifies the interval at which it wants to do transfers,
 * but the host initiates all transfers. If the interval is some multiple
 * number of frames, the device has no idea which frame in an interval
 * window the host is going to start transfers. This could even be at a
 * point many frames beyond the current window, as the starting point
 * can be very application dependant and subject to an indeterminate
 * amount of latency.
 */
#define FRAME_NUM_INVALID                   (~(unsigned)0)

/*
 * Normally ISOC IN DMA transfers are disabled until such time that
 * an IN token is received from the host so that proper frame number
 * alignment is achieved. See previous comments regarding FRAME_NUM_INVALID.
 * If it desired that frames start being DMA'd w/o this alignment, then
 * define ISOC_IN_XFER_DELAY_DISABLED. If things are not aligned, they
 * should correct themselves when an IN token interrupt is received.
 * See IrqEpInStatusCheck() processing.
 *
 * #define ISOC_IN_XFER_DELAY_DISABLED
 */

/*
 * For IN DMA transfers, problems have been noticed in the UDC h/w when
 * buffer fill mode is used (descriptor length is set to buffer length
 * as opposed to packet length. Only applicable to cases where buffer
 * length is larger than max packet). To enable buffer fill mode for
 * IN transfers, define IN_DMA_BUFFER_FILL_ENABLED.
 *
 * #define IN_DMA_BUFFER_FILL_ENABLED
 */

/* ---- Private Function Prototypes -------------------------------------- */
static void CtrlEpSetupInit(BCM_UDC_EP_t *udcEpP, int status);
static void CtrlEpSetupRx(BCM_UDC_EP_t *udcEpP, struct usb_ctrlrequest *setup);

static void DmaEpInit(BCM_UDC_EP_t *udcEpP);
static void DmaDataInit(BCM_UDC_EP_t *udcEpP);
static void DmaDataFinis(BCM_UDC_EP_t *udcEpP);
static void DmaDataAddReady(BCM_UDC_EP_t *udcEpP);
static void DmaDataRemoveDone(BCM_UDC_EP_t *udcEpP);

static inline BCM_UDC_DMA_DESC_t *DmaDescChainAlloc(BCM_UDC_EP_t *udcEpP);
static inline int DmaDescChainEmpty(BCM_UDC_EP_t *udcEpP);
static inline void DmaDescChainFree(BCM_UDC_EP_t *udcEpP);
static inline int DmaDescChainFull(BCM_UDC_EP_t *udcEpP);
static inline BCM_UDC_DMA_DESC_t *DmaDescChainHead(BCM_UDC_EP_t *udcEpP);
static inline void DmaDescChainReset(BCM_UDC_EP_t *udcEpP);

static void GadgetDevRelease(struct device *dev);
static int GadgetDevRemove(BCM_UDC_t *udcP);

static int GadgetEpEnable(struct usb_ep *ep, const struct usb_endpoint_descriptor *desc);
static int GadgetEpDisable(struct usb_ep *ep);
static struct usb_request *GadgetEpRequestAlloc(struct usb_ep *ep, unsigned gfp_flags);
static void GadgetEpRequestFree(struct usb_ep *ep, struct usb_request *req);
static int GadgetEpRequestQueue(struct usb_ep *ep, struct usb_request *req, unsigned gfp_flags);
static int GadgetEpRequestDequeue(struct usb_ep *ep, struct usb_request *req);
static int GadgetEpSetHalt(struct usb_ep *ep, int value);
static int GadgetEpFifoStatus(struct usb_ep *ep);
static void GadgetEpFifoFlush(struct usb_ep *ep);

static irqreturn_t IrqUdc(int irq, void *context);
static void IrqDev(BCM_UDC_t *udcP, uint32_t irq);
static void IrqDevCfgSet(BCM_UDC_t *udcP);
static void IrqDevIntfSet(BCM_UDC_t *udcP);
static void IrqDevSpeedEnum(BCM_UDC_t *udcP);

static void IrqEp(BCM_UDC_t *udcP, uint32_t irqIn, uint32_t irqOut);
static void IrqEpInStatusCheck(BCM_UDC_EP_t *udcEpP);
static void IrqEpOutStatusCheck(BCM_UDC_EP_t *udcEpP);
static void IrqEpOutSetup(BCM_UDC_EP_t *udcEpP);

static int PlatformDriverProbe(struct platform_device *devP);
static int PlatformDriverRemove(struct platform_device *devP);
static int PlatformDmaAlloc(struct platform_device *platformDevP, BCM_UDC_t *udcP);
static void PlatformDmaFree(struct platform_device *platformDevP, BCM_UDC_t *udcP);

static void ProcFileCreate(void);
static void ProcFileRemove(void);

static void ReqQueueFlush(BCM_UDC_EP_t *udcEpP, int status);
static void ReqXferError(BCM_UDC_EP_t *udcEpP, int status);
static void ReqXferDone(BCM_UDC_EP_t *udcEpP, BCM_UDC_EP_REQ_t *udcEpReqP, int status);
static void ReqXferProcess(BCM_UDC_EP_t *udcEpP);
static void ReqXferAdd(BCM_UDC_EP_t *udcEpP, BCM_UDC_EP_REQ_t *udcEpReqP);

static void UdcOpsFinis(BCM_UDC_t *udcP);
static void UdcOpsInit(BCM_UDC_t *udcP);
static void UdcOpsShutdown(BCM_UDC_t *udcP);
static void UdcOpsStartup(BCM_UDC_t *udcP);
static void UdcOpsDisconnect(BCM_UDC_t *udcP);

static void UdcEpInit(BCM_UDC_t *udcP, unsigned num, const char *name, unsigned dir);
static int UdcEpCfg(BCM_UDC_EP_t *udcEpP, unsigned type, unsigned maxPktSize);

static void UdcFifoRamInit(BCM_UDC_t *udcP);
static int UdcFifoRamAlloc(BCM_UDC_EP_t *udcEpP, unsigned maxPktSize);
static void UdcFifoRamFree(BCM_UDC_EP_t *udcEpP);

static int bcm_udc_start(struct usb_gadget *, struct usb_gadget_driver *);
static int bcm_udc_stop(struct usb_gadget *, struct usb_gadget_driver *);

/* ---- Private Variables ------------------------------------------------ */
BCM_UDC_t *bcmUdcP = NULL;
static void __iomem *usb2d_base = NULL;
static void __iomem *idm_usb2d_base = NULL;
static void __iomem *iproc_wrap_base = NULL;
static void __iomem *icfg_usb2d_base = NULL;

static void iproc_udc_release (struct device *dev) {}
static struct platform_device iproc_udc_pdev = {
    .name   = BCM_UDC_NAME,
    .id     = 0,
    .dev    = {
        .coherent_dma_mask = DMA_BIT_MASK(32),
        .dma_mask = &iproc_udc_pdev.dev.coherent_dma_mask,
        .release = iproc_udc_release,
    },
};

static struct usb_gadget_ops bcm_udc_gadgetDevOps = {
    .pullup             = NULL,
    .udc_start          = bcm_udc_start,
    .udc_stop           = bcm_udc_stop,
};

static struct usb_ep_ops bcm_udc_gadgetEpOps = {
    .enable         = GadgetEpEnable,
    .disable        = GadgetEpDisable,
    .alloc_request  = GadgetEpRequestAlloc,
    .free_request   = GadgetEpRequestFree,
    .queue          = GadgetEpRequestQueue,
    .dequeue        = GadgetEpRequestDequeue,
    .set_halt       = GadgetEpSetHalt,
    .fifo_status    = GadgetEpFifoStatus,
    .fifo_flush     = GadgetEpFifoFlush,
};

/****************************************************************************
 * APIs used by a Gadget driver to attach / detach from the UDC driver.
 ***************************************************************************/
static int bcm_udc_start(struct usb_gadget *gadget,
                         struct usb_gadget_driver *gadget_driver)
{
    unsigned long flags;

    BCM_DEBUG_TRACE("%s : entry\n", __func__);

    if (!bcmUdcP) {
        BCM_KERROR("UDC driver not initialized\n");
        BCM_DEBUG_TRACE("%s : exit on bcmUdcP null\n", __func__);
        return -ENODEV;
    }

    if (!gadget_driver || !gadget_driver->setup ||
        gadget_driver->max_speed < USB_SPEED_FULL) {
        BCM_KERROR( "invalid gadget driver\n" );
        BCM_DEBUG_TRACE( "%s : exit\n", __func__ );
        return -EINVAL;
    }

    spin_lock_irqsave(&bcmUdcP->lock, flags);

    if (bcmUdcP->gadget_driver) {
        spin_unlock_irqrestore(&bcmUdcP->lock, flags);
        BCM_KNOTICE("UDC driver busy\n");
        BCM_DEBUG_TRACE("%s : exit on driver busy\n", __func__);
        return -EBUSY;
    }

    /* Hook up the gadget driver to the UDC controller driver */
    gadget_driver->driver.bus = NULL;
    bcmUdcP->gadget_driver = gadget_driver;
    bcmUdcP->gadget.dev.driver = &gadget_driver->driver;
    bcmUdcP->pullupOn = 1;
    spin_unlock_irqrestore(&bcmUdcP->lock, flags );

    spin_lock_irqsave(&bcmUdcP->lock, flags);
    UdcOpsStartup(bcmUdcP);
    /* un-stop the control endpoint */
    bcmUdcP->ep[0].stopped = 0;
    usbDevHw_DeviceBusConnect();

    usbDevHw_DeviceSetupDone();
    usbDevHw_DeviceDmaEnable();
    spin_unlock_irqrestore(&bcmUdcP->lock, flags);

    BCM_DEBUG_TRACE("%s : exit\n", __func__);

    return ENOERROR;
}

static void UdcOpsShutdownDev(void)
{
    BCM_UDC_EP_t *udcEpP;

    bcmUdcP->ep[0].desc = NULL;
    list_for_each_entry(udcEpP, &bcmUdcP->gadget.ep_list, usb_ep.ep_list) {
        udcEpP->desc = NULL;
    }
    bcmUdcP->gadget.dev.driver = NULL;
    bcmUdcP->gadget_driver = NULL;
}

static int bcm_udc_stop(struct usb_gadget *gadget, struct usb_gadget_driver *gadget_driver)
{
    unsigned long flags;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!bcmUdcP) {
        BCM_KERROR("UDC driver not initialized\n");
        return -ENODEV;
    }

    if (!gadget_driver || gadget_driver != bcmUdcP->gadget_driver ||
        !gadget_driver->unbind) {
        BCM_KERROR( "invalid gadget driver\n" );
        return -EINVAL;
    }

    spin_lock_irqsave(&bcmUdcP->lock, flags);

    bcmUdcP->ep[0].stopped = 1;
    UdcOpsShutdown(bcmUdcP);
    udelay(20);
    bcmUdcP->pullupOn = 0;
    usbDevHw_DeviceBusDisconnect();

    UdcOpsShutdownDev();

    spin_unlock_irqrestore(&bcmUdcP->lock, flags);

    return ENOERROR;
}

/****************************************************************************
 *
 * Platform device level alloc / free of memory used for DMA descriptors.
 * A single block of memory static in size is used for DMA descriptors.
 * Each endpoint has a small number of descriptors for its exclusive use.
 * These are chained in a loop. See bcm_udc_dwc.h and DmaEpInit() for more
 * details.
 *
 ***************************************************************************/
int PlatformDmaAlloc(struct platform_device *platformDevP, BCM_UDC_t *udcP)
{
    udcP->dma.virtualAddr = dma_alloc_coherent(&platformDevP->dev, sizeof(BCM_UDC_DMA_t),
                                                (dma_addr_t *)&udcP->dma.physicalAddr, GFP_KERNEL);

    if (!udcP->dma.virtualAddr) {
        BCM_KERROR("dma_alloc_coherent() failed\n");
        return -ENOMEM;
    }

    return ENOERROR;
}

void PlatformDmaFree(struct platform_device *platformDevP, BCM_UDC_t *udcP)
{
    unsigned num;

    dma_free_coherent(&platformDevP->dev, sizeof(BCM_UDC_DMA_t), udcP->dma.virtualAddr,
                        (dma_addr_t)udcP->dma.physicalAddr);

    for (num = 0; num < BCM_UDC_EP_CNT; num ++) {
        if (udcP->ep[num].dma.alignedBuf) {
            dma_free_coherent(NULL, udcP->ep[num].dma.alignedLen,
                              udcP->ep[num].dma.alignedBuf,
                              udcP->ep[num].dma.alignedAddr);
            udcP->ep[num].dma.alignedBuf = NULL;
        }
    }
}

void GadgetDevRelease(struct device *dev)
{
    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    /* Shutdown the hardware operations */
    usbDevHw_OpsFinis();

    complete(bcmUdcP->devRelease);

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

int GadgetDevRemove(BCM_UDC_t *udcP)
{
    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    usb_del_gadget_udc(&udcP->gadget);
    if (udcP->gadget_driver) {
        return -EBUSY;
    }

    BCM_DEBUG_TRACE("%s : exit\n", __func__);

    return ENOERROR;
}

/****************************************************************************
 * Linux Gadget endpoint operations. See usb_ep_ops in usb_gadget.h.
 ***************************************************************************/
int GadgetEpEnable(struct usb_ep *usb_ep, const struct usb_endpoint_descriptor *desc)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    BCM_UDC_t *udcP;
    unsigned long flags;
    unsigned maxPktSize;
    unsigned xferType;
    int ret = ENOERROR;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep || (udcEpP->bEndpointAddress != desc->bEndpointAddress)) {
        BCM_KERROR("invalid endpoint (%p)\n", usb_ep);
        ret = -EINVAL;
        goto err;
    }

    if (!desc || (desc->bDescriptorType != USB_DT_ENDPOINT)) {
        BCM_KERROR("ep%d: invalid descriptor=%p type=%d\n", udcEpP->num, desc, desc ? desc->bDescriptorType : -1);
        ret = -EINVAL;
        goto err;
    }

    if (desc == udcEpP->desc) {
        BCM_KWARN("ep%d: already enabled with same descriptor\n", udcEpP->num);
        ret = -EEXIST;
        goto err;
    }

    if (udcEpP->desc) {
        BCM_KWARN("ep%d: already enabled with another descriptor\n", udcEpP->num);
        ret = -EBUSY;
        goto err;
    }

    udcP = udcEpP->udcP;

    if (!udcP->gadget_driver || (udcP->gadget.speed == USB_SPEED_UNKNOWN)) {
        BCM_KWARN("%s: invalid device state\n", udcEpP->usb_ep.name);
        ret = -ESHUTDOWN;
        goto err;
    }

    xferType = desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    maxPktSize = le16_to_cpu (desc->wMaxPacketSize) & 0x7FF;

    if (!maxPktSize || (maxPktSize > udcEpP->maxPktSize)) {
        BCM_KERROR("%s: invalid max pkt size: ep=%d desc=%d\n", udcEpP->usb_ep.name, udcEpP->maxPktSize, maxPktSize);
        ret = -ERANGE;
        goto err;
    }

    if ((udcEpP->dir == USB_DIR_IN) && (xferType == USB_ENDPOINT_XFER_ISOC)) {
        if ((desc->bInterval < 1) || (desc->bInterval > 16)) {
            BCM_KERROR("%s: invalid ISOC bInterval=%u\n", udcEpP->usb_ep.name, desc->bInterval);
            ret = -ERANGE;
            goto err;
        }
        /*
         * We don't know when the host will send the first ISO IN request, so we need to set up
         * to capture that event so we can align subsequent transfers to that particular frame
         * number. Also set the frame number increment. The endpoint descriptor specifies this
         * as a power of 2 (2**(n-1)). Translate this into a specific number of frames.
         */
        udcEpP->dma.frameNum = FRAME_NUM_INVALID;
        udcEpP->dma.frameIncr = 1 << (desc->bInterval - 1);
        BCM_DEBUG_ISOC("%s: frameIncr=%d\n", udcEpP->usb_ep.name, udcEpP->dma.frameIncr);
    }

    spin_lock_irqsave(&udcP->lock, flags);

    if (UdcEpCfg(udcEpP, xferType, maxPktSize) != ENOERROR) {
        spin_unlock_irqrestore(&udcP->lock, flags);
        BCM_KERROR("%s: not enough FIFO space\n", udcEpP->usb_ep.name);
        ret = -ENOSPC;
        goto err;
    }

    /** @todo Rework the UdcEpCfg() so it includes usbDevHw_EndptCfgSet() ... */
    usbDevHw_EndptCfgSet(udcEpP->num, usbDevHw_DeviceCfgNum());

    udcEpP->desc = desc;
    udcEpP->stopped = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
    udcEpP->usb_ep.maxpacket = maxPktSize;
#else
    usb_ep_set_maxpacket_limit(&udcEpP->usb_ep, maxPktSize);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) */

    spin_unlock_irqrestore(&udcP->lock, flags);

    BCM_DEBUG_EP("%s: enabled: type=0x%x, maxPktSize=%d\n", udcEpP->usb_ep.name, xferType, maxPktSize);

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
    return ret;
}

int GadgetEpDisable(struct usb_ep *usb_ep)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    BCM_UDC_t *udcP;
    unsigned long flags;
    int ret = ENOERROR;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep) {
        BCM_KERROR("invalid endpoint\n");
        ret = -EINVAL;
        goto err;
    }

    if (!udcEpP->desc) {
        BCM_DEBUG_EP("%s: already disabled\n", udcEpP->usb_ep.name);
        goto err;
    }

    udcP = udcEpP->udcP;

    /** @todo Really need to do this around udcEpP->desc check */
    spin_lock_irqsave(&udcP->lock, flags);

    ReqQueueFlush(udcEpP, -ESHUTDOWN);

    usbDevHw_EndptIrqDisable(udcEpP->num, udcEpP->dir);
    udcEpP->desc = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
    udcEpP->usb_ep.maxpacket = udcEpP->maxPktSize;
#else
    usb_ep_set_maxpacket_limit(&udcEpP->usb_ep, udcEpP->maxPktSize);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) */
    UdcFifoRamFree(udcEpP);

    spin_unlock_irqrestore(&udcP->lock, flags);

    BCM_DEBUG_EP("%s: disabled\n", udcEpP->usb_ep.name);

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
    return ret;
}

struct usb_request * GadgetEpRequestAlloc(struct usb_ep *usb_ep, unsigned gfp_flags)
{
    BCM_UDC_EP_REQ_t *udcEpReqP;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep) {
        return NULL;
    }

    if ((udcEpReqP = kzalloc(sizeof(*udcEpReqP), gfp_flags)) != NULL) {
        /*
         * Set the usb_req.dma to DMA_ADDR_INVALID so it can be determined if the usb_req.buf needs
         * to be mapped when the request is subsequently queued.
         */
        INIT_LIST_HEAD(&udcEpReqP->listNode);
        udcEpReqP->usb_req.dma = DMA_ADDR_INVALID;

        BCM_DEBUG_MEM("%s: req=0x%p flags=0x%x\n", usb_ep->name, udcEpReqP, gfp_flags);
        BCM_DEBUG_TRACE("%s : exit\n", __func__);
        return &udcEpReqP->usb_req;
    }

    BCM_KERROR("kmalloc() failed\n");
    BCM_DEBUG_TRACE("%s : exit\n", __func__);

    return NULL;
}

void  GadgetEpRequestFree(struct usb_ep *usb_ep, struct usb_request *usb_req)
{
    BCM_UDC_EP_REQ_t *udcEpReqP = container_of(usb_req, BCM_UDC_EP_REQ_t, usb_req);

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (usb_req) {
        BCM_DEBUG_MEM("%s: req=0x%p\n", usb_ep->name, udcEpReqP);
        kfree(udcEpReqP);
    }

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

int GadgetEpRequestQueue(struct usb_ep *usb_ep, struct usb_request *usb_req, unsigned gfp_flags)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    BCM_UDC_EP_REQ_t *udcEpReqP = container_of(usb_req, BCM_UDC_EP_REQ_t, usb_req);
    BCM_UDC_t *udcP;
    unsigned long flags;
    int ret = ENOERROR;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep || !usb_req || !udcEpReqP->usb_req.complete || !udcEpReqP->usb_req.buf || !list_empty(&udcEpReqP->listNode)) {
        BCM_KERROR("invalid request\n");
        BCM_DEBUG_REQ("usb_ep=0x%p udc_req=0x%p usb_req=0x%p usb_req.complete=0x%p usb_req.buf=0x%p\n",
                        usb_ep, udcEpReqP, usb_req, udcEpReqP->usb_req.complete, udcEpReqP->usb_req.buf);
        ret = -EINVAL;
        goto err;
    }

    if (!udcEpP->desc && (udcEpP->num != 0)) {
        BCM_KERROR("%s: invalid EP state\n", udcEpP->usb_ep.name);
        ret = -EFAULT;
        goto err;
    }

    if ((udcEpP->type == USB_ENDPOINT_XFER_CONTROL) && !list_empty(&udcEpP->listQueue)) {
        BCM_KERROR("%s: CTRL EP queue not empty\n", udcEpP->usb_ep.name);
        ret = -EPERM;
        goto err;
    }

    if (usb_req->length > 16384 /* FSG_BUFLEN */) {
        /** @todo DMA descriptors have a 16-bit length field. Only really applicable if doing
         * buffer fill mode. Cannot really do this for OUT transfers (too many issues with
         * validating buffer sizes), and things seem to be broken for IN transfers.
         */
        BCM_KERROR("%s: request too big, length=%u\n", udcEpP->usb_ep.name, usb_req->length);
        ret = -E2BIG;
        goto err;
    }

    /*
     * Restrict ISOC IN requests to the max packet size. Assumption is that it does not make
     * much sense to have more than one interval's (scheduled bandwidth's) worth of data.
     */
    /** @todo Support for multiple packets per frame (high speed/bandwidth). These could have up to 3
     * packets of max length per uframe.
     */
    if ((udcEpP->type == USB_ENDPOINT_XFER_ISOC) && (udcEpP->dir == USB_DIR_IN) && (usb_req->length > udcEpP->usb_ep.maxpacket)) {
        BCM_KERROR("%s: request > scheduled bandwidth, length=%u\n", udcEpP->usb_ep.name, usb_req->length);
        ret = -EFBIG;
        goto err;
    }

    udcP = udcEpP->udcP;

    if (!udcP->gadget_driver || (udcP->gadget.speed == USB_SPEED_UNKNOWN)) {
        BCM_KWARN("%s: invalid device state\n", udcEpP->usb_ep.name);
        ret = -ESHUTDOWN;
        goto err;
    }

    if (((unsigned long)udcEpReqP->usb_req.buf) & 0x3UL) {
        /*
         * The DMA buffer does not have the alignment required by the hardware. We keep an endpoint level
         * buffer available to handle this situation if it arises. If we don't currently have one available
         * for this purpose, or if the current one is not large enough, then allocate a new one. Since
         * we only have one buffer, we won't copy into the buffer until we are ready to do the DMA transfer.
         * Mark the request as needing this alignment (copy).
         */
        if ((udcEpP->dma.alignedBuf != NULL) && (udcEpP->dma.alignedLen < udcEpReqP->usb_req.length)) {
            BCM_DEBUG_MEM("%s: dma_free_coherent(): addr=0x%x length=%u\n", udcEpP->usb_ep.name, udcEpP->dma.alignedAddr, udcEpP->dma.alignedLen);
            dma_free_coherent(NULL, udcEpP->dma.alignedLen, udcEpP->dma.alignedBuf, udcEpP->dma.alignedAddr);
            udcEpP->dma.alignedBuf = NULL;
        }

        if (udcEpP->dma.alignedBuf == NULL) {
            udcEpP->dma.alignedLen = udcEpReqP->usb_req.length;
            udcEpP->dma.alignedBuf = dma_alloc_coherent(NULL, udcEpP->dma.alignedLen, &(udcEpP->dma.alignedAddr), GFP_KERNEL);
            BCM_DEBUG_MEM("%s: dma_alloc_coherent(): addr=0x%x length=%u\n", udcEpP->usb_ep.name, udcEpP->dma.alignedAddr, udcEpP->dma.alignedLen);
        }

        if (udcEpP->dma.alignedBuf == NULL) {
            BCM_KERROR("%s: dma_alloc_coherent() failed, length=%u\n", udcEpP->usb_ep.name, usb_req->length);
            ret = -ENOMEM;
            goto err;
        }

        udcEpReqP->dmaAligned = 1;
    } else if ((udcEpReqP->usb_req.dma == DMA_ADDR_INVALID) || (udcEpReqP->usb_req.dma == 0)) {
        /* A physical address was not provided for the DMA buffer, so request it.
         */
        udcEpReqP->dmaMapped = 1;
        udcEpReqP->usb_req.dma = dma_map_single(udcEpP->udcP->gadget.dev.parent,
                                                    udcEpReqP->usb_req.buf,
                                                    udcEpReqP->usb_req.length,
                                                    (udcEpP->dir == USB_DIR_IN ? DMA_TO_DEVICE : DMA_FROM_DEVICE));
    }

    spin_lock_irqsave(&udcP->lock, flags);

    udcEpReqP->usb_req.status = -EINPROGRESS;
    udcEpReqP->usb_req.actual = 0;

    BCM_DEBUG_REQ("%s: req=0x%p buf=0x%p dma=0x%x len=%d\n", udcEpP->usb_ep.name, usb_req, usb_req->buf, udcEpReqP->usb_req.dma, usb_req->length);

    if ((udcEpP->type == USB_ENDPOINT_XFER_CONTROL) && (udcEpP->dir == USB_DIR_OUT) && (udcEpReqP->usb_req.length == 0)) {
        /*
         * This might happen if gadget driver decides to send zero length packet (ZLP) during STATUS phase
         * of a control transfer. This may happen for the cases where there is not a DATA phase. Just consider
         * things complete. ZLP will be issued by hardware. See the handling of SETUP packets for more details
         * on control transfer processing.
         */
        ReqXferDone(udcEpP, udcEpReqP, ENOERROR);
    } else {
        if (udcEpReqP->usb_req.length == 0) {
            udcEpReqP->usb_req.zero = 1;
        }
        ReqXferAdd(udcEpP, udcEpReqP);
    }

    spin_unlock_irqrestore(&udcP->lock, flags);

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
    return ret;
}

int GadgetEpRequestDequeue(struct usb_ep *usb_ep, struct usb_request *usb_req)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    BCM_UDC_EP_REQ_t *udcEpReqP = container_of(usb_req, BCM_UDC_EP_REQ_t, usb_req);
    unsigned long flags;
    int ret = ENOERROR;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep || !usb_req) {
        BCM_KERROR("invalid request\n");
        ret = -EINVAL;
        goto err;
    }

    spin_lock_irqsave(&udcEpP->udcP->lock, flags);

    /* Make sure it's actually queued on this endpoint */
    list_for_each_entry(udcEpReqP, &udcEpP->listQueue, listNode) {
        if (&udcEpReqP->usb_req == usb_req) {
            break;
        }
    }

    if (&udcEpReqP->usb_req != usb_req) {
        spin_unlock_irqrestore(&udcEpP->udcP->lock, flags);
        BCM_KNOTICE("%s: request not queued\n", udcEpP->usb_ep.name);

        ret = -ENOLINK;
        goto err;
    }

    /** @todo Handle case where the request is in progress, or completed but not dequeued */

    ReqXferDone(udcEpP, udcEpReqP, -ECONNRESET);
    spin_unlock_irqrestore(&udcEpP->udcP->lock, flags);

    BCM_DEBUG_REQ("%s: req=0x%p\n", udcEpP->usb_ep.name, usb_req);

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
    return ret;
}

int GadgetEpSetHalt(struct usb_ep *usb_ep, int haltEnable)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    unsigned long flags;
    int ret = ENOERROR;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep) {
        BCM_KERROR("invalid request\n");
        ret = -EINVAL;
        goto err;
    }

    if (udcEpP->type == USB_ENDPOINT_XFER_ISOC) {
        BCM_KWARN("%s: ISO HALT operations not supported\n", udcEpP->usb_ep.name);
        ret = -EOPNOTSUPP;
        goto err;
    }

    if (haltEnable && (udcEpP->dir == USB_DIR_IN) && !list_empty(&udcEpP->listQueue)) {
        /* Only allow halt on an IN EP if its queue is empty */
        BCM_KNOTICE("%s: IN queue not empty\n", udcEpP->usb_ep.name);
        ret = -EAGAIN;
        goto err;
    }

    if (!haltEnable && (udcEpP->type == USB_ENDPOINT_XFER_CONTROL)) {
        /*
         * Halt clear for a control EP should only be handled as part of the subsequent SETUP
         * exchange that occurs after the Halt was set.
         */
        BCM_KWARN("%s: CTRL HALT clear\n", udcEpP->usb_ep.name);
        ret = -EPROTO;
        goto err;
    }

    spin_lock_irqsave(&udcEpP->udcP->lock, flags);

    if (!haltEnable) {
        usbDevHw_EndptStallDisable(udcEpP->num, udcEpP->dir);
    } else if (udcEpP->type != USB_ENDPOINT_XFER_CONTROL) {
        usbDevHw_EndptStallEnable(udcEpP->num, udcEpP->dir);
    } else {
        usbDevHw_EndptStallEnable(udcEpP->num, USB_DIR_IN);
        usbDevHw_EndptStallEnable(udcEpP->num, USB_DIR_OUT);
    }

    spin_unlock_irqrestore(&udcEpP->udcP->lock, flags);
#ifdef CONFIG_ARCH_IPROC
    mdelay(2);
#endif

    BCM_DEBUG_EP("%s: HALT %s done\n", udcEpP->usb_ep.name, haltEnable ? "SET" : "CLR");

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
    return ret;
}

int GadgetEpFifoStatus(struct usb_ep *usb_ep)
{
    /*
     * The DWC UDC core doesn't have a mechanism for determining the number of bytes
     * currently in a FIFO. The best that can be done is determine whether or not a
     * FIFO is empty. However, for the situation where a single Rx FIFO is being
     * used for all endpoints, if cannot be determined which OUT and CTRL EP's are
     * affected if the Rx FIFO is not empty.
     */
    return -EOPNOTSUPP;
}


void GadgetEpFifoFlush(struct usb_ep *usb_ep)
{
    BCM_UDC_EP_t *udcEpP = container_of(usb_ep, BCM_UDC_EP_t, usb_ep);
    unsigned long flags;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    if (!usb_ep) {
        BCM_KERROR("invalid request\n");
        goto err;
    }

    if (udcEpP->type == USB_ENDPOINT_XFER_CONTROL) {
        /*
         * FIFO flush for a control EP does not make any sense. The SETUP protocol
         * should eliminate the need to flush.
         */
        BCM_KWARN("%s: CTRL FIFO flush\n", udcEpP->usb_ep.name);
        goto err;
    }

    if (usbDevHw_EndptFifoEmpty(udcEpP->num, udcEpP->dir)) {
        BCM_DEBUG_EP("%s: FIFO empty\n", udcEpP->usb_ep.name);
        goto err;
    }

    spin_lock_irqsave(&udcEpP->udcP->lock, flags);

    /** @todo There may be some issues for single Rx FIFO and subsequent EP0 operations */
    /** @todo The UDC doc'n also mentions having to set DEVNAK bit and clearing it later. */
    /* FIFO flush will need to be disabled later on. E.g. when a EP request is queued.
     */
    usbDevHw_EndptFifoFlushEnable(udcEpP->num, udcEpP->dir);

    spin_unlock_irqrestore(&udcEpP->udcP->lock, flags);

    BCM_DEBUG_EP("%s: FIFO flush enabled\n", udcEpP->usb_ep.name);

err:
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

/***************************************************************************
 * Routines for debug dump of DMA descriptors
 **************************************************************************/
#ifdef DEBUG
void DmaDump(BCM_UDC_t *udcP)
{
    unsigned i;

    for (i = 0; i < BCM_UDC_EP_CNT; i++) {
        DmaDumpEp(&udcP->ep[i]);
    }
}

void DmaDumpDesc(char *label, BCM_UDC_DMA_DESC_t *virt, BCM_UDC_DMA_DESC_t *phys)
{
    BCM_DEBUG_DMA("%s virt=0x%p phys=0x%p: 0x%08x 0x%08x 0x%08x", label, virt, phys, virt->status, virt->reserved, virt->bufAddr);
}

void DmaDumpEp(BCM_UDC_EP_t *udcEpP)
{
    unsigned i;

    BCM_DEBUG_DMA("EP %d DMA\n", udcEpP->num);
    BCM_DEBUG_DMA("   setup\n");
    DmaDumpDesc("       ", (BCM_UDC_DMA_DESC_t *)&udcEpP->dma.virtualAddr->setup, (BCM_UDC_DMA_DESC_t *)&udcEpP->dma.physicalAddr->setup);
    BCM_DEBUG_DMA("   desc\n");

    for (i = 0; i < BCM_UDC_EP_DMA_DESC_CNT; i++) {
        DmaDumpDesc("       ", &udcEpP->dma.virtualAddr->desc[i], &udcEpP->dma.physicalAddr->desc[i]);

        /* Don't bother displaying entries beyond the last. */
        if (REG_RD(udcEpP->dma.virtualAddr->desc[i].status) & usbDevHw_REG_DMA_STATUS_LAST_DESC) {
            break;
        }
    }
}
#endif /* DEBUG */
/****************************************************************************
 * Initialization of DMA descriptors at the endpoint level.
 ***************************************************************************/
void DmaEpInit(BCM_UDC_EP_t *udcEpP)
{
    unsigned i;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);
    BCM_DEBUG_DMA("%s: num=%u\n", udcEpP->usb_ep.name, udcEpP->num);

    /** @todo shorten names to virtAddr physAddr?? */
    udcEpP->dma.virtualAddr = &udcEpP->udcP->dma.virtualAddr->ep[ udcEpP->num ];
    udcEpP->dma.physicalAddr = &udcEpP->udcP->dma.physicalAddr->ep[ udcEpP->num ];

    /*
     * Control endpoints only do setup in the OUT direction, so only need to set the
     * buffer address for that direction. The buffer is set, even if not a control
     * endpoint, just to simplify things. There's no harm with this.
     */
    udcEpP->dma.virtualAddr->setup.status = cpu_to_le32(usbDevHw_REG_DMA_STATUS_BUF_HOST_BUSY);
    wmb();
    usbDevHw_EndptDmaSetupBufAddrSet(udcEpP->num, USB_DIR_OUT, &udcEpP->dma.physicalAddr->setup);

    /*
     * Take ownership of the DMA descriptors, and chain them in a loop. This allows a small number
     * descriptors to be used for requests. Need to have the DWC DMA Descriptor Update option enabled
     * in the device control register in order to do this. When a transfer for a descriptor completes,
     * the descriptor will get re-used if there's still data left in a request to transfer. See the
     * DmaDataRemoveDone() and DmaDataAddReady() routines.
     */
     /** @todo Put these in endpoint context?? */
    for (i = 0; i < BCM_UDC_EP_DMA_DESC_CNT; i++) {
        udcEpP->dma.virtualAddr->desc[i].status = cpu_to_le32(usbDevHw_REG_DMA_STATUS_BUF_HOST_BUSY);
        wmb();
        udcEpP->dma.virtualAddr->desc[i].nextDescAddr = cpu_to_le32((uint32_t)&udcEpP->dma.physicalAddr->desc[i+1]);
    }
    udcEpP->dma.virtualAddr->desc[(BCM_UDC_EP_DMA_DESC_CNT - 1)].nextDescAddr = cpu_to_le32((uint32_t)&udcEpP->dma.physicalAddr->desc[0]);

    /*
     * To simplify things, register the descriptor chain in both directions. Control endpoints are the
     * only type that will be transferring in both directions, but they will only be transferring in one
     * direction at a time, so should not be any issues with using the same descriptor set for both directions.
     * For single direction endpoints, the other direction will not be used.
     */

    usbDevHw_EndptDmaDataDescAddrSet(udcEpP->num, USB_DIR_OUT, &udcEpP->dma.physicalAddr->desc[0]);
    usbDevHw_EndptDmaDataDescAddrSet(udcEpP->num, USB_DIR_IN,  &udcEpP->dma.physicalAddr->desc[0]);

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

/****************************************************************************
 * DMA descriptor chain routines.
 *
 *  DmaDescChainReset - Initialize chain in preparation for transfer
 *  DmaDescChainFull - Indicates if no descriptors in chain for available for use.
 *  DmaDescChainAlloc - Get next free descriptor for use. Have to check if chain not full first.
 *  DmaDescChainEmpty - Indicates if no descriptors in the chain are being used.
 *  DmaDescChainHead - Pointer to 1st entry in chain. Have to check if chain not empty first.
 *  DmaDescChainFree - Frees up 1st entry for use. Only do this if DMA for this descriptor has completed.
 *
 ***************************************************************************/
inline BCM_UDC_DMA_DESC_t *DmaDescChainAlloc(BCM_UDC_EP_t *udcEpP)
{
    unsigned idx;

    idx = udcEpP->dma.addIndex++;

    return &udcEpP->dma.virtualAddr->desc[BCM_UDC_EP_DMA_DESC_IDX(idx)];
}

inline int DmaDescChainEmpty(BCM_UDC_EP_t *udcEpP)
{
    return udcEpP->dma.addIndex == udcEpP->dma.removeIndex;
}

inline void DmaDescChainFree(BCM_UDC_EP_t *udcEpP)
{
    udcEpP->dma.removeIndex++;
}

inline int DmaDescChainFull(BCM_UDC_EP_t *udcEpP)
{
    return (!DmaDescChainEmpty(udcEpP) && (BCM_UDC_EP_DMA_DESC_IDX(udcEpP->dma.addIndex) == BCM_UDC_EP_DMA_DESC_IDX(udcEpP->dma.removeIndex)));
}

inline BCM_UDC_DMA_DESC_t *DmaDescChainHead(BCM_UDC_EP_t *udcEpP)
{
    return (&udcEpP->dma.virtualAddr->desc[BCM_UDC_EP_DMA_DESC_IDX(udcEpP->dma.removeIndex)]);
}

inline void DmaDescChainReset(BCM_UDC_EP_t *udcEpP)
{
    udcEpP->dma.addIndex = 0;
    udcEpP->dma.removeIndex = 0;
}

/****************************************************************************
 * DMA data routines.
 *
 * A gadget usb_request buf is used for the data. The entire buf contents may
 * or may not fit into the descriptor chain at once. When the DMA transfer
 * associated with a descriptor completes, the descriptor is re-used to add
 * more segments of the usb_request to the chain as necessary.
 *
 *  DmaDataInit - Initialization in preparation for DMA of usb_request.
 *  DmaDataAddReady - Adds usb_request segments into DMA chain until full or no segments left
 *  DmaDataRemoveDone - Removes usb_request segments from DMA chain that have completed transfer
 *  DmaDataFinis - Final stage of DMA of the usb_request
 *
 ***************************************************************************/
void DmaDataInit(BCM_UDC_EP_t *udcEpP)
{
    BCM_UDC_EP_REQ_t *udcEpReqP;

    BCM_DEBUG_TRACE("enter: %s\n", __func__);

    udcEpReqP = list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode);

    if (udcEpReqP->dmaAligned) {
        /*
         * This buffer needs to be aligned in order to DMA. We do this by copying into a special buffer we
         * have for this purpose. Save the original DMA physical address so it can be restored later.
         * This may not be used, but we'll do it anyways. Then set the DMA address to the aligned buffer
         * address. Only the DMA physical address is used for the transfers, so the original buffer virtual
         * address does not need to be changed. Then copy the data into the aligned buffer.
         */
        /** @todo Really only need to do the memcpy for IN data */

        udcEpReqP->dmaAddrOrig = udcEpReqP->usb_req.dma;
        udcEpReqP->usb_req.dma = udcEpP->dma.alignedAddr;
        memcpy(udcEpP->dma.alignedBuf, udcEpReqP->usb_req.buf, udcEpReqP->usb_req.length);
    }

    udcEpP->dma.done = 0;
    udcEpP->dma.lengthDone = 0;
    udcEpP->dma.lengthToDo = udcEpP->dma.usb_req->length;
    udcEpP->dma.bufAddr = udcEpP->dma.usb_req->dma;
    udcEpP->dma.status = usbDevHw_REG_DMA_STATUS_RX_SUCCESS;

    if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type != USB_ENDPOINT_XFER_ISOC)) {
        /*
         * For IN transfers, do not need to segment the buffer into max packet portions
         * for the DMA descriptors. The hardware will automatically segment into max
         * packet sizes as necessary.
         */

#ifdef IN_DMA_BUFFER_FILL_ENABLED
        udcEpP->dma.lengthBufMax = udcEpP->dma.usb_req->length;
#else
        udcEpP->dma.lengthBufMax = udcEpP->usb_ep.maxpacket;
#endif

#ifdef BCM_UDC_IN_TX_MAX
        udcEpP->dma.lengthBufMax = BCM_UDC_IN_TX_MAX;
#endif

        /*
         * If the request is of zero length, then force the zero flag so DmaDataAddReady()
         * will queue the request. Conversely, if the gadget has set the zero flag, leave
         * it set only if it is needed (request length is a multiple of maxpacket)
         */
        if (udcEpP->dma.usb_req->length == 0) {
            udcEpP->dma.usb_req->zero = 1;
            udcEpP->dma.lengthBufMax = udcEpP->usb_ep.maxpacket;
        } else if (udcEpP->dma.usb_req->zero) {
            udcEpP->dma.usb_req->zero = (udcEpP->dma.usb_req->length % udcEpP->usb_ep.maxpacket) ? 0 : 1;
        }
    } else {
        udcEpP->dma.lengthBufMax = udcEpP->usb_ep.maxpacket;
    }

    DmaDescChainReset(udcEpP);

    BCM_DEBUG_DMA("%s: todo=%d bufMax=%d buf=0x%x add=0x%x remove=0x%x\n",
                    udcEpP->usb_ep.name, udcEpP->dma.lengthToDo,
                    udcEpP->dma.lengthBufMax, udcEpP->dma.bufAddr, udcEpP->dma.addIndex, udcEpP->dma.removeIndex);

    usbDevHw_EndptIrqEnable(udcEpP->num, udcEpP->dir);

    BCM_DEBUG_TRACE("exit: %s\n", __func__);
}

void DmaDataFinis(BCM_UDC_EP_t *udcEpP)
{
    BCM_UDC_EP_REQ_t *udcEpReqP;

    BCM_DEBUG_TRACE("enter: %s\n", __func__);

    usbDevHw_EndptIrqDisable(udcEpP->num, udcEpP->dir);
    usbDevHw_EndptDmaDisable(udcEpP->num, udcEpP->dir);

    udcEpReqP = list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode);

    if (udcEpReqP->dmaAligned) {
        /*
         * The original request buffer was not aligned properly, so a special buffer was used
         * for the transfer. Copy the aligned buffer contents into the original. Also restore
         * the original dma physical address.
         */
        /** @todo Really only need to do the memcpy for OUT setup/data */
        memcpy(udcEpReqP->usb_req.buf, udcEpP->dma.alignedBuf, udcEpReqP->usb_req.length);
        udcEpReqP->usb_req.dma = udcEpReqP->dmaAddrOrig;
    }

    BCM_DEBUG_DMA("%s: udcEpReqP=0x%x buf=0x%x dma=0x%x actual=%u\n",
                    udcEpP->usb_ep.name,
                    (unsigned int)udcEpReqP,
                    (unsigned int)udcEpReqP->usb_req.buf,
                    (unsigned int)udcEpReqP->usb_req.dma,
                    (unsigned int)udcEpReqP->usb_req.actual);

    BCM_DEBUG_TRACE("%s: exit\n", __func__);
}

void DmaDataAddReady(BCM_UDC_EP_t *udcEpP)
{
    volatile BCM_UDC_DMA_DESC_t *dmaDescP = NULL;
    uint32_t status;
    unsigned len;
    int enable_dma = 0;

    BCM_DEBUG_TRACE("enter: %s\n", __func__);

    /*
     * DMA must be disabled while this loop is running, as multi-descriptor transfers
     * will have the descriptor chain in an intermediate state until the last descriptor
     * is written and the chain terminated.
     */
    if (usbDevHw_DeviceDmaEnabled()) {
        enable_dma = 1;
        usbDevHw_DeviceDmaDisable();
    }

    if (!udcEpP->dma.lengthToDo) {
        udcEpP->dma.usb_req->zero = 1;
    }

    /*
     * Will only have one request in the chain at a time. Add request segments to the
     * chain until all parts of the request have been put in the chain or the chain
     * has no more room.
     */
    while (!DmaDescChainFull(udcEpP) && (udcEpP->dma.lengthToDo || udcEpP->dma.usb_req->zero)) {
        /*
         * Get the next descriptor in the chain, and then fill the descriptor contents as needed.
         * Do not set the descriptor buffer status to ready until last to ensure there's no
         * contention with the hardware.
         */
        dmaDescP = DmaDescChainAlloc(udcEpP);

        len = udcEpP->dma.lengthToDo < udcEpP->dma.lengthBufMax ? udcEpP->dma.lengthToDo : udcEpP->dma.lengthBufMax;
        udcEpP->dma.lengthToDo -= len;

        status = 0;

        if (len < udcEpP->dma.lengthBufMax) {
            /*
             * If this segment is less than the max, then it is the last segment. There's no need to
             * send a closing ZLP, although this segment might be a ZLP. Regardless, clear the ZLP flag
             * to ensure that the processing of this request finishes. Also set the end of the descriptor
             * chain.
             */
            udcEpP->dma.usb_req->zero = 0;
            status |= usbDevHw_REG_DMA_STATUS_LAST_DESC;
        } else if ((udcEpP->dma.lengthToDo == 0) && !udcEpP->dma.usb_req->zero) {
            /*
             * Segment is of the max packet length. Since there's nothing left, it has to also be the last
             * last segment. No closing ZLP segment requested, just set the end of the descriptor chain.
             */
            status |= usbDevHw_REG_DMA_STATUS_LAST_DESC;
        }

        if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC)) {
            /*
             * Increment the frame number for transmit, then use it for the next packet. The frame number
             * may get larger than its 13-bit size, but the mask will handle the wrap-around so we don't
             * need to add checks for this condition. E.g. 0x7ff + 1 = 0x800. 0x800 & 0x7ff = 0 which
             * is the next number in the sequence.
             */
            /** @todo Handle ISOC PIDs and frame numbers used with HS high bandwidth transfers */
            /** @todo Might not need to set the last descriptor status. Currently restricting
             * IN ISOC transfers to the max packet size.
             */
            status |= usbDevHw_REG_DMA_STATUS_LAST_DESC;

            udcEpP->dma.frameNum += udcEpP->dma.frameIncr;
            BCM_DEBUG_ISOC("%s: DMA start: frameNum=%d.%d\n", udcEpP->usb_ep.name, (udcEpP->dma.frameNum >> 3), (udcEpP->dma.frameNum & 0x7));
            status |= ((udcEpP->dma.frameNum << usbDevHw_REG_DMA_STATUS_FRAME_NUM_SHIFT) & usbDevHw_REG_DMA_STATUS_FRAME_NUM_MASK);
        }

        REG_WR(dmaDescP->bufAddr, udcEpP->dma.bufAddr);
        status |= (len << usbDevHw_REG_DMA_STATUS_BYTE_CNT_SHIFT);
        REG_WR(dmaDescP->status, status | usbDevHw_REG_DMA_STATUS_BUF_HOST_READY);
        wmb();
        BCM_DEBUG_DMA("%s: desc=0x%p status=0x%08x bufAddr=0x%08x len=%d add=0x%x\n",
                        udcEpP->usb_ep.name, dmaDescP, REG_RD(dmaDescP->status), REG_RD(dmaDescP->bufAddr), len, udcEpP->dma.addIndex);
        udcEpP->dma.bufAddr += len;

        if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC)) {
            /* With ISOC transfers, only enable one DMA descriptors at a time.
             */
            /** @todo Determine if FIFO will overflow. If it does not, then can remove this check.
             * This may not even be an issue if the buffer size is restricted to the max packet size
             * when a request is submitted to the endpoint.
             */
            break;
        }
    }
    /* Set LAST bit on last descriptor we've configured */
    if (dmaDescP) {
        REG_MOD_OR(dmaDescP->status, usbDevHw_REG_DMA_STATUS_LAST_DESC);
    }

    if (enable_dma) {
        usbDevHw_DeviceDmaEnable();
    }

    BCM_DEBUG_TRACE("exit: %s\n", __func__);
}

void DmaDataRemoveDone(BCM_UDC_EP_t *udcEpP)
{
    volatile BCM_UDC_DMA_DESC_t *dmaDescP;
    uint32_t status;
    unsigned len;

    BCM_DEBUG_TRACE("enter: %s\n", __func__);

    /*
     * Will only have one request in the chain at a time. Remove any completed
     * request segments from the chain so any segments awaiting transfer can
     * be put in the chain.
     */
    while (!DmaDescChainEmpty(udcEpP)) {
        /*
         * Examine the first entry in the chain. If its status is not done, then there's
         * nothing to remove.
         */
        dmaDescP = DmaDescChainHead(udcEpP);

        if ((REG_RD(dmaDescP->status) & usbDevHw_REG_DMA_STATUS_BUF_MASK) != usbDevHw_REG_DMA_STATUS_BUF_DMA_DONE) {
            BCM_DEBUG_DMA("%s: not done: desc=0x%p status=0x%x bufAddr=0x%08x add=%d remove=0x%x\n",
                            udcEpP->usb_ep.name, dmaDescP, REG_RD(dmaDescP->status), REG_RD(dmaDescP->bufAddr), udcEpP->dma.addIndex, udcEpP->dma.removeIndex);
            break;
        }

        /*
         * The transfer of this request segment has completed. Save the status info and then
         * take ownership of the descriptor. It is simpler to do this than modifying parts of
         * the descriptor in order to take ownership. Don't put the descriptor back in the chain
         * until all info affected by the status has been updated, just to be safe.
         */
        status = REG_RD(dmaDescP->status);
        REG_WR(dmaDescP->status, usbDevHw_REG_DMA_STATUS_BUF_HOST_BUSY);
        wmb();

        len = (status & usbDevHw_REG_DMA_STATUS_NON_ISO_BYTE_CNT_MASK) >> usbDevHw_REG_DMA_STATUS_NON_ISO_BYTE_CNT_SHIFT;

        /* RX: For multiple descriptors, len is cumulative, not absolute.
         * RX: So only adjust the dma fields when we get to the last descriptor
         * TX: Each descriptor entry is absolute, count them all
         */
        if ((udcEpP->dir == USB_DIR_IN) || (status & usbDevHw_REG_DMA_STATUS_LAST_DESC)) {
            udcEpP->dma.lengthDone += len;
            udcEpP->dma.usb_req->actual += len;
        }

        if ((status & usbDevHw_REG_DMA_STATUS_RX_MASK) != usbDevHw_REG_DMA_STATUS_RX_SUCCESS) {
            udcEpP->dma.status = status & usbDevHw_REG_DMA_STATUS_RX_MASK;
            udcEpP->dma.usb_req->status = -EIO;
            BCM_KWARN("%s: DMA error: desc=0x%p status=0x%x len=%d add=0x%x remove=0x%x\n",
                        udcEpP->usb_ep.name, dmaDescP, status, len, udcEpP->dma.addIndex, udcEpP->dma.removeIndex);
        }

        if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC)){
            /** @todo Determine if this special processing needs to be done. May not to do this if the
             * buffer size is restricted to the max packet size when a request is submitted to the endpoint.
             */
            if (udcEpP->dma.usb_req->actual == udcEpP->dma.usb_req->length) {
                udcEpP->dma.usb_req->status = ENOERROR;
            }
            DmaDescChainReset(udcEpP);
        } else {
            DmaDescChainFree(udcEpP);
        }

        BCM_DEBUG_DMA("%s: desc=0x%p status=0x%x bufAddr=0x%08x len=%d remove=0x%x\n",
                        udcEpP->usb_ep.name, dmaDescP, status, REG_RD(dmaDescP->bufAddr), len, udcEpP->dma.removeIndex);
    }

    /* When last segment processed, update status if there has not been an error */
    if (!udcEpP->dma.lengthToDo && (udcEpP->dma.usb_req->status == -EINPROGRESS)) {
        udcEpP->dma.usb_req->status = ENOERROR;
    }

    BCM_DEBUG_TRACE("exit: %s\n", __func__);
}

/***************************************************************************
 * UDC Operations routines.
 *
 *  UdcOpsInit - Initialization of the UDC in preparation for use by Gadget driver.
 *  UdcOpsStartup - Start UDC operations. Happens after a Gadget driver attaches.
 *  UdcOpsShutdown - Stop UDC operations. Happens after a Gadget driver detaches.
 *  UdcOpsFinis - Finish / terminate all UDC operations
 *
 ***************************************************************************/
static void UdcOpsFinis(BCM_UDC_t *udcP)
{
    /** @todo Anything need to be done here?? */
}

static void UdcOpsInit(BCM_UDC_t *udcP)
{
    BCM_DEBUG_TRACE("%s : enter\n", __func__);
    BCM_DEBUG_DEV("enter: dev: ctrl=0x%x stat=0x%x  irq mask: dev=0x%x ep=0x%x  irq status: dev=0x%x ep=0x%x\n",
                    REG_RD(usbDevHw_REG_P->devCtrl), REG_RD(usbDevHw_REG_P->devStatus),
                    REG_RD(usbDevHw_REG_P->devIntrMask), REG_RD(usbDevHw_REG_P->eptIntrMask),
                    REG_RD(usbDevHw_REG_P->devIntrStatus), REG_RD(usbDevHw_REG_P->eptIntrStatus));
    BCM_DEBUG_DEV("enter: ep0: status=0x%x\n", REG_RD(usbDevHw_REG_P->eptFifoOut[0].status));

    usbDevHw_OpsInit();
    UdcFifoRamInit(udcP);

    /*
     * See usb/gadget/epautoconf.c for endpoint naming conventions.
     * Control endpoints are bi-directional, but initial transfer (SETUP stage) is always OUT.
     */
    /** @todo Really should make the non endpoint 0 init attributes configurable by the chip specific part
     * of the driver, i.e. the device instantiation. The settings below are for a chip specific DWG UDC
     * core configuration. Also should incorporate the DWG UDC endpoint type attribute as part of this,
     * which can be control, IN, OUT, or bidirectional.
     */

    UdcEpInit(udcP, 0, "ep0",    USB_DIR_OUT);

    /* On the IPROC, all endpoints except ep0 are birectional and generic type */
    UdcEpInit(udcP, 1, "ep1in",  USB_DIR_IN);
    UdcEpInit(udcP, 2, "ep2out",  USB_DIR_OUT);
    UdcEpInit(udcP, 3, "ep3in", USB_DIR_IN);
    UdcEpInit(udcP, 4, "ep4out", USB_DIR_OUT);
    UdcEpInit(udcP, 5, "ep5in", USB_DIR_IN);
    UdcEpInit(udcP, 6, "ep6out", USB_DIR_OUT);
    UdcEpInit(udcP, 7, "ep7in", USB_DIR_IN);
    UdcEpInit(udcP, 8, "ep8out", USB_DIR_IN);
    UdcEpInit(udcP, 9, "ep9in", USB_DIR_IN);

    UdcEpCfg(&udcP->ep[0], USB_ENDPOINT_XFER_CONTROL, USB_CONTROL_MAX_PACKET_SIZE);
    usbDevHw_DeviceSelfPwrEnable();

#ifdef DEBUG
    if (debug & DEBUG_DMA) {
        DmaDump( udcP );
    }
#endif /* DEBUG */

    BCM_DEBUG_DEV( "exit: dev: ctrl=0x%x stat=0x%x  irq mask: dev=0x%x ep=0x%x  irq status: dev=0x%x ep=0x%x\n",
                    usbDevHw_REG_P->devCtrl, usbDevHw_REG_P->devStatus,
                    usbDevHw_REG_P->devIntrMask, usbDevHw_REG_P->eptIntrMask,
                    usbDevHw_REG_P->devIntrStatus, usbDevHw_REG_P->eptIntrStatus );
    BCM_DEBUG_DEV( "exit: ep0: status=0x%x\n", usbDevHw_REG_P->eptFifoOut[0].status );

    BCM_DEBUG_TRACE( "%s : exit\n", __func__ );
}

static void UdcOpsStartup( BCM_UDC_t *udcP )
{
    unsigned num;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    /*
     * Just enable interrupts for now. Endpoint 0 will get enabled once the speed enumeration
     * has completed. The Device DMA enable is global in scope. There's endpoint specific
     * DMA enables that will happen later.
     */
    usbDevHw_DeviceIrqEnable(usbDevHw_DEVICE_IRQ_SPEED_ENUM_DONE |
                              usbDevHw_DEVICE_IRQ_BUS_SUSPEND |
                              usbDevHw_DEVICE_IRQ_BUS_IDLE |
                              usbDevHw_DEVICE_IRQ_BUS_RESET |
                              usbDevHw_DEVICE_IRQ_SET_INTF |
                              usbDevHw_DEVICE_IRQ_SET_CFG
                           );
    usbDevHw_DeviceDmaEnable();

    /* Enable interrupts for all configured endpoints */
    for (num = 0; num < BCM_UDC_EP_CNT; ++num) {
        if (udcP->ep[num].usb_ep.name) {
            usbDevHw_EndptIrqEnable(udcP->ep[num].num, USB_DIR_OUT);
            usbDevHw_EndptIrqEnable(udcP->ep[num].num, USB_DIR_IN);
        }
    }
    usbDevHw_DeviceNakAllOutEptDisable();

    BCM_DEBUG_DEV("dev: ctrl=0x%x stat=0x%x  irq mask: dev=0x%x ep=0x%x  irq status: dev=0x%x ep=0x%x\n",
                    REG_RD(usbDevHw_REG_P->devCtrl), REG_RD(usbDevHw_REG_P->devStatus),
                    REG_RD(usbDevHw_REG_P->devIntrMask), REG_RD(usbDevHw_REG_P->eptIntrMask),
                    REG_RD(usbDevHw_REG_P->devIntrStatus), REG_RD(usbDevHw_REG_P->eptIntrStatus));
    BCM_DEBUG_DEV("ep0: status=0x%x\n", REG_RD(usbDevHw_REG_P->eptFifoOut[0].status));

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

void UdcOpsShutdown(BCM_UDC_t *udcP)
{
    BCM_UDC_EP_t *udcEpP;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    usbDevHw_DeviceDmaDisable();
    usbDevHw_DeviceIrqDisable(usbDevHw_DEVICE_IRQ_ALL);
    usbDevHw_DeviceIrqClear(usbDevHw_DEVICE_IRQ_ALL);

    udcP->gadget.speed = USB_SPEED_UNKNOWN;

    ReqQueueFlush(&udcP->ep[0], -ESHUTDOWN);
    list_for_each_entry(udcEpP, &udcP->gadget.ep_list, usb_ep.ep_list) {
        ReqQueueFlush(udcEpP, -ESHUTDOWN);
    }

    BCM_DEBUG_DEV("dev: ctrl=0x%x stat=0x%x  irq mask: dev=0x%x ep=0x%x  irq status: dev=0x%x ep=0x%x\n",
                    REG_RD(usbDevHw_REG_P->devCtrl), REG_RD(usbDevHw_REG_P->devStatus),
                    REG_RD(usbDevHw_REG_P->devIntrMask), REG_RD(usbDevHw_REG_P->eptIntrMask),
                    REG_RD(usbDevHw_REG_P->devIntrStatus), REG_RD(usbDevHw_REG_P->eptIntrStatus));
    BCM_DEBUG_DEV("ep0: status=0x%x\n", REG_RD(usbDevHw_REG_P->eptFifoOut[0].status));

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

/****************************************************************************
 * Control Endpoint SETUP related routines.
 *
 *  CtrlEpSetupInit - Prepares for next SETUP Rx. Status indicates if STALL req'd.
 *  CtrlEpSetupRx - Handle Rx of a SETUP.
 *
 ***************************************************************************/
void CtrlEpSetupInit(BCM_UDC_EP_t *udcEpP, int status)
{
    BCM_DEBUG_TRACE("%s: enter\n", __func__ /*udcEpP->usb_ep.name */);

    /* Re-enable transfers to the SETUP buffer, clear IN and OUT NAKs, and re-enable OUT interrupts. */

    udcEpP->dma.virtualAddr->setup.status = cpu_to_le32(usbDevHw_REG_DMA_STATUS_BUF_HOST_READY);
    udcEpP->dir = USB_DIR_OUT;
    udcEpP->stopped = 0;

    if (status == ENOERROR) {
        /* Handling of previous SETUP was OK. Just clear any NAKs. */

        usbDevHw_EndptNakClear(udcEpP->num, USB_DIR_OUT);
        usbDevHw_EndptNakClear(udcEpP->num, USB_DIR_IN);
    } else {
        /*
         * Handling of previous SETUP failed. Set the STALL. This will get cleared
         * when the next SETUP is rx'd.
         */
        usbDevHw_EndptStallEnable(udcEpP->num, USB_DIR_IN);
        usbDevHw_EndptStallEnable(udcEpP->num, USB_DIR_OUT);
    }

    usbDevHw_EndptIrqEnable(udcEpP->num, USB_DIR_OUT);
    usbDevHw_EndptDmaEnable(udcEpP->num, USB_DIR_OUT);

    BCM_DEBUG_CTRL("%s: status=%d\n", udcEpP->usb_ep.name, status);
    BCM_DEBUG_TRACE("%s: exit\n", __func__  /*udcEpP->usb_ep.name, status */);
}

/** @todo this only happens in the context of an irq. Might rename IrqCtrlEpSetupRx. */
void CtrlEpSetupRx(BCM_UDC_EP_t *udcEpP, struct usb_ctrlrequest *setup)
{
    BCM_UDC_t *udcP;
    unsigned value;
    unsigned index;
    unsigned length;
    int status;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    value = le16_to_cpu(setup->wValue);
    index = le16_to_cpu(setup->wIndex);
    length = le16_to_cpu(setup->wLength);

    /*
     * Any SETUP packets appearing here need to be handled by the gadget driver. Some SETUPs may have
     * already been silently handled and acknowledged by the DWC UDC. The exceptions to this rule are the
     * USB_REQ_SET_CONFIGURATION and USB_REQ_SET_INTERFACE, which have been only partially handled with
     * the expectation that some additional software processing is required in order to complete these requests.
     * Thus, they have not been acknowledged by the DWC UDC. There is no DATA stage for these requests.
     */

    /*
     * Set the direction of the subsequent DATA stage of a control transfer. This is an
     * optional stage. It may not exist for all control transfers. If there is a DATA
     * stage, this info is used for DMA operations for any requests received from the
     * Gadget driver.
     */

    udcEpP->dir = setup->bRequestType & USB_DIR_MASK;
    udcP = udcEpP->udcP;

    if (udcEpP->num != 0) {
        /** @todo Make changes here if the Linux USB gadget ever supports a control endpoint other
         * than endpoint 0. The DWC UDC supports multiple control endpoints, and this driver has
         * been written with this in mind. To make things work, really need to change the Gadget
         * setup() callback parameters to provide an endpoint context, or add something similar
         * to the usb_ep structure, or possibly use a usb_request to hold a setup data packet.
         */

        BCM_KERROR("%s: control transfer not supported\n", udcEpP->usb_ep.name);
        status = -EOPNOTSUPP;
    } else {
        /*
         * Forward the SETUP to the gadget driver for processing. The appropriate directional
         * interrupt and NAK clear will happen when the DATA stage request is queued.
         */

        BCM_DEBUG_CTRL("%s: SETUP %02x.%02x value=%04x index=%04x len=%04x\n",
                        udcEpP->usb_ep.name, setup->bRequestType, setup->bRequest, value, index, length);

        spin_unlock(&udcP->lock);
        status = udcP->gadget_driver->setup (&udcP->gadget, setup);
        spin_lock(&udcP->lock);
    }

    if (status < 0) {
        /*
         * Error occurred during the processing of the SETUP, so enable STALL. This condition
         * can only be cleared with the RX of another SETUP, so prepare for that event.
         */
        BCM_KNOTICE("%s: SETUP %02x.%02x STALL; status=%d\n",
                     udcEpP->usb_ep.name, setup->bRequestType, setup->bRequest, status);

        CtrlEpSetupInit(udcEpP, status);
    } else if (length == 0) {
        /* No DATA stage. Just need to prepare for the next SETUP. */
        CtrlEpSetupInit(udcEpP, ENOERROR);
    } else {
        /*
         * The SETUP stage processing has completed OK, and there may or may not be a request queued
         * for the DATA stage. When the DATA stage completes, preparation for the RX of the next
         * SETUP will be done.
         */
    }

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}


/****************************************************************************
 * IRQ routines.
 *
 *  IrqUdc - top level entry point.
 *  IrqDev - top level device related interrupt handler
 *  IrqDevCfgSet - device (endpoint 0) set config interrupt handler
 *  IrqDevIntfSet - device (endpoint 0) set interface interrupt handler
 *  IrqDevSpeedEnum - device speed enumeration done interrupt handler
 *  IrqEp - top level endpoint related interrupt handler
 *  IrqEpInStatusCheck - top level IN endpoint related interrupt handler
 *  IrqEpOutStatusCheck -  top level OUT endpoint related interrupt handler
 *  IrqEpOutSetup - Control endpoint SETUP Rx handler. This may get called
 *                  directly as the result of an endpoint OUT interrupt, or
 *                  indirectly as the result of device SET_CFG or SET_INTF.
 *
 ***************************************************************************/
irqreturn_t IrqUdc(int irq, void *context)
{
    BCM_UDC_t *udcP;
    unsigned long flags;
    uint32_t irqDev;
    uint32_t irqEpIn;
    uint32_t irqEpOut;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    /** @todo sanity check irq */
    (void)irq;

    udcP = (BCM_UDC_t *)context;

    spin_lock_irqsave(&udcP->lock, flags);

    if (!udcP || !udcP->gadget_driver) {
        BCM_KERROR("Invalid context or no driver registered: irq dev=0x%x\n", usbDevHw_DeviceIrqActive());

        usbDevHw_DeviceIrqClear(usbDevHw_DEVICE_IRQ_ALL);
        usbDevHw_EndptIrqListClear(USB_DIR_IN, ~0);
        usbDevHw_EndptIrqListClear(USB_DIR_OUT, ~0);

        spin_unlock_irqrestore(&udcP->lock, flags);
        BCM_DEBUG_TRACE("%s : exit\n", __func__);

        return IRQ_HANDLED;
    }

    BCM_DEBUG_IRQ("enter: devCfg: 0x%x, devCtrl: 0x%x, devStatus: 0x%x, mask: dev=0x%x ep=0x%x  status: dev=0x%x ep=0x%x\n",
                    REG_RD(usbDevHw_REG_P->devCfg), REG_RD(usbDevHw_REG_P->devCtrl), REG_RD(usbDevHw_REG_P->devStatus),
                    REG_RD(usbDevHw_REG_P->devIntrMask), REG_RD(usbDevHw_REG_P->eptIntrMask),
                    REG_RD(usbDevHw_REG_P->devIntrStatus), REG_RD(usbDevHw_REG_P->eptIntrStatus));

    /** @todo change Active to Pending?? */
    /** @todo merge usbDevHw EP IN/OUT routines?? Can only have 16 endpoints max due to a USB protocol restriction. */

    irqDev = usbDevHw_DeviceIrqActive();
    irqEpIn = usbDevHw_EndptIrqListActive(USB_DIR_IN);
    irqEpOut = usbDevHw_EndptIrqListActive(USB_DIR_OUT);

    BCM_DEBUG_IRQ("enter: irqDev=0x%x irqEpIn=0x%x irqEpOut=0x%x\n", irqDev, irqEpIn, irqEpOut);

    usbDevHw_DeviceIrqClear(irqDev);
    usbDevHw_EndptIrqListClear(USB_DIR_IN, irqEpIn);
    usbDevHw_EndptIrqListClear(USB_DIR_OUT, irqEpOut);

    /*
     * Handle the SET_CFG and SET_INTF interrupts after the endpoint and other device interrupts.
     * There can be some race conditions where we have an endpoint 0 interrupt pending for the
     * completion of a previous endpoint 0 transfer (e.g. a GET config) when a SETUP arrives
     * corresponding to the SET_CFG and SET_INTF. Need to complete the processing of the previous
     * transfer before handling the next one, i.e. the SET_CFG or SET_INTF.
     */

    IrqDev(udcP, irqDev & ~(usbDevHw_DEVICE_IRQ_SET_CFG | usbDevHw_DEVICE_IRQ_SET_INTF));
    IrqEp(udcP, irqEpIn, irqEpOut);
    IrqDev(udcP, irqDev & (usbDevHw_DEVICE_IRQ_SET_CFG | usbDevHw_DEVICE_IRQ_SET_INTF));

    spin_unlock_irqrestore(&udcP->lock, flags);

    BCM_DEBUG_IRQ(" exit: mask: dev=0x%x ep=0x%x  status: dev=0x%x ep=0x%x\n",
                 REG_RD(usbDevHw_REG_P->devIntrMask), REG_RD(usbDevHw_REG_P->eptIntrMask),
                 REG_RD(usbDevHw_REG_P->devIntrStatus), REG_RD(usbDevHw_REG_P->eptIntrStatus));

    BCM_DEBUG_TRACE("%s : exit\n", __func__);

    return((irqDev || irqEpIn || irqEpOut) ? IRQ_HANDLED : IRQ_NONE);
}

void IrqDev(BCM_UDC_t *udcP, uint32_t irq)
{
    if (irq & usbDevHw_DEVICE_IRQ_BUS_RESET) {
        BCM_KINFO("BUS reset\n");
    }

    if (irq & usbDevHw_DEVICE_IRQ_BUS_SUSPEND) {
        BCM_DEBUG_DEV("BUS suspend\n");
    }

    if (irq & usbDevHw_DEVICE_IRQ_BUS_IDLE) {
        BCM_DEBUG_DEV("BUS idle\n");
        UdcOpsDisconnect(udcP);
    }

    if (irq & usbDevHw_DEVICE_IRQ_SPEED_ENUM_DONE) {
        BCM_DEBUG_DEV("BUS speed enum done\n");
        IrqDevSpeedEnum(udcP);
    }

    if (irq & usbDevHw_DEVICE_IRQ_SET_CFG) {
        BCM_DEBUG_DEV("SET CFG\n");
        IrqDevCfgSet(udcP);
    }

    if (irq & usbDevHw_DEVICE_IRQ_SET_INTF) {
        BCM_DEBUG_DEV("SET INTF\n");
        IrqDevIntfSet(udcP);
    }
}

void IrqDevCfgSet(BCM_UDC_t *udcP)
{
    struct usb_ctrlrequest setup;
    unsigned epNum;
    uint16_t cfg;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    /*
     * Device Configuration SETUP has been received. This is not placed in the SETUP
     * DMA buffer. The packet has to be re-created here so it can be forwarded to the
     * gadget driver to act upon.
     */

    cfg = (uint16_t) usbDevHw_DeviceCfgNum();

    setup.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    setup.bRequest = USB_REQ_SET_CONFIGURATION;
    setup.wValue = cpu_to_le16(cfg);
    setup.wIndex = 0;
    setup.wLength = 0;

    /*
     * Setting the configuration number before the gadget responds is a bit presumptious, but should
     * not be fatal.
     */
    /** @todo Do not set endpoint 0? Or is it a don't care? */

    for (epNum = 0; epNum < BCM_UDC_EP_CNT; epNum++) {
        usbDevHw_EndptCfgSet(epNum, cfg);
    }

    BCM_KINFO("SET CFG=%d\n", cfg);

    CtrlEpSetupRx(&udcP->ep[0], &setup);
    usbDevHw_DeviceSetupDone();
    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

void IrqDevIntfSet(BCM_UDC_t *udcP)
{
    struct usb_ctrlrequest setup;
    unsigned epNum;
    uint16_t intf;
    uint16_t alt;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    /*
     * Device Interface SETUP has been received. This is not placed in the SETUP
     * DMA buffer. The packet has to be re-created here so it can be forwarded to the
     * gadget driver to act upon.
     */

    intf = (uint16_t) usbDevHw_DeviceIntfNum();
    alt =  (uint16_t) usbDevHw_DeviceAltNum();

    setup.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_INTERFACE;
    setup.bRequest = USB_REQ_SET_INTERFACE;
    setup.wValue = cpu_to_le16(alt);
    setup.wIndex = cpu_to_le16(intf);
    setup.wLength = 0;

    /*
     * Setting the interface numbers before the gadget responds is a bit presumptious, but should
     * not be fatal.
     */
    /** @todo Do not set endpoint 0? Or is it a don't care? */

    for (epNum = 0; epNum < BCM_UDC_EP_CNT; epNum++) {
        usbDevHw_EndptAltSet(epNum, alt);
        usbDevHw_EndptIntfSet(epNum, intf);
    }

    BCM_KINFO("SET INTF=%d ALT=%d\n", intf, alt);

    CtrlEpSetupRx(&udcP->ep[0], &setup);
    usbDevHw_DeviceSetupDone();

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

void IrqDevSpeedEnum(BCM_UDC_t *udcP)
{
    unsigned prevSpeed;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

    prevSpeed = udcP->gadget.speed;

    switch(usbDevHw_DeviceSpeedEnumerated()) {
        case usbDevHw_DEVICE_SPEED_HIGH:
            BCM_KINFO("HIGH SPEED\n");
            udcP->gadget.speed = USB_SPEED_HIGH;
            break;
        case usbDevHw_DEVICE_SPEED_FULL:
            BCM_KINFO("FULL SPEED\n");
            udcP->gadget.speed = USB_SPEED_FULL;
            break;
        case usbDevHw_DEVICE_SPEED_LOW:
            BCM_KWARN("low speed not supported\n");
            udcP->gadget.speed = USB_SPEED_LOW;
            break;
        default:
            BCM_KERROR("unknown speed=0x%x\n", usbDevHw_DeviceSpeedEnumerated());
            break;
    }

    if ((prevSpeed == USB_SPEED_UNKNOWN) && (udcP->gadget.speed != USB_SPEED_UNKNOWN)) {
        /*
         * Speed has not been enumerated before, so now we can initialize transfers on endpoint 0.
         * Also have to disable the NAKs at a global level, which has been in place while waiting
         * for enumeration to complete.
         */

        BCM_DEBUG_DEV("dev status=0x%08x: ep0 IN status=0x%08x OUT status=0x%08x\n",
                        REG_RD(usbDevHw_REG_P->devStatus), REG_RD(usbDevHw_REG_P->eptFifoIn[0].status), REG_RD(usbDevHw_REG_P->eptFifoOut[0].status));
        CtrlEpSetupInit(&udcP->ep[0], ENOERROR);
        usbDevHw_DeviceNakAllOutEptDisable();
    }

    BCM_DEBUG_TRACE("%s : exit\n", __func__);
}

void IrqEp(BCM_UDC_t *udcP, uint32_t irqIn, uint32_t irqOut)
{
    uint32_t mask;
    unsigned num;

    mask = 1;
    for (num = 0; num < BCM_UDC_EP_CNT; num++) {
        if (irqIn & mask) {
            IrqEpInStatusCheck(&udcP->ep[num]);
        }
        if (irqOut & mask) {
            IrqEpOutStatusCheck(&udcP->ep[num]);
        }
        mask <<= 1;
    }

}

void IrqEpInStatusCheck(BCM_UDC_EP_t *udcEpP)
{
    uint32_t status;

    status = usbDevHw_EndptStatusActive(udcEpP->num, USB_DIR_IN);
    usbDevHw_EndptStatusClear(udcEpP->num, USB_DIR_IN, status);

    BCM_DEBUG_IRQ("enter: %s: %s: status=0x%x\n", __func__, udcEpP->usb_ep.name, status);
    if (!status) {
        return;
    }

    /** @todo check might only be for direction... */
    if ((udcEpP->dir != USB_DIR_IN) && (udcEpP->type != USB_ENDPOINT_XFER_CONTROL)) {
        BCM_KERROR("%s: unexpected IN interrupt\n", udcEpP->usb_ep.name);
        return;
    }

    if (udcEpP->dir != USB_DIR_IN) {
        /* This probably should not be happening */
        BCM_DEBUG_IRQ("%s: CTRL dir OUT\n", udcEpP->usb_ep.name);
    }

    if ((udcEpP->type == USB_ENDPOINT_XFER_ISOC) &&
        (status & (usbDevHw_ENDPT_STATUS_IN_XFER_DONE | usbDevHw_ENDPT_STATUS_DMA_BUF_NOT_AVAIL))) {
        BCM_KWARN("%s: ISOC IN unexpected status=0x%x\n", udcEpP->usb_ep.name, status);
    }

    if (status & usbDevHw_ENDPT_STATUS_IN_TOKEN_RX) {
        /*
         * If there's any IN requests, the DMA should be setup and ready to go if
         * the endpoint is not an ISOC. Nothing to do in this case. However, if
         * this is an ISOC endpoint, then this interrupt implies there was no
         * data available for this frame number. This will happen if the gadget
         * does not have any data queued to send in this frame, or we have been
         * waiting for this event to occur so we can get alignment with the host
         * for the interval. This alignment is necessary when the interval is
         * greater than one frame / uframe. E.g. for an audio stream sending
         * samples @ 5ms intervals on a FS link, this corresponds to a period
         * of 5 frames. Samples with be queued for every 5th frame number after
         * the frame number in which this interrupt occurred.
         */

        status &= ~usbDevHw_ENDPT_STATUS_IN_TOKEN_RX;
        usbDevHw_EndptNakClear(udcEpP->num, USB_DIR_IN);

        if ((udcEpP->type == USB_ENDPOINT_XFER_ISOC)) {
            /* Always align to the current frame number for subsequent transfers. */
            udcEpP->dma.frameNum = usbDevHw_DeviceFrameNumLastRx();
            BCM_DEBUG_ISOC("%s: ISOC IN rx: align frameNum=%d.%d\n", udcEpP->usb_ep.name, (udcEpP->dma.frameNum >> 3), (udcEpP->dma.frameNum & 0x7));
            if (udcEpP->dma.usb_req != NULL) {
                /*
                 * Might have something queued when waiting for alignment. If something is queued,
                 * it is already too late for the current transfer point. It will also have been
                 * placed in the queue at some point before this interrupt, and it will be stale
                 * if we try to transmit at the next transfer point.
                 */
                udcEpP->dma.usb_req->status = -EREMOTEIO;
                ReqXferProcess(udcEpP);
            }
        }
    }

    if (status & usbDevHw_ENDPT_STATUS_IN_DMA_DONE) {
        /*
         * DMA has completed, but cannot start next transfer until usbDevHw_ENDPT_STATUS_IN_XFER_DONE.
         * To avoid race conditions and other issues, do not release the current transfer until both
         * interrupts have arrived. Normally this interrupt will arrive at or before the IN_XFER_DONE,
         * but there have been situations when the system is under load that this interrupt might
         * arrive after the IN_XFER_DONE, in which case we will need to do the processing now.
         * The exception to this rule is for ISOC endpoints. They will only get this interrupt to
         * indicate that DMA has completed.
         */

        status &= ~usbDevHw_ENDPT_STATUS_IN_DMA_DONE;

        if ((udcEpP->type == USB_ENDPOINT_XFER_ISOC)) {
            BCM_DEBUG_ISOC("%s: ISOC IN DMA done: frameNum=%d.%d\n", udcEpP->usb_ep.name, (udcEpP->dma.frameNum >> 3), (udcEpP->dma.frameNum & 0x7));
            ReqXferProcess(udcEpP);
        } else if (udcEpP->dma.done & usbDevHw_ENDPT_STATUS_IN_XFER_DONE) {
            /*
             * Did not receive the IN_DMA_DONE interrupt for this request before or
             * at the same time as the IN_XFER_DONE interrupt, so the request
             * processing was postponed until the IN_DMA_DONE interrupt arrived.
             * See handling of IN_XFER_DONE status below.
             */
            BCM_DEBUG_DMA("%s: late IN DMA done rec'd\n", udcEpP->usb_ep.name);
            ReqXferProcess(udcEpP);
        } else {
            /*
             * IN_DMA_DONE received. Save this info so request processing will be
             * done when the IN_XFER_DONE interrupt is received. This may happen
             * immediately, i.e. both IN_DMA_DONE and IN_XFER_DONE status are
             * set when the interrupt processing takes place.
             */
            udcEpP->dma.done = usbDevHw_ENDPT_STATUS_IN_DMA_DONE;
        }
    }

    if (status & usbDevHw_ENDPT_STATUS_IN_XFER_DONE) {
        status &= ~(usbDevHw_ENDPT_STATUS_IN_XFER_DONE);
        status &= ~(usbDevHw_ENDPT_STATUS_IN_FIFO_EMPTY);

        if (udcEpP->dma.done & usbDevHw_ENDPT_STATUS_IN_DMA_DONE) {
            /*
             * Have received both the IN_DMA_DONE and IN_XFER_DONE interrupts
             * for this request. OK to process the request (remove the request
             * and start the next one).
             */
            ReqXferProcess(udcEpP);
        } else {
            /*
             * Have not received the IN_DMA_DONE interrupt for this request.
             * Need to postpone processing of the request until the IN_DMA_DONE
             * interrupt occurs. See handling of IN_DMA_DONE status above.
             */
            udcEpP->dma.done = usbDevHw_ENDPT_STATUS_IN_XFER_DONE;
            BCM_DEBUG_DMA("%s: late IN DMA done pending\n", udcEpP->usb_ep.name);
        }
    }

    /* Clear the FIFO EMPTY bit, not to print error message */
    status &= ~(usbDevHw_ENDPT_STATUS_IN_FIFO_EMPTY);

    if (status & usbDevHw_ENDPT_STATUS_DMA_BUF_NOT_AVAIL) {
        BCM_KERROR("%s: DMA BUF NOT AVAIL\n", udcEpP->usb_ep.name);
        status &= ~(usbDevHw_ENDPT_STATUS_DMA_BUF_NOT_AVAIL);
        ReqXferProcess(udcEpP);
    }

    if (status & usbDevHw_ENDPT_STATUS_DMA_ERROR) {
        status &= ~usbDevHw_ENDPT_STATUS_DMA_ERROR;
        BCM_KERROR("%s: DMA ERROR\n", udcEpP->usb_ep.name);
        ReqXferError(udcEpP, -EIO);
    }

    if (status) {
        BCM_KERROR("exit: %s %s: unknown status=0x%x\n", __func__, udcEpP->usb_ep.name, status);
    }
}

void IrqEpOutStatusCheck(BCM_UDC_EP_t *udcEpP)
{
    uint32_t status;


    status = usbDevHw_EndptStatusActive(udcEpP->num, USB_DIR_OUT);
    usbDevHw_EndptStatusClear(udcEpP->num, USB_DIR_OUT, status);

    BCM_DEBUG_IRQ("enter: %s: %s: status=0x%x\n", __func__, udcEpP->usb_ep.name, status);

    /*
     * Remove the Rx packet size field from the status. The datasheet states this field is not used
     * in DMA mode, but that is not true.
     */
    status &= usbDevHw_ENDPT_STATUS_ALL;

    if (!status) {
        return;
    }

    if ((udcEpP->dir != USB_DIR_OUT) && (udcEpP->type != USB_ENDPOINT_XFER_CONTROL)) {
        BCM_KERROR("%s: unexpected OUT interrupt\n", udcEpP->usb_ep.name);
        return;
    }

    if (udcEpP->dir != USB_DIR_OUT) {
        /* This probably should not be happening */
        BCM_KNOTICE("%s: CTRL dir IN\n", udcEpP->usb_ep.name);
    }

    if (status & usbDevHw_ENDPT_STATUS_OUT_DMA_DATA_DONE) {
        status &= ~usbDevHw_ENDPT_STATUS_OUT_DMA_DATA_DONE;
        ReqXferProcess(udcEpP);
    }

    if (status & usbDevHw_ENDPT_STATUS_OUT_DMA_SETUP_DONE) {
        status &= ~usbDevHw_ENDPT_STATUS_OUT_DMA_SETUP_DONE;
        IrqEpOutSetup(udcEpP);
    }

    if (status & usbDevHw_ENDPT_STATUS_DMA_BUF_NOT_AVAIL) {
        /** @todo Verify under what situations this can happen. Should be when chain has emptied but last desc not reached  */
        /** @todo status for desc updates */

        status &= ~usbDevHw_ENDPT_STATUS_DMA_BUF_NOT_AVAIL;
        BCM_KERROR("%s: DMA BUF NOT AVAIL\n", udcEpP->usb_ep.name);
        ReqXferProcess(udcEpP);
    }

    if (status & usbDevHw_ENDPT_STATUS_DMA_ERROR) {
        status &= ~usbDevHw_ENDPT_STATUS_DMA_ERROR;
        BCM_KERROR("%s: DMA ERROR\n", udcEpP->usb_ep.name);
        /** @todo merge XferError and XferProcess?? */
        ReqXferError(udcEpP, -EIO);
    }

    if (status) {
        BCM_KERROR("%s: unknown status=0x%x\n", udcEpP->usb_ep.name, status);
    }
}

void IrqEpOutSetup(BCM_UDC_EP_t *udcEpP)
{
    BCM_UDC_DMA_SETUP_t *dmaP;


    dmaP = &udcEpP->dma.virtualAddr->setup;

    if ((REG_RD(dmaP->status) & usbDevHw_REG_DMA_STATUS_BUF_MASK) != usbDevHw_REG_DMA_STATUS_BUF_DMA_DONE) {
        BCM_KERROR("%s: unexpected DMA buf status=0x%x\n", udcEpP->usb_ep.name, (REG_RD(dmaP->status) & usbDevHw_REG_DMA_STATUS_BUF_MASK));

        CtrlEpSetupInit(udcEpP, ENOERROR);
    } else if ((REG_RD(dmaP->status) & usbDevHw_REG_DMA_STATUS_RX_MASK) != usbDevHw_REG_DMA_STATUS_RX_SUCCESS) {
        BCM_KERROR("%s: unexpected DMA rx status=0x%x\n", udcEpP->usb_ep.name, (REG_RD(dmaP->status) & usbDevHw_REG_DMA_STATUS_RX_MASK));

        CtrlEpSetupInit(udcEpP, ENOERROR);
    } else {
        if (udcEpP->num != 0) {
            /** @todo Handle the cfg / intf / alt fields of the DMA status. This will only be any issue
             * once the Linux Gadget driver framework supports control transfers on an endpoint other
             * than 0.
             */

            BCM_KWARN("%s: CTRL xfr support not complete\n", udcEpP->usb_ep.name);
        }
        /*
         * Take ownership of the descriptor while processing the request. Ownership will be released
         * when ready to Rx SETUP again.
         */
        REG_MOD_MASK(dmaP->status, ~usbDevHw_REG_DMA_STATUS_BUF_MASK, usbDevHw_REG_DMA_STATUS_BUF_HOST_BUSY);
        CtrlEpSetupRx(udcEpP, (struct usb_ctrlrequest *)&dmaP->data1);
    }
}

/****************************************************************************
 * UDC Endpoint routines.
 *
 * UdcEpInit - Initialize endpoint structures
 * UdcEpCfg - Sets endpoint configuration in preparation for usage.
 *
 ***************************************************************************/

static int UdcEpCfg(BCM_UDC_EP_t *udcEpP, unsigned type, unsigned maxPktSize)
{
    BCM_DEBUG_TRACE("%s : enter\n", __func__);
    BCM_DEBUG_EP("%s: type=%u dir=0x%x pkt=%u\n", udcEpP->usb_ep.name, type, udcEpP->dir, maxPktSize);
    udcEpP->type = type;
    if (UdcFifoRamAlloc(udcEpP, maxPktSize) != ENOERROR) {
        return(-ENOSPC);
    }

    udcEpP->type = type;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
    udcEpP->usb_ep.maxpacket = maxPktSize;
#else
    usb_ep_set_maxpacket_limit(&udcEpP->usb_ep, maxPktSize);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) */
    usbDevHw_EndptOpsInit(udcEpP->num, udcEpP->type, udcEpP->dir, maxPktSize);

    BCM_DEBUG_EP("%s: type=%u maxPktSize=%u\n", udcEpP->usb_ep.name, type, maxPktSize);

    BCM_DEBUG_TRACE("%s : exit\n", __func__);

    return(ENOERROR);
}

static void UdcEpInit(BCM_UDC_t *udcP, unsigned num, const char *name, unsigned dir)
{
    BCM_UDC_EP_t *udcEpP;

    BCM_DEBUG_TRACE("%s: enter\n", name);
    BCM_DEBUG_EP("%s: num=%u dir=%s\n", name, num, DIR_STR(dir));

    if ((num >= BCM_UDC_EP_CNT) || (udcP == NULL))  {
        BCM_KERROR("Parameters error\n");
        return;
    }

    udcEpP = &udcP->ep[num];

    /*
     * Initialize the endpoint attribute / control structure. Note that the UDC max packet
     * size is an indication of the hardware capabilities, not what is necessarily
     * configured and used by the endpoint. In order to provide the most flexibility on
     * how the endpoints are used, this is set to the maximum possible. When the Linux
     * Gadget usb_ep_autoconfig() looks for a suitable endpoint, it *may* check to ensure
     * the max size is adequate. There may or may not be enough FIFO RAM left to support an
     * endpoint configuration, even though the max size indicates otherwise, due to FIFO RAM
     * consumption by other endpoints. If this condition exists, an error will be returned
     * when the gadget driver tries to enable the endpoint. It is felt that doing things in
     * this manner is much easier than trying to predict and accomodate all the endpoint
     * usage scenarios by various gadget drivers, both existing and yet to be developed.
     */

    udcEpP->udcP = udcP;
    udcEpP->num = num;
    udcEpP->dir = dir;
    udcEpP->bEndpointAddress = num | dir;
    udcEpP->maxPktSize = BCM_UDC_EP_MAX_PKT_SIZE;
    udcEpP->stopped = 0;

    INIT_LIST_HEAD(&udcEpP->listQueue);
    udcEpP->usb_ep.name = name;
    udcEpP->usb_ep.ops = &bcm_udc_gadgetEpOps;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
    udcEpP->usb_ep.maxpacket = udcEpP->maxPktSize;
#else
    usb_ep_set_maxpacket_limit(&udcEpP->usb_ep, udcEpP->maxPktSize);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) */
    INIT_LIST_HEAD(&udcEpP->usb_ep.ep_list);

    DmaEpInit(udcEpP);

    BCM_DEBUG_TRACE("%s: exit\n", name);
}

/****************************************************************************
 * UDC FIFO RAM management routines.
 *
 *  The are two FIFO RAMs, one for IN and one for OUT. Each is shared amongst
 *  the endpoints and is dynamically allocated. In order to handle any excess
 *  allocation issues, we need to keep track of consumption. These are used
 *  as part of the Gadget endpoint enable / disable operations.
 *
 *  UdcFifoRamInit - Initializes the space available for allocation.
 *  UdcFifoRamAlloc - Allocates space for endpoint.
 *  UdcFifoRamFree - Fress space used by endpoint.
 *
 ***************************************************************************/

static void UdcFifoRamInit(BCM_UDC_t *udcP)
{
    udcP->rxFifoSpace = BCM_UDC_OUT_RX_FIFO_MEM_SIZE;
    udcP->txFifoSpace = BCM_UDC_IN_TX_FIFO_MEM_SIZE;
}

static int UdcFifoRamAlloc(BCM_UDC_EP_t *udcEpP, unsigned maxPktSize)
{
    unsigned rxCnt;
    unsigned txCnt;

    BCM_DEBUG_TRACE("%s : enter\n", __func__);

#define EP_DIRN_TYPE(d,t)   (((d) << 8) | (t))

    /** @todo Move this FIFO space requirement calculation to CSP? */
    switch (EP_DIRN_TYPE(udcEpP->dir, udcEpP->type))
    {
        case EP_DIRN_TYPE(USB_DIR_OUT, USB_ENDPOINT_XFER_BULK):
        case EP_DIRN_TYPE(USB_DIR_OUT, USB_ENDPOINT_XFER_INT):
        case EP_DIRN_TYPE(USB_DIR_OUT, USB_ENDPOINT_XFER_ISOC):
            rxCnt = usbDevHw_FIFO_SIZE_UINT8(maxPktSize);
            txCnt = 0;
            break;
        case EP_DIRN_TYPE(USB_DIR_IN, USB_ENDPOINT_XFER_BULK):
        case EP_DIRN_TYPE(USB_DIR_IN, USB_ENDPOINT_XFER_INT):
            rxCnt = 0;
            txCnt = usbDevHw_FIFO_SIZE_UINT8(maxPktSize);
            break;
        case EP_DIRN_TYPE(USB_DIR_IN, USB_ENDPOINT_XFER_ISOC):
            /* DWC UDC does double buffering for IN ISOC */
            rxCnt = 0;
            txCnt = 2 * usbDevHw_FIFO_SIZE_UINT8(maxPktSize);
            break;
        case EP_DIRN_TYPE(USB_DIR_IN,  USB_ENDPOINT_XFER_CONTROL):
        case EP_DIRN_TYPE(USB_DIR_OUT, USB_ENDPOINT_XFER_CONTROL):
            rxCnt = usbDevHw_FIFO_SIZE_UINT8(maxPktSize);
            txCnt = rxCnt;
            break;
        default:
            BCM_KERROR("%s: invalid EP attributes\n", udcEpP->usb_ep.name);
            BCM_DEBUG_TRACE("exit: error\n");
            return(-ENODEV);
    }

    BCM_DEBUG_EP("rx req=%u free=%u: tx req=%u free=%u\n",
                    rxCnt, udcEpP->udcP->rxFifoSpace, txCnt, udcEpP->udcP->txFifoSpace);

    /** @todo change FifoSpace to uint32 units?? */
    if ((udcEpP->udcP->rxFifoSpace < rxCnt) || (udcEpP->udcP->txFifoSpace < txCnt)) {
        BCM_DEBUG_TRACE("exit: error\n");
        return(-ENOSPC);
    }

    udcEpP->rxFifoSize = rxCnt;
    udcEpP->txFifoSize = txCnt;

#if usbDevHw_REG_MULTI_RX_FIFO
    udcEpP->udcP->rxFifoSpace -= rxCnt;
#endif
    udcEpP->udcP->txFifoSpace -= txCnt;

    BCM_DEBUG_TRACE("exit: ok\n");

    return(ENOERROR);
}

static void UdcFifoRamFree(BCM_UDC_EP_t *udcEpP)
{
#if usbDevHw_REG_MULTI_RX_FIFO
    udcEpP->udcP->rxFifoSpace += udcEpP->rxFifoSize;
#endif
    udcEpP->udcP->txFifoSpace += udcEpP->txFifoSize;

    udcEpP->rxFifoSize = 0;
    udcEpP->txFifoSize = 0;
}

static void UdcOpsDisconnect(BCM_UDC_t *udcP)
{
    BCM_UDC_EP_t    *udcEpP;
    int             num;

    for (num = 0; num < BCM_UDC_EP_CNT; num++) {
        udcEpP=&udcP->ep[num];
        if (udcEpP->dma.usb_req) {
            // Flush DMA, reqeust still pending
            usbDevHw_EndptFifoFlushEnable(0, usbDevHw_ENDPT_DIRN_IN);
            usbDevHw_EndptFifoFlushDisable(0, usbDevHw_ENDPT_DIRN_IN);
            ReqXferProcess(udcEpP);
        }
    }
}

/***************************************************************************
* Endpoint request operations
***************************************************************************/
void ReqQueueFlush(BCM_UDC_EP_t *udcEpP, int status)
{
    BCM_UDC_EP_REQ_t *udcEpReqP;

    BCM_DEBUG_TRACE("%s: enter\n", udcEpP->usb_ep.name);
    BCM_DEBUG_REQ("%s\n", udcEpP->usb_ep.name);

    udcEpP->stopped = 1;
    usbDevHw_EndptOpsFinis(udcEpP->num);

    while (!list_empty(&udcEpP->listQueue)) {
        udcEpReqP = list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode);
        ReqXferDone(udcEpP, udcEpReqP, status);
    }
    udcEpP->dma.usb_req = NULL;

    BCM_DEBUG_TRACE("%s: exit\n", udcEpP->usb_ep.name);
}


void ReqXferAdd(BCM_UDC_EP_t *udcEpP, BCM_UDC_EP_REQ_t *udcEpReqP)
{
    BCM_DEBUG_TRACE("%s: enter\n", __func__);
    BCM_DEBUG_REQ("%s: %s: stopped=%d\n", udcEpP->usb_ep.name, DIR_STR(udcEpP->dir), udcEpP->stopped);


    list_add_tail(&udcEpReqP->listNode, &udcEpP->listQueue);

    /** @todo Is this necessary?? Stopped happens as a result of a halt, complete(), dequeue(), nuke().
     * nuke() is called when ep disabled, during setup processing, and by udc_queisce(). The latter is
     * called during vbus state change (cable insert/remove), USB reset interrupt, and gadget deregister.
     */
    if (udcEpP->stopped) {
        BCM_DEBUG_TRACE("%s: exit\n", __func__);
        return;
    }

    if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC) && udcEpP->dma.usb_req && (udcEpP->dma.frameNum == FRAME_NUM_INVALID)) {
        /*
         * Gadget has a request already queued, but still have not received an IN token from the host
         * and the interval window is not aligned. Queued packet is now very stale, so remove it.
         */

        DmaDataFinis(udcEpP);
        /** @todo Move set of udcEpP->dma.usb_req to DmaDataInit() and DmaDataFinis() routines. */
        udcEpP->dma.usb_req = NULL;
        ReqXferDone(udcEpP, list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode), -EREMOTEIO);
    }

    /** @todo Current transfer is always the queue head. Do we need a separate pointer? Maybe just a pointer to usb_request
     * need to know if the queue head has already been loaded. Maybe that's the point of the "stopped".
     */
    if (udcEpP->dma.usb_req) {
        BCM_DEBUG_REQ("%s: busy\n", udcEpP->usb_ep.name);
    }
#ifndef ISOC_IN_XFER_DELAY_DISABLED
    else if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC) && (udcEpP->dma.frameNum == FRAME_NUM_INVALID)) {
        /*
         * Delay any ISOC IN DMA operations until it is known what frame number the host
         * is going to start transfers with. Normally might just return requests until
         * this event occurs. However, the zero gadget does not submit requests based on
         * its own timer or similar, so if the request is returned right away things are
         * going to thrash, as another request will be immediately submitted.
         */

        BCM_DEBUG_ISOC("%s: ISOC delay xfer start\n", udcEpP->usb_ep.name);
        udcEpP->dma.usb_req = &(list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode))->usb_req;
        DmaDataInit(udcEpP);
        usbDevHw_EndptNakClear(udcEpP->num, udcEpP->dir);
        usbDevHw_EndptIrqEnable(udcEpP->num, udcEpP->dir);

    }
#endif
    else {
#ifdef ISOC_IN_XFER_DELAY_DISABLED
        if ((udcEpP->dir == USB_DIR_IN) && (udcEpP->type == USB_ENDPOINT_XFER_ISOC) && (udcEpP->dma.frameNum == FRAME_NUM_INVALID)) {
            /*
             * Try and start ISOC IN transfers without any regard to alignment to the
             * host. Unless the interval is set to its lowest possible value (a single
             * frame or uframe), transfers may not work until a IN token is received
             * from the host. See ENDPT_STATUS_IN_TOKEN_RX processing in IrqEpInStatusCheck().
             */

            udcEpP->dma.frameNum = usbDevHw_DeviceFrameNumLastRx();
            BCM_DEBUG_ISOC("%s: INIT: current frameNum=%d.%d\n", udcEpP->usb_ep.name, (udcEpP->dma.frameNum >> 3), (udcEpP->dma.frameNum & 0x7));
        }
#endif

        udcEpReqP = list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode);
        udcEpP->dma.usb_req = &udcEpReqP->usb_req;
        DmaDataInit(udcEpP);
        BCM_DEBUG_REQ("%s: begin: req=0x%p buf=0x%p len=%d actual=%d\n",
                        udcEpP->usb_ep.name, &udcEpReqP->usb_req, udcEpReqP->usb_req.buf, udcEpReqP->usb_req.length, udcEpReqP->usb_req.actual);
        DmaDataAddReady(udcEpP);
        usbDevHw_EndptNakClear(udcEpP->num, udcEpP->dir);
        usbDevHw_EndptDmaEnable(udcEpP->num, udcEpP->dir);

        /* needed for gadget commands to complete correctly - possible locking issue */
        mdelay(3);
    }

    BCM_DEBUG_TRACE("%s: exit\n", __func__);
}

void ReqXferDone(BCM_UDC_EP_t *udcEpP, BCM_UDC_EP_REQ_t *udcEpReqP, int status)
{
    unsigned stopped;

    BCM_DEBUG_TRACE("%s: enter\n", __func__);

    list_del_init(&udcEpReqP->listNode);

    if (udcEpReqP->usb_req.status == -EINPROGRESS) {
        udcEpReqP->usb_req.status = status;
    }

    if (udcEpReqP->dmaAligned) {
        udcEpReqP->dmaAligned = 0;
    } else if (udcEpReqP->dmaMapped) {
        /*
         * A physical address was not provided for the DMA buffer. Release any resources
         * that were requested by the driver.
         */
        BCM_DEBUG_DMA("%s: udcEpReqP=0x%x buf=0x%x dma=0x%x actual=%u len=%u\n",
                    udcEpP->usb_ep.name,
                    (unsigned int)udcEpReqP,
                    (unsigned int)udcEpReqP->usb_req.buf,
                    (unsigned int)udcEpReqP->usb_req.dma,
                    (unsigned int)udcEpReqP->usb_req.actual,
                    (unsigned int)udcEpReqP->usb_req.length);

        dma_unmap_single(udcEpP->udcP->gadget.dev.parent, udcEpReqP->usb_req.dma, udcEpReqP->usb_req.length,
                            (udcEpP->dir == USB_DIR_IN ? DMA_TO_DEVICE : DMA_FROM_DEVICE));

        udcEpReqP->dmaMapped = 0;
        udcEpReqP->usb_req.dma = DMA_ADDR_INVALID;
    }

    BCM_DEBUG_REQ("%s: ready: req=0x%p buf=0x%p len=%d actual=%d\n",
                    udcEpP->usb_ep.name, &udcEpReqP->usb_req, udcEpReqP->usb_req.buf, udcEpReqP->usb_req.length, udcEpReqP->usb_req.actual);

    /*
     * Disable DMA operations during completion callback. The callback may cause requests to be
     * added to the queue, but we don't want to change the state of the queue head.
     */

    stopped = udcEpP->stopped;
    udcEpP->stopped = 1;
    spin_unlock(&udcEpP->udcP->lock);
    udcEpReqP->usb_req.complete(&udcEpP->usb_ep, &udcEpReqP->usb_req);
    spin_lock(&udcEpP->udcP->lock);
    udcEpP->stopped = stopped;

    /** @todo May not have valid access to request any longer it has been freed... */
    BCM_DEBUG_REQ("%s: complete: req=0x%p buf=0x%p\n", udcEpP->usb_ep.name, &udcEpReqP->usb_req, udcEpReqP->usb_req.buf);
    BCM_DEBUG_TRACE("%s: exit\n", __func__);
}

void ReqXferError(BCM_UDC_EP_t *udcEpP, int status)
{
    BCM_DEBUG_TRACE("%s: enter\n", __func__);
    BCM_DEBUG_REQ("%s: status=%d\n", udcEpP->usb_ep.name, status);

    if (!udcEpP->dma.usb_req) {
        BCM_KERROR("%s: No request being transferred\n", udcEpP->usb_ep.name);
        BCM_DEBUG_TRACE("%s: exit\n", __func__);
        return;
    }

    /** @todo abort current DMA, start next transfer if there is one. */
    udcEpP->dma.usb_req->status = status;
    ReqXferProcess(udcEpP);

    BCM_DEBUG_TRACE("%s: exit\n", __func__);
}

void ReqXferProcess(BCM_UDC_EP_t *udcEpP)
{
    BCM_UDC_EP_REQ_t *udcEpReqP;

    BCM_DEBUG_TRACE("%s: enter\n", __func__);
    BCM_DEBUG_REQ("%s\n", udcEpP->usb_ep.name);

    /** @todo Current transfer is always the queue head. Do we need a separate pointer? Maybe just a pointer to usb_request */
    if (!udcEpP->dma.usb_req) {
        BCM_KERROR("%s: No request being transferred\n", udcEpP->usb_ep.name);
        BCM_DEBUG_TRACE("%s: exit\n", __func__);
        return;
    }

    usbDevHw_EndptDmaDisable(udcEpP->num, udcEpP->dir);
    DmaDataRemoveDone(udcEpP);

    if (udcEpP->dma.usb_req->status != -EINPROGRESS) {
        /*
         * Current transfer stage has finished. This may or may not be with error.
         * Complete the transfer as needed before starting the next one, if any.
         */
        DmaDataFinis(udcEpP);

        if ((udcEpP->type == USB_ENDPOINT_XFER_CONTROL) && (udcEpP->dir == USB_DIR_IN) && (udcEpP->dma.usb_req->status == ENOERROR)) {
            /*
             * For the status phase of control IN transfers, the hardware requires that an OUT DMA transfer
             * actually takes place. This should be just an OUT ZLP, and we will re-use the IN buffer that
             * just completed transfer for this purpose. There should be no harm in doing this, even if the
             * OUT status is more than a ZLP.
             */
            udcEpP->dir = USB_DIR_OUT;
            DmaDataInit(udcEpP);
        } else {
            /*
             * All transfer stages have completed. Return the request to the gadget driver, and then
             * setup for the next transfer.
             */
            ReqXferDone(udcEpP, list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode), ENOERROR);

            if (udcEpP->type == USB_ENDPOINT_XFER_CONTROL) {
                CtrlEpSetupInit(udcEpP, ENOERROR);
            }

            if (list_empty(&udcEpP->listQueue)) {
                /** @todo Probably should more closely bind this to DmaDataFinis. */
                udcEpP->dma.usb_req = NULL;
            } else {
                udcEpReqP = list_first_entry(&udcEpP->listQueue, BCM_UDC_EP_REQ_t, listNode);
                udcEpP->dma.usb_req = &udcEpReqP->usb_req;
                DmaDataInit(udcEpP);
                BCM_DEBUG_REQ("%s: begin: req=0x%p buf=0x%p len=%d actual=%d\n",
                                udcEpP->usb_ep.name, &udcEpReqP->usb_req, udcEpReqP->usb_req.buf, udcEpReqP->usb_req.length, udcEpReqP->usb_req.actual);
            }
        }
    }

    if (udcEpP->dma.usb_req != NULL) {
        DmaDataAddReady(udcEpP);
        usbDevHw_EndptDmaEnable(udcEpP->num, udcEpP->dir);
        usbDevHw_EndptNakClear(udcEpP->num, udcEpP->dir);
    }

    BCM_DEBUG_TRACE("%s: exit\n", __func__);
}


/***************************************************************************
 * Linux proc file system functions
 ***************************************************************************/
#ifdef CONFIG_USB_GADGET_DEBUG_FILES

#include <linux/seq_file.h>

static const char bcm_udc_procFileName[] = "driver/" BCM_UDC_NAME;

static int ProcFileShow(struct seq_file *s, void *_)
{
    return(0);
}

static int ProcFileOpen(struct inode *inode, struct file *file)
{
    return(single_open(file, ProcFileShow, NULL));
}

static struct file_operations bcm_udc_procFileOps =
{
    .open       = ProcFileOpen,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static void ProcFileCreate(void)
{
    struct proc_dir_entry *pde;

    pde = create_proc_entry (bcm_udc_procFileName, 0, NULL);
    if (pde) {
        pde->proc_fops = &bcm_udc_procFileOps;
    }
}

static void ProcFileRemove(void)
{
    remove_proc_entry(bcm_udc_procFileName, NULL);
}

#else

static void ProcFileCreate(void) {}
static void ProcFileRemove(void) {}

#endif


#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))

/* Returns USB PHY PLL ref clock in MHz */
static unsigned int _get_usb_clk(void)
{
    unsigned int ndiv = 0, mdiv = 1, usbrefclk;

#if defined(CONFIG_MACH_HX4)
    ndiv = readl_relaxed(IPROC_WRAP_IPROC_XGPLL_CTRL_4_ADDR(iproc_wrap_base)) & 0xff;
    mdiv = (readl_relaxed(IPROC_WRAP_IPROC_XGPLL_CTRL_0_ADDR(iproc_wrap_base)) >>
            IPROC_WRAP_IPROC_XGPLL_CTRL_0__CH3_MDIV_R) & 0xff; /* Ch3 MDIV */
#else
    ndiv = (readl_relaxed(IPROC_DDR_PLL_CTRL_REGISTER_3_ADDR(iproc_wrap_base)) >>
            IPROC_DDR_PLL_CTRL_REGISTER_3__NDIV_INT_R) &
            ((1 << IPROC_DDR_PLL_CTRL_REGISTER_3__NDIV_INT_WIDTH) - 1);

    /* read channel 1 mdiv */
    mdiv = (readl_relaxed(IPROC_DDR_PLL_CTRL_REGISTER_5_ADDR(iproc_wrap_base)) >>
            IPROC_DDR_PLL_CTRL_REGISTER_5__CH1_MDIV_R) &
            ((1 << IPROC_DDR_PLL_CTRL_REGISTER_5__CH1_MDIV_WIDTH) - 1);
#endif

    usbrefclk = (25 * ndiv) / mdiv;

    BCM_DEBUG_DEV("GPLL ndiv = %d, mdiv = %d, USB refclk = %d\n", ndiv, mdiv, usbrefclk);

    return usbrefclk;
}

static int _config_hx4_usbphy(void)
{
    unsigned int usbrefclk, ndiv, precmd, miicmd, miidata;
    static void __iomem *ccb_mdio_base = NULL;

#ifdef CONFIG_OF
    struct device_node *np;

    np = of_find_compatible_node(NULL, NULL, IPROC_CCB_MDIO_COMPATIBLE);
    if (!np) {
        printk(KERN_INFO "Failed to find CCB MDIO defined in DT\n");
        return -ENODEV;
    }

    ccb_mdio_base = of_iomap(np, 0);
    if (!ccb_mdio_base) {
        printk(KERN_ERR "Unable to iomap CCB MDIO base address\n");
        return -ENXIO;
    }
#else
    ccb_mdio_base = ioremap_nocache(IPROC_CCB_MDIO_BASE, IPROC_CCB_MDIO_REG_SIZE);
    if (!ccb_mdio_base) {
        printk(KERN_ERR "Unable to iomap IPROC WRAP ctrl base address\n");
        return -ENXIO;
    }
#endif /* CONFIG_OF */

    usbrefclk = _get_usb_clk();
    ndiv = 1920 / usbrefclk;

    /* Construct precmd with Start Bit, PHY address and turnaround time */
    /* SB | PA | TA */
    precmd = 1 << 30 | 6 << 23 | 2 << 16;

    /* Connect MDIO interface to onchip PHY */
    writel_relaxed(0x9A, IPROC_CCB_MDIO_MII_CTRL_ADDR(ccb_mdio_base));
    mdelay(10);

    /* Program NDIV and PDIV into 0x1C register */
    miicmd = precmd | (0x1 << 28) | (0x1C << 18);
    miidata = 1 << 12 | ndiv;
    /* 0x53721040 */
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);

    /* Program other PLL parameters into 0x1D register, disable suspend and put PHY into reset */
    miicmd = precmd | (0x1 << 28) | (0x1D << 18);
    miidata = 1 << 13 | 3 << 8 | 3 << 4 | 0xa;
    /* 0x5376233a  */
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);

    /* Program register 0x15, USB device mode set and get PHY out of reset */
    miicmd = precmd | (0x1 << 28) | (0x15 << 18);
    miidata = 1 << 2 | 1 << 1;
    /* 0x53560006 */
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);

    /* Program register 0x19, set mdio mode */
    miicmd = precmd | (0x1 << 28) | (0x19 << 18);
    miidata = 1 << 7;
    /* 0x53660080 */
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);

    /* get the PLL out of reset */
    miicmd = precmd | (0x2 << 28) | (0x1D << 18);
    miidata = 0;
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);
    miidata = readl_relaxed(IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    miicmd = precmd | (0x1 << 28) | (0x1D << 18);
    miidata |= (1 << 12);
    /* 0x5376333a  */
    writel_relaxed(miicmd | miidata, IPROC_CCB_MDIO_MII_DATA_ADDR(ccb_mdio_base));
    mdelay(10);

    if (ccb_mdio_base) {
        iounmap(ccb_mdio_base);
        ccb_mdio_base = NULL;
    }

    return ENOERROR;
}

static int usbd_hx4_config(void)
{
    unsigned long val;
    int ret = ENOERROR;

    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));

    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));

    ret = _config_hx4_usbphy();
    if (ret < 0) {
        return ret;
    }

    /* Enable clock to USBD and get the USBD out of reset  */
    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));

    mdelay(10);
    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));

    return ret;
}
#else
#define usbd_hx4_config()       NULL
#endif /* (defined (CONFIG_MACH_HX4) || defined (CONFIG_MACH_KT2)) */

#if defined(CONFIG_MACH_SB2)
static int _config_sb2_usbphy(void)
{
    unsigned long val, mask;
    int count = 0;

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val |= 0x0c000000;      /* 27:PHY_ISO & 26:PLL_SUSPEND_EN = 1 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val &= ~0x03000000;     /* 25:PLL_RESETB & 24:RESETB = 0 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val &= ~0x03000000;     /* 25:AFE_BG_PWRDWNB & 24:AFE_LDO_PWRDWNB = 0 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    udelay(10);
    val |= 0x02000000;      /* 25:AFE_BG_PWRDWNB = 1 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    udelay(150);
    val |= 0x01000000;      /* 24:AFE_LDO_PWRDWNB = 1 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    udelay(160);

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val &= ~0x08000000;     /* 27:PHY_ISO = 0 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    udelay(20);
    val |= 0x02000000;      /* 25:PLL_RESETB = 1 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    mdelay(20);

    /* check pll_lock */
    mask = (1 << IPROC_WRAP_MISC_STATUS__USBPHY_PLL_LOCK);
    do {
        val = readl_relaxed(IPROC_WRAP_MISC_STATUS_ADDR(iproc_wrap_base));
        if ((val & mask) == mask)
            break;
        else {
            udelay(10);
            count ++;
        }
    } while(count <= 10);

    if (count > 10) {
        printk(KERN_WARNING "%s : PLL not lock! IPROC_WRAP_MISC_STATUS = 0x%08lx\n",
               __FUNCTION__, val);
    }

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val |= 0x01000000;      /* 24:RESETB = 1 */
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    udelay(2);

    return ENOERROR;
}

static int usbd_sb2_config(void)
{
    int ret = ENOERROR;
    unsigned long val;

    /* u-boot enable this bit to indicate usb in host mode */
    if (readl_relaxed(IPROC_WRAP_IPROC_STRAP_CTRL_ADDR(iproc_wrap_base)) & (1 << 10)) {
        return -ENODEV;
    }

    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));

    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    mdelay(10);

    /* Enable clock to USBD */
    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    mdelay(10);

    /* Get USBD out of reset  */
    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    mdelay(100);

    /* Configure USB PHY and PHY PLL to drive 60MHz USB clock*/
    ret = _config_sb2_usbphy();
    if (ret < 0) {
        return ret;
    }

    /* Dev configuration */
    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val |= 0x07ff0000;
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    mdelay(10);
    val &= ~0x07ff0000;
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    mdelay(10);

    /* AXI related configuration */
    val = readl_relaxed(ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    val &= ~0x1f1f0fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    val |= 0x0f0f0fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    val = readl_relaxed(ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    val &= ~0x10100000;
    writel_relaxed(val, ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    val &= ~0x00000fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_0_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_1_ADDR(icfg_usb2d_base));
    val |= 0x00000fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_1_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_1_ADDR(icfg_usb2d_base));
    val &= ~0x00000fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_1_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_2_ADDR(icfg_usb2d_base));
    val |= 0x00000fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_2_ADDR(icfg_usb2d_base));
    mdelay(10);

    val = readl_relaxed(ICFG_USB2D_CONFIG_2_ADDR(icfg_usb2d_base));
    val &= ~0x00000fff;
    writel_relaxed(val, ICFG_USB2D_CONFIG_2_ADDR(icfg_usb2d_base));
    mdelay(10);

    /* Dev configuration */
    val = readl_relaxed(USB2D_DEVCONFIG_ADDR(usb2d_base));
    val |= 0x00040028;     /* 18:SET_DESC & 5:PI & 3:SP = 1 */
    writel_relaxed(val, USB2D_DEVCONFIG_ADDR(usb2d_base));
    val &= ~0x00000040;    /* 6:DIR = 0 */
    writel_relaxed(val, USB2D_DEVCONFIG_ADDR(usb2d_base));
    val &= ~0x00000011;    /* 0-1:SPD = 00 */
    writel_relaxed(val, USB2D_DEVCONFIG_ADDR(usb2d_base));
    mdelay(10);

    /* Dev control */
    val = readl_relaxed(USB2D_DEVCTRL_ADDR(usb2d_base));
    val |= 0x00000350;     /* 4:DU & 6:BF & 8:BREN & 9:MODE = 1 */
    writel_relaxed(val, USB2D_DEVCTRL_ADDR(usb2d_base));
    /* val |= 0x00002000; */  /* 13:CSR_DONE = 1 */
    /* writel_relaxed(val, USB2D_DEVCTRL_ADDR(usb2d_base)); */
    val |= 0x0a0a0000;     /* 16-23:BRLEN & 24-31:THLEN = random(3,15), give 10 */
    writel_relaxed(val, USB2D_DEVCTRL_ADDR(usb2d_base));

    return ret;
}
#else
#define usbd_sb2_config()       NULL
#endif /* defined(CONFIG_MACH_SB2) */

#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2))
static int _config_gh_usbphy(void)
{
    unsigned long val, mask;
    int count = 0;

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__PHY_ISO);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__PHY_IDDQ);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B0);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    /* set phy_resetb to 0, pll_resetb to 0 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__RESETB);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__PLL_RESETB);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    /* set p1ctl[11] to 0 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B11);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    /* set phy_iso to 0 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__PHY_ISO);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    /* set phy_iddq to 0 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_0__PHY_IDDQ);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    mdelay(1);

    /* set pll_resetb to 1, phy_resetb to 1 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__PLL_RESETB);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_0__RESETB);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_0_ADDR(iproc_wrap_base));

    mdelay(20);

    /* check pll_lock */
    mask = (1 << IPROC_WRAP_MISC_STATUS__USBPHY_PLL_LOCK);
    do {
        val = readl_relaxed(IPROC_WRAP_MISC_STATUS_ADDR(iproc_wrap_base));
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
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val &= ~(1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B0);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    /* set p1ctl[11] to 1 */
    val = readl_relaxed(IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));
    val |= (1 << IPROC_WRAP_USBPHY_CTRL_2__P1CTL_B11);
    writel_relaxed(val, IPROC_WRAP_USBPHY_CTRL_2_ADDR(iproc_wrap_base));

    return ENOERROR;
}

static int usbd_gh_config(void)
{
    int ret;
    unsigned long val;

    /* Put USBD controller into reset state and disable clock via IDM registers */
    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));

    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));

    ret = _config_gh_usbphy();
    if (ret < 0) {
        return ret;
    }

    /* Enable clock to USBD and get the USBD out of reset  */
    val = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
    val |= (1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
    writel_relaxed(val, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));

    mdelay(10);
    val = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    val &= ~(1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
    writel_relaxed(val, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));

    return ENOERROR;
}
#else
#define usbd_gh_config()        NULL
#endif /* (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined (CONFIG_MACH_GH2)) */

#ifdef CONFIG_OF
static const struct of_device_id usbd_iproc_dt_ids[] = {
    { .compatible = "brcm,usbd,hx4", },
    { .compatible = "brcm,usbd,kt2", },
    { .compatible = "brcm,usbd,gh", },
    { .compatible = "brcm,usbd,sb2", },
    { .compatible = "brcm,usbd,hr3", },
    { .compatible = "brcm,usbd,gh2", },
    { }
};
MODULE_DEVICE_TABLE(of, usbd_iproc_dt_ids);
#endif /* CONFIG_OF */

/****************************************************************************
 ***************************************************************************/
int PlatformDriverProbe(struct platform_device *pdev)
{
    int ret = ENOERROR;
    unsigned num;

#ifdef CONFIG_OF
    const struct of_device_id *match;
    struct device_node *dn = pdev->dev.of_node;
    struct device_node *np;
    unsigned int gpio_pin;
    int irq;

    match = of_match_device(usbd_iproc_dt_ids, &pdev->dev);
    if (!match) {
        dev_err(&pdev->dev, "Failed to find USBD in DT\n");
        return -ENODEV;
    }

    usb2d_base = of_iomap(dn, 0);
    if (!usb2d_base) {
        printk(KERN_ERR "Unable to iomap USB2D base address\n");
        return -ENXIO;
    }

    idm_usb2d_base = of_iomap(dn, 1);
    if (!idm_usb2d_base) {
        printk(KERN_ERR "Unable to iomap USB2D IDM base address\n");
        ret = -ENXIO;
        goto err1;
    }

    irq = (unsigned int)irq_of_parse_and_map(dn, 0);

    if (of_property_read_u32(dn, "gpio-pin-usb-power", &gpio_pin)) {
        dev_warn(&pdev->dev, "missing gpio-pin-usb-power property (default to 10)\n");
        gpio_pin = 10;
    }

    np = of_find_compatible_node(NULL, NULL, IPROC_WRAP_CTRL_COMPATIBLE);
    if (!np) {
        printk(KERN_INFO "Failed to find wrap ctrl defined in DT\n");
        ret = -ENODEV;
        goto err1;
    }

    iproc_wrap_base = of_iomap(np, 0);
    if (!iproc_wrap_base) {
        printk(KERN_ERR "Unable to iomap IPROC WRAP ctrl base address\n");
        ret = -ENXIO;
        goto err1;
    }

    if (strstr(match->compatible, "sb2")) {
        icfg_usb2d_base = of_iomap(dn, 2);
        if (!icfg_usb2d_base) {
            printk(KERN_ERR "Unable to iomap ICFG USB2D base address\n");
            ret = -ENXIO;
            goto err1;
        }
        ret = (int)usbd_sb2_config();
    } else {
        if (gpio_request(gpio_pin, "usbd") == 0) {
            gpio_direction_input(gpio_pin);
            if (__gpio_get_value(gpio_pin) == 0) {
                ret = -ENODEV;
                gpio_free(gpio_pin);
                goto err1;
            }
        } else {
            ret = -ENODEV;
            goto err1;
        }
        gpio_free(gpio_pin);

        if (strstr(match->compatible, "hx4") ||
            strstr(match->compatible, "kt2")) { /* HX4, KT2 */
            ret = (int)usbd_hx4_config();
        } else if (strstr(match->compatible, "gh") ||
                   strstr(match->compatible, "hr3") ||
                   strstr(match->compatible, "gh2")) {    /* GH, HR3, GH2 */
            ret = (int)usbd_gh_config();
        }
    }
    if (ret < 0) {
        goto err1;
    }
#else
    int irq = BCM_UDC_IRQ;

    usb2d_base = ioremap_nocache(IPROC_USB2D_REG_BASE, IPROC_USB2D_REG_SIZE);
    if (!usb2d_base) {
        printk(KERN_ERR "Unable to iomap USB2D base address\n");
        return -ENXIO;
    }

    idm_usb2d_base = ioremap_nocache(USB2D_IDM_IDM_BASE, USB2D_IDM_IDM_REG_SIZE);
    if (!idm_usb2d_base) {
        printk(KERN_ERR "Unable to iomap USB2D IDM base address\n");
        ret = -ENXIO;
        goto err1;
    }

    iproc_wrap_base = ioremap_nocache(IPROC_WRAP_BASE, IPROC_WRAP_REG_SIZE);
    if (!iproc_wrap_base) {
        printk(KERN_ERR "Unable to iomap IPROC WRAP ctrl base address\n");
        ret = -ENXIO;
        goto err1;
    }

#if defined(CONFIG_MACH_SB2)
    icfg_usb2d_base = ioremap_nocache(ICFG_USB2D_CONFIG_BASE, ICFG_USB2D_CONFIG_REG_SIZE);
    if (!icfg_usb2d_base) {
        printk(KERN_ERR "Unable to iomap ICFG USB2D base address\n");
        ret = -ENXIO;
        goto err1;
    }

    ret = (int)usbd_sb2_config();
#else
    if (gpio_request(USBD_VBUS_GPIO, "usbd") == 0) {
        gpio_direction_input(USBD_VBUS_GPIO);
        if (__gpio_get_value(USBD_VBUS_GPIO) == 0) {
            ret = -ENODEV;
            gpio_free(USBD_VBUS_GPIO);
            goto err1;
        }
    } else {
        ret = -ENODEV;
        goto err1;
    }
    gpio_free(USBD_VBUS_GPIO);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
    ret = (int)usbd_hx4_config();
#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2))
    ret = (int)usbd_gh_config();
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_MACH_SB2) */
    if (ret < 0) {
        goto err1;
    }
#endif /* CONFIG_OF */

    usbDevHw_REG_P = usb2d_base;

    if (bcmUdcP != NULL) {
        BCM_KERROR("device already attached\n");
        ret = -EBUSY;
        goto err1;
    }

    bcmUdcP = kzalloc(sizeof(*bcmUdcP), GFP_KERNEL);
    if (!bcmUdcP) {
        BCM_KERROR("kmalloc() failed\n" );
        ret = -ENOMEM;
        goto err1;
    }

    spin_lock_init(&bcmUdcP->lock);

    platform_set_drvdata(pdev, bcmUdcP);
    bcmUdcP->dev = &pdev->dev;

    ret = PlatformDmaAlloc(pdev, bcmUdcP);
    if (ret < 0) {
        BCM_KERROR("PlatformDmaAlloc() failed\n");
        goto err1;
    }

    /* gadget init */
    bcmUdcP->gadget.name = BCM_UDC_NAME;
    bcmUdcP->gadget.speed = USB_SPEED_UNKNOWN;
    bcmUdcP->gadget.max_speed = USB_SPEED_HIGH;
    bcmUdcP->gadget.ops = &bcm_udc_gadgetDevOps;

    UdcOpsInit(bcmUdcP);

    bcmUdcP->gadget.ep0 = &bcmUdcP->ep[0].usb_ep;
    INIT_LIST_HEAD(&bcmUdcP->gadget.ep_list);
    for (num = 1; num < BCM_UDC_EP_CNT; num ++) {
        list_add_tail(&bcmUdcP->ep[num].usb_ep.ep_list, &bcmUdcP->gadget.ep_list);
    }

    usbDevHw_DeviceIrqDisable(usbDevHw_DEVICE_IRQ_ALL);
    usbDevHw_DeviceIrqClear(usbDevHw_DEVICE_IRQ_ALL);

    ret = request_irq(irq, IrqUdc, 0, BCM_UDC_NAME, (void *)bcmUdcP);
    if (ret < 0) {
        BCM_KERROR("request_irq() failed\n");
        goto err2;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
    dev_set_name(&bcmUdcP->gadget.dev, "gadget");
    bcmUdcP->gadget.dev.release = GadgetDevRelease;
    bcmUdcP->gadget.dev.parent = &pdev->dev;
    bcmUdcP->gadget.dev.dma_mask = pdev->dev.dma_mask;

    ret = device_register(&bcmUdcP->gadget.dev);
    if (ret) {
        printk("device_register failed\n");
    }

    ret = usb_add_gadget_udc(&pdev->dev, &bcmUdcP->gadget);
    if (ret < 0) {
        BCM_KERROR("usb_add_gadget_udc() failed\n");
        goto err3;
    }
#else
    ret = usb_add_gadget_udc_release(&pdev->dev, &bcmUdcP->gadget, &GadgetDevRelease);
    if (ret < 0) {
        BCM_KERROR("usb_add_gadget_udc() failed\n");
        goto err3;
    }
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) */

    ProcFileCreate();

    return ENOERROR;


err3:
    free_irq(BCM_UDC_IRQ, bcmUdcP);
err2:
    PlatformDmaFree(pdev, bcmUdcP);
err1:
    if (bcmUdcP) {
        kfree(bcmUdcP);
        bcmUdcP = NULL;
    }
    if (icfg_usb2d_base) {
        iounmap(icfg_usb2d_base);
        icfg_usb2d_base = NULL;
    }
    if (iproc_wrap_base) {
        iounmap(iproc_wrap_base);
        iproc_wrap_base = NULL;
    }
    if (idm_usb2d_base) {
        iounmap(idm_usb2d_base);
        idm_usb2d_base = NULL;
    }
    if (usb2d_base) {
        iounmap(usb2d_base);
        usb2d_base = NULL;
    }

    return ret;
}

int PlatformDriverRemove(struct platform_device *pdev)
{
    volatile unsigned int regval;
#ifdef CONFIG_OF
    struct device_node *dn = pdev->dev.of_node;
    int irq = (unsigned int)irq_of_parse_and_map(dn, 0);
#else
    int irq = BCM_UDC_IRQ;
#endif /* CONFIG_OF */

    if (bcmUdcP) {
        ProcFileRemove();
        GadgetDevRemove(bcmUdcP);
        platform_set_drvdata(pdev, NULL);
        UdcOpsFinis(bcmUdcP);

        PlatformDmaFree(pdev, bcmUdcP);

        free_irq(irq, bcmUdcP);

        kfree(bcmUdcP);
        bcmUdcP = NULL;
    }

    if (idm_usb2d_base) {
        /* Put USBD controller into reset state and disable clock via IDM registers */
        regval = readl_relaxed(USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));
        regval &= ~(1 << USB2D_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
        writel_relaxed(regval, USB2D_IDM_IDM_IO_CONTROL_DIRECT_ADDR(idm_usb2d_base));

        regval = readl_relaxed(USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
        regval |= (1 << USB2D_IDM_IDM_RESET_CONTROL__RESET);
        writel_relaxed(regval, USB2D_IDM_IDM_RESET_CONTROL_ADDR(idm_usb2d_base));
    }

    if (icfg_usb2d_base) {
        iounmap(icfg_usb2d_base);
        icfg_usb2d_base = NULL;
    }
    if (iproc_wrap_base) {
        iounmap(iproc_wrap_base);
        iproc_wrap_base = NULL;
    }
    if (idm_usb2d_base) {
        iounmap(idm_usb2d_base);
        idm_usb2d_base = NULL;
    }
    if (usb2d_base) {
        iounmap(usb2d_base);
        usb2d_base = NULL;
    }

    return ENOERROR;
}

/*
 * Generic platform device driver definition.
 */
#ifdef CONFIG_OF
static struct platform_driver bcm_udc_PlatformDriver =
{
    .probe      = PlatformDriverProbe,
    .remove     = PlatformDriverRemove,
    .driver = {
        .name   = BCM_UDC_NAME,
        .owner  = THIS_MODULE,
        .of_match_table = of_match_ptr(usbd_iproc_dt_ids),
    },
};
#else
static struct platform_driver bcm_udc_PlatformDriver =
{
    .probe      = PlatformDriverProbe,
    .remove     = PlatformDriverRemove,
    .driver = {
        .name   = BCM_UDC_NAME,
        .owner  = THIS_MODULE,
    },
};

static int __init bcm_udc_module_init(void)
{
    int err;

    err = platform_driver_register(&bcm_udc_PlatformDriver);
    if (err) {
        BCM_KERROR("platform_driver_register failed, err=%d\n", err);
        return err;
    }

    err = platform_device_register(&iproc_udc_pdev);
    if (err) {
        BCM_KERROR("platform_device_register failed, err=%d\n", err);
        platform_driver_unregister(&bcm_udc_PlatformDriver);
    }

    return err;
}

static void __exit bcm_udc_module_exit(void)
{
    platform_device_unregister(&iproc_udc_pdev);
    platform_driver_unregister(&bcm_udc_PlatformDriver);
}
#endif /* CONFIG_Of */

#ifdef CONFIG_OF
module_platform_driver(bcm_udc_PlatformDriver);
#else
module_init(bcm_udc_module_init);
module_exit(bcm_udc_module_exit);
#endif /* CONFIG_OF */

MODULE_DESCRIPTION(BCM_UDC_MODULE_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_VERSION(BCM_UDC_MODULE_VERSION);
