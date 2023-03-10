/*
 * drivers/tdm/line_ctrl/slic_maxim.h
 *
 * Copyright 2014 Freescale Semiconductor, Inc.
 *
 * Author: Zhao Qiang <B45475@freescale.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DS26522_RF_ADDR_START	0x00
#define DS26522_RF_ADDR_END	0xef
#define DS26522_GLB_ADDR_START	0xf0
#define DS26522_GLB_ADDR_END	0xff
#define DS26522_TF_ADDR_START	0x100
#define DS26522_TF_ADDR_END	0x1ef
#define DS26522_LIU_ADDR_START	0x1000
#define DS26522_LIU_ADDR_END	0x101f
#define DS26522_TEST_ADDR_START	0x1008
#define DS26522_TEST_ADDR_END	0x101f
#define DS26522_BERT_ADDR_START	0x1100
#define DS26522_BERT_ADDR_END	0x110f

#define DS26522_RMMR_ADDR	0x80
#define DS26522_RCR1_ADDR	0x81
#define DS26522_RCR3_ADDR	0x83
#define DS26522_RIOCR_ADDR	0x84

#define DS26522_GTCR1_ADDR	0xf0
#define DS26522_GFCR_ADDR	0xf1
#define DS26522_GTCR2_ADDR	0xf2
#define DS26522_GTCCR_ADDR	0xf3
#define DS26522_GLSRR_ADDR	0xf5
#define DS26522_GFSRR_ADDR	0xf6
#define DS26522_IDR_ADDR	0xf8

#define DS26522_E1TAF_ADDR	0x164
#define DS26522_E1TNAF_ADDR	0x165
#define DS26522_TMMR_ADDR	0x180
#define DS26522_TCR1_ADDR	0x181
#define DS26522_TIOCR_ADDR	0x184

#define DS26522_LTRCR_ADDR	0x1000
#define DS26522_LTITSR_ADDR	0x1001
#define DS26522_LMCR_ADDR	0x1002
#define DS26522_LRISMR_ADDR	0x1007

#define MAX_NUM_OF_CHANNELS	8
#define PQ_MDS_8E1T1_BRD_REV	0x00
#define PQ_MDS_8E1T1_PLD_REV	0x00

#define DS26522_GTCCR_BPREFSEL_REFCLKIN	0xa0	/* REFCLKIO is an input */
#define DS26522_GTCCR_BFREQSEL_1544KHZ	0x08	/* Backplane reference clock
						   is 1.544MHz */
#define DS26522_GTCCR_FREQSEL_1544KHZ	0x04	/* The external master clock
						   is 1.544MHz or multiple
						   thereof */
#define DS26522_GTCCR_BFREQSEL_2048KHZ	0x00	/* Backplane reference clock
						   is 2.048MHz */
#define DS26522_GTCCR_FREQSEL_2048KHZ	0x00	/* The external master clock is
						   2.048MHz or multiple thereof
						*/

#define DS26522_GFCR_BPCLK_2048KHZ	0x00	/* Backplane Clock Select
						   2.048MHz */

#define DS26522_GTCR2_TSSYNCOUT	0x02	/* the TSSYNCIO is an 8kHz output
					   synchronous to the BPCLK */
#define DS26522_GTCR1	0x00

#define DS26522_GFSRR_RESET	0x01	/* Reset framer and BERT */
#define DS26522_GFSRR_NORMAL	0x00	/* Normal operation */

#define DS26522_GLSRR_RESET	0x01	/* Reset LIU */
#define DS26522_GLSRR_NORMAL	0x00	/* Normal operation */

#define DS26522_RMMR_SFTRST	0x02	/* Level sensitive soft reset */
#define DS26522_RMMR_FRM_EN	0x80	/* Framer enabled???all features
					   active */
#define DS26522_RMMR_INIT_DONE	0x40	/* Initialization Done */
#define DS26522_RMMR_T1		0x00	/* Receiver T1 Mode Select */
#define DS26522_RMMR_E1		0x01	/* Receiver E1 Mode Select */

#define DS26522_E1TAF_DEFAULT	0x1b	/* Transmit Align Frame Register */
#define DS26522_E1TNAF_DEFAULT	0x40	/* Transmit Non-Align Frame Register */

#define DS26522_TMMR_SFTRST	0x02	/* Level sensitive soft reset */
#define DS26522_TMMR_FRM_EN	0x80	/* Framer enabled???all features
					   active */
#define DS26522_TMMR_INIT_DONE	0x40	/* Initialization Done */
#define DS26522_TMMR_T1		0x00	/* Transmit T1 Mode Select */
#define DS26522_TMMR_E1		0x01	/* Transmit E1 Mode Select */

#define DS26522_RCR1_T1_SYNCT	0x80	/* qualify 24 bits */
#define DS26522_RCR1_T1_RB8ZS	0x40	/* B8ZS enabled */
#define DS26522_RCR1_T1_SYNCC	0x08	/* cross couple Ft and Fs pattern */

#define DS26522_RCR1_E1_HDB3	0x40	/* Receive HDB3 enabled */
#define DS26522_RCR1_E1_CCS	0x20	/* Receive CCS signaling mode */

#define DS26522_RIOCR_1544KHZ	0x00	/* RSYSCLK Mode Select is 1.544MHz */
#define DS26522_RIOCR_2048KHZ	0x10	/* RSYSCLK Mode Select is 2.048MHz or
					   IBO enabled */
#define DS26522_RIOCR_RSIO_OUT	0x00	/* RSYNC is an output */

#define DS26522_RCR3_FLB	0x01	/* Framer Loopback enabled */

#define DS26522_TIOCR_1544KHZ	0x00	/* TSYSCLK is 1.544MHz */
#define DS26522_TIOCR_2048KHZ	0x10	/* TSYSCLK is 2.048/4.096/8.192MHz or
					   IBO enabled */
#define DS26522_TIOCR_TSIO_OUT	0x04	/* TSYNC is an output */

#define DS26522_TCR1_TB8ZS	0x04	/* Transmit B8ZS Enable */

#define DS26522_LTRCR_T1	0x02	/* configures the LIU for T1 */
#define DS26522_LTRCR_E1	0x00	/* configures the LIU for E1 */

#define DS26522_LTITSR_TLIS_75OHM	0x00	/* Transmit Load
						   Impedance 75? */
#define DS26522_LTITSR_LBOS_75OHM	0x00	/* Transmit Pulse
						   Shape 75? */
#define DS26522_LTITSR_TLIS_100OHM	0x10	/* Transmit Load
						   Impedance 100? */
#define DS26522_LTITSR_TLIS_0DB_CSU	0x00	/* DSX-1/0dB CSU,
						   0ft???133ft ABAM 100? */

#define DS26522_LRISMR_75OHM	0x00	/* Receive Impedance 75? */
#define DS26522_LRISMR_100OHM	0x10	/* Receive Impedance 100? */
#define DS26522_LRISMR_MAX	0x03	/* Receive Impedance 120? */

#define DS26522_LMCR_TE	0x01	/* TTIP/TRING outputs enabled */


enum line_rate_t {
	LINE_RATE_T1,	/* T1 line rate (1.544 Mbps)      */
	LINE_RATE_E1	/* E1 line rate (2.048 Mbps)     */
};

enum tdm_trans_mode_t {
	NORMAL = 0,
	FRAMER_LB
};

enum card_support_type {
	LM_CARD = 0,
	DS26522_CARD,
	NO_CARD
};
