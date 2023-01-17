# File: bcmdrivers/Makefile
#
# Makefile for the Linux kernel modules.
#
# Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
-include $(KERNEL_DIR)/.config

export BCMDRIVERS_DIR:=$(src)

# The following must have config defined for each driver

obj-y += timer/
obj-y += otp/
obj-y += rng/
obj-y += mdio/
obj-y += gsio_spi/
obj-y += sd/
obj-y += qspi/
obj-y += nand/
obj-y += gpio/
obj-y += usb2h/
obj-y += usb3h/
obj-m += usbd/
obj-y += pcie/
obj-$(CONFIG_ET) += gmac/et/
obj-y += gmac/hnd/
#obj-y += smbus/
obj-y += sra/
obj-y += pmu/
obj-y += ../bcmgpldrivers/

clean: 
