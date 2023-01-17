##############################################################################
#
# (C) Copyright 2013 Open-Silicon, Inc.
# <info@open-silicon.com>
#
# Makefile for Open-Silicon OPV5XC PSE Linux device driver.
#
# See file CREDITS for list of people who contributed to this
# project.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA
##############################################################################

DRIVER_NAME = pse

obj-$(CONFIG_OPV5XC_PSE) += $(DRIVER_NAME).o

$(DRIVER_NAME)-objs := pse_ring.o \
			pse_vlan.o pse_mac.o \
			pse_sys.o pse_ethtool.o \
			pse_mii.o pse_phy.o \
			pse_tc.o pse_tx_sch.o pse_police.o \
			pse_fc.o pse_shape.o pse_intr.o \
			pse_proc.o pse_sysfs.o \
			pse_process.o \
			pse_debug.o \
			pse_main.o
