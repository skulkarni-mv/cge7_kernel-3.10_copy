/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.

*******************************************************************************/
#include "mvPp2Common.h"

/*#define PP2_REG_WRITE_TRACE*/
/*#define PP2_REG_READ_TRACE*/

int mvPp2WrReg(unsigned int offset, unsigned int  val)
{
	MV_PP2_REG_WRITE(offset, val);

#if defined(PP2_REG_WRITE_TRACE)
	mvOsPrintf("REG:0x%08X	W:0x%08X\n", offset, val);
#endif
	return val;
}

int mvPp2RdReg(unsigned int offset)
{
	unsigned int val = MV_PP2_REG_READ(offset);

#if defined(PP2_REG_READ_TRACE)
	mvOsPrintf("REG:0x%08X	R:0x%08X\n", offset, val);
#endif
	return val;
}

int mvPp2SPrintReg(char *buf, unsigned int  reg_addr, char *reg_name)
{
	return mvOsSPrintf(buf, "  %-32s: 0x%x = 0x%08x\n", reg_name, reg_addr, mvPp2RdReg(reg_addr));
}

void mvPp2PrintReg(unsigned int reg_addr, char *reg_name)
{
	mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", reg_name, reg_addr, mvPp2RdReg(reg_addr));
}

void mvPp2PrintReg2(MV_U32 reg_addr, char *reg_name, MV_U32 index)
{
	char buf[64];

	mvOsSPrintf(buf, "%s[%d]", reg_name, index);
	mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", buf, reg_addr, mvPp2RdReg(reg_addr));
}

void mvPp2RegPrintNonZero(MV_U32 reg_addr, char *reg_name)
{
	unsigned int regVal = MV_REG_READ(reg_addr);

	if (regVal)
		mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", reg_name, reg_addr, regVal);
}

void mvPp2RegPrintNonZero2(MV_U32 reg_addr, char *reg_name, MV_U32 index)
{
	char buf[64];
	unsigned int regVal = MV_REG_READ(reg_addr);

	if (regVal) {
		mvOsSPrintf(buf, "%s[%d]", reg_name, index);
		mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", buf, reg_addr, regVal);
	}
}

