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
#ifndef __INCmvVideoh
#define __INCmvVideoh

/* includes */

/* Defines */

typedef struct mvVideoResolution {
	MV_U32 width;
	MV_U32 height;
	char *name;
} MV_VIDEO_RESOLUTION;

/*
 * Basic window sizes.
 */

#define VGA_WIDTH	640
#define VGA_HEIGHT	480
#define QVGA_WIDTH	320
#define QVGA_HEIGHT	240
#define CIF_WIDTH	352
#define CIF_HEIGHT	288
#define QCIF_WIDTH	176
#define	QCIF_HEIGHT	144

#define MV_VIDEO_RESOLUTION_VGA {VGA_WIDTH, VGA_HEIGHT, "VGA"}
#define MV_VIDEO_RESOLUTION_QVGA {QVGA_WIDTH, QVGA_HEIGHT, "QVGA"}
#define MV_VIDEO_RESOLUTION_CIF {CIF_WIDTH, CIF_HEIGHT, "CIF"}
#define MV_VIDEO_RESOLUTION_QCIF {QCIF_WIDTH, QCIF_HEIGHT, "QCIF"}

/* Pixel format */
typedef enum mvPixFormatId {
	MV_PIX_FORMAT_ID_RGB444 = 0x444,
	MV_PIX_FORMAT_ID_RGB555 = 0x555,
	MV_PIX_FORMAT_ID_RGB565 = 0x565,
	MV_PIX_FORMAT_ID_YUV422 = 0x422,
	MV_PIX_FORMAT_ID_RAW_BAYER = 0x111
} MV_PIX_FORMAT_ID;

typedef struct mvPixelFormat {
	MV_PIX_FORMAT_ID id;
	char *name;
} MV_PIXEL_FORMAT;

/* known formats */
#define MV_PIXEL_FORMAT_RGB444	{MV_PIX_FORMAT_ID_RGB444, "RGB444"}
#define MV_PIXEL_FORMAT_RGB555  {MV_PIX_FORMAT_ID_RGB555, "RGB555"}
#define MV_PIXEL_FORMAT_RGB565  {MV_PIX_FORMAT_ID_RGB565, "RGB565"}
#define MV_PIXEL_FORMAT_YUV422  {MV_PIX_FORMAT_ID_YUV422, "YUV422"}
#define MV_PIXEL_FORMAT_RAW_BAYER  {MV_PIX_FORMAT_ID_RAW_BAYER, "RAW BAYER"}

typedef struct {
	MV_PIXEL_FORMAT pixelFormat;
	MV_VIDEO_RESOLUTION resolution;
} MV_IMAGE_FORMAT;

#endif /* __INCmvVideoh */
