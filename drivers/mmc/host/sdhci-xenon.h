/*
 * Temporarily added MMC HS400 macro
 */
#define MMC_TIMING_MMC_HS400    10
#define MMC_CAP2_HS400_1_8V     (1 << 15)       /* Can support HS400 1.8V */
#define MMC_CAP2_HS400_1_2V     (1 << 16)       /* Can support HS400 1.2V */
#define MMC_CAP2_HS400          (MMC_CAP2_HS400_1_8V | \
				 MMC_CAP2_HS400_1_2V)
