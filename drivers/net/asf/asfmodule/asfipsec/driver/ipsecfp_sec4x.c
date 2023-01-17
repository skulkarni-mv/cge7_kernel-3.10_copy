/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp_sec4x.c
 * Description: Contains the optimized routines for accessing SEC3X
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *		Sandeep Malik <sandeep.malik@freescale.com>
 *
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/
#ifdef CONFIG_ASF_SEC4x

#include <linux/ip.h>
#include <net/ip.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <linux/version.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include <net/dst.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include "ipseccmn.h"
#include "../../asfffp/driver/asfreasm.h"
#ifdef ASF_SECFP_PROTO_OFFLOAD
#include <pdb.h>
#endif
#include "dcl.h"
extern struct device *pdev;

#define xstr(s) str(s)
#define str(s) #s

#define GET_CACHE_ALLIGNED(x) (uintptr_t *)(((uintptr_t)x + (L1_CACHE_BYTES - 1)) \
	& ~(L1_CACHE_BYTES - 1))

static void secfp_splitKeyDone(struct device *dev, u32 *desc, u32 error,
				void *context)
{
	if (error) {
#ifdef ASF_IPSEC_DEBUG
		ASFIPSEC_DPERR("%08x", error);
		if (net_ratelimit())
			caam_jr_strstatus(dev, error);
#endif
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
	}

	kfree(desc);
}
/*
get a split ipad/opad key

Split key generation-----------------------------------------------

[00] 0xb0810008 jobdesc: stidx=1 share=never len=8
[01] 0x04000014 key: class2->keyreg len=20
			@0xffe01000
[03] 0x84410014 operation: cls2-op sha1 hmac init dec
[04] 0x24940000 fifold: class2 msgdata-last2 len=0 imm
[05] 0xa4000001 jump: class2 local all ->1 [06]
[06] 0x64260028 fifostr: class2 mdsplit-jdk len=40
			@0xffe04000
*/
unsigned int secfp_genCaamSplitKey(struct caam_ctx *ctx,
					const u8 *key_in, u32 authkeylen)
{
	u32 *desc;
	dma_addr_t dma_addr_in, dma_addr_out;
	int ret = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	desc = kzalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_DMA | flags);
	if (!desc) {
		ASFIPSEC_DEBUG("Unable to allocate memory\n");
		return -ENOMEM;
	}

	init_job_desc(desc, 0);

	dma_addr_in = dma_map_single(ctx->jrdev, (void *)key_in, authkeylen,
				DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, dma_addr_in)) {
		ASFIPSEC_DEBUG("secfp_genCaamSplitKey: Unable to map key"\
				"input memory\n");
		kfree(desc);
		return -ENOMEM;
	}

	append_key(desc, dma_addr_in, authkeylen, CLASS_2 |
		KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	append_operation(desc, ctx->alg_op | OP_ALG_DECRYPT |
			OP_ALG_AS_INIT);

	/*
	* do a FIFO_LOAD of zero, this will trigger the internal key expansion
	into both pads inside MDHA
	*/
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/*
	* FIFO_STORE with the explicit split-key content store
	* (0x26 output type)
	*/
	dma_addr_out = dma_map_single(ctx->jrdev, ctx->key,
				ctx->split_key_pad_len, DMA_FROM_DEVICE);
	if (dma_mapping_error(ctx->jrdev, dma_addr_out)) {
		ASFIPSEC_DEBUG("secfp_genCaamSplitKey: Unable to map key"\
				"input memory\n");
		kfree(desc);
		return -ENOMEM;
	}

	append_fifo_store(desc, dma_addr_out, ctx->split_key_len,
			LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

#ifdef ASFIPSEC_DEBUG_FRAME
	pr_err("\nDMA_ADDR_IN: %x authkeylen %d flags %x",
			dma_addr_in, authkeylen, CLASS_2 | KEY_DEST_CLASS_REG);
	pr_err("\nCTX ALG OP %x",
				ctx->alg_op | OP_ALG_DECRYPT | OP_ALG_AS_INIT);
	pr_err("\nDMA_ADDR_OUT: %x flags %x", dma_addr_out,
				LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);
	pr_err("\nsplit_key_len %d split_key_pad_len %d",
				ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "ctx.key@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, key_in, authkeylen, 1);
	print_hex_dump(KERN_ERR, "jobdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	ret = caam_jr_enqueue(ctx->jrdev, desc, secfp_splitKeyDone, NULL);
	if (ret) {
		ASFIPSEC_DEBUG("caam_jr_enqueue failed ");
		kfree(desc);
	}

	return ret;
}

/*
get a encrypted key for null_xcbc

key generation-----------------------------------------------

[00] B080000C jobhdr: stidx=0 len=12
[01] 02800010 key: class1-keyreg len=16 imm
[06] 22920000 fifold: class1 msg-last1 len=0 imm
[07] 82100705 operation: cls1-op aes xcbc-mac init enc
[08] 52201020 str: ccb1-ctx+16 len=32
[10] 62240010 fifostr: class1 keyreg-jdk len=16
*/
unsigned int secfp_genCaamSplitKey_null_xcbc(struct caam_ctx *ctx,
	const u8 *key_in, u32 authkeylen)
{
	u32 *desc;
	int ret = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	u8 *k3;

	desc = kzalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_DMA | flags);
	if (!desc) {
		ASFIPSEC_DPERR("Memory allocation failiure");
		return -ENOMEM;
	}

	/* k1 and k3 keys are generated for null_xcbc and the SEC block uses
	these keys to authenticate the packets */

	ctx->k3_null_xcbc = kzalloc(K3_NULL_XCBC_LEN + L1_CACHE_BYTES - 1,
			GFP_DMA | flags);
	if (!ctx->k3_null_xcbc) {
		kfree(desc);
		ASFIPSEC_DPERR("Memory allocation failiure");
		return -ENOMEM;
	}

	k3 = (u8 *) GET_CACHE_ALLIGNED(ctx->k3_null_xcbc);

	/* Job descriptor being created which will be submitted to caam to
	generate k1 (ctx->key) and k3 required for null xcbc*/
	init_job_desc(desc, 0);

	ctx->k3_null_xcbc_phys = dma_map_single(ctx->jrdev,
			(void *)k3, K3_NULL_XCBC_LEN, DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, ctx->k3_null_xcbc_phys)) {
		ASFIPSEC_DPERR("secfp_genCaamSplitKey: Unable to map key"\
			"input memory\n");
		ret = -ENOMEM;
		goto error;
	}

	append_key_as_imm(desc, (void *)key_in, authkeylen,
	authkeylen, CLASS_1 | KEY_DEST_CLASS_REG);

	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_1_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);

	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_AES |
		OP_ALG_AAI_XCBC_MAC | OP_ALG_ENCRYPT | OP_ALG_AS_INIT);

	append_cmd(desc, CMD_STORE | LDST_CLASS_1_CCB |
			LDST_SRCDST_BYTE_CONTEXT | K3_NULL_XCBC_LEN |
			K3_NULL_XCBC_OFFSET << LDST_OFFSET_SHIFT);
	append_ptr(desc, ctx->k3_null_xcbc_phys);

	append_cmd(desc, CMD_FIFO_STORE | LDST_CLASS_1_CCB |
			FIFOST_TYPE_KEY_KEK | ctx->split_key_pad_len);
	append_ptr(desc, ctx->key_phys);

	ret = caam_jr_enqueue(ctx->jrdev, desc, secfp_splitKeyDone, NULL);
	if (ret) {
		ASFIPSEC_DPERR("secfp_caam_submit failed ");
		goto error;
	}

	return ret;

error:
	dma_unmap_single(ctx->jrdev, ctx->k3_null_xcbc_phys,
	K3_NULL_XCBC_LEN, DMA_TO_DEVICE);
	kfree(ctx->k3_null_xcbc);
	kfree(desc);
	ctx->k3_null_xcbc = NULL;
	return ret;
}

static inline u32 alg_to_caamdesc(u8 cipheralg, u8 authalg)
{
	u32 descwd = 0;

	/*
	* Note that these cipher selectors match the PFKEY selectors
	* almost 1 for 1, so this is really little more than an error
	* check
	*/
	switch (cipheralg) {
	case SECFP_DES:
		descwd |= OP_PCL_IPSEC_DES_IV64;
		break;

	case SECFP_3DES:
		descwd |= OP_PCL_IPSEC_3DES;
		break;

	case SECFP_AES:
		descwd |= OP_PCL_IPSEC_AES_CBC;
		break;

	case SECFP_AESCTR:
		descwd |= OP_PCL_IPSEC_AES_CTR;
		break;

	case SECFP_AES_CCM_ICV8:
		descwd |= OP_PCL_IPSEC_AES_CCM8;
		break;

	case SECFP_AES_CCM_ICV12:
		descwd |= OP_PCL_IPSEC_AES_CCM12;
		break;

	case SECFP_AES_CCM_ICV16:
		descwd |= OP_PCL_IPSEC_AES_CCM16;
		break;

	case SECFP_AES_GCM_ICV8:
		descwd |= OP_PCL_IPSEC_AES_GCM8;
		break;

	case SECFP_AES_GCM_ICV12:
		descwd |= OP_PCL_IPSEC_AES_GCM12;
		break;

	case SECFP_AES_GCM_ICV16:
		descwd |= OP_PCL_IPSEC_AES_GCM16;
		break;
	case SECFP_NULL_AES_GMAC:
		/*
		* hard code for PROTOCOL operation, should
		* add #define in linux
		*/
		descwd |= 0x1500;
		break;
	case SECFP_ESP_NULL:
		/*
		* hard code for PROTOCOL operation, should
		* add #define in linux
		*/
		descwd |= OP_PCL_IPSEC_NULL;
		break;
	}

	/*
	* Authentication selectors. These do not match the PFKEY
	* selectors
	*/
	switch (authalg) {
	case SECFP_HMAC_MD5:
		descwd |= OP_PCL_IPSEC_HMAC_MD5_96;
		break;

	case SECFP_HMAC_SHA1:
		descwd |= OP_PCL_IPSEC_HMAC_SHA1_96;
		break;

	case SECFP_HMAC_AES_XCBC_MAC:
		descwd |= OP_PCL_IPSEC_AES_XCBC_MAC_96;
		break;

	case SECFP_HMAC_NULL:
		descwd |= OP_PCL_IPSEC_HMAC_NULL;
		break;

	case SECFP_HMAC_SHA1_160:
		descwd |= OP_PCL_IPSEC_HMAC_SHA1_160;
		break;

	case SECFP_HMAC_SHA256:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_256_128;
		break;

	case SECFP_HMAC_SHA384:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_384_192;
		break;

	case SECFP_HMAC_SHA512:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_512_256;
		break;
	}
	return descwd;
}

int secfp_prepareDecapShareDescDesXcbc(struct caam_ctx *ctx,
	u32 *sh_desc, inSA_t *pSA)
{
	append_jump(sh_desc, JUMP_JSL | JUMP_COND_SHRD |
		JUMP_COND_SELF | 0x03);
	append_key(sh_desc, ctx->key_phys, 0x20,
		CLASS_2 | KEY_DEST_MDHA_SPLIT);
	append_load_imm_u32(sh_desc, 0x20080065,
		LDST_SRCDST_WORD_DECO_MATH0 | 0x4);
	append_key(sh_desc, ctx->key_phys, 0x10,
		CLASS_1 | KEY_DEST_CLASS_REG);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		append_math_sub_imm_u32(sh_desc, REG0, SEQINLEN,
			IMM, 0x00000034);
	} else {
		append_math_sub_imm_u32(sh_desc, REG0, SEQINLEN,
			IMM, 0x00000020);
	}
	append_math_sub(sh_desc, VARSEQINLEN, REG0, ZERO, 0x04);
	append_operation(sh_desc, OP_TYPE_CLASS2_ALG |
		OP_ALG_AS_INITFINAL | OP_ALG_ALGSEL_MD5
		| OP_ALG_AAI_HMAC_PRECOMP | OP_ALG_ENCRYPT);
	append_operation(sh_desc, OP_TYPE_CLASS1_ALG|
		OP_ALG_AS_INITFINAL | OP_ALG_ALGSEL_AES |
		OP_ALG_AAI_XCBC_MAC | OP_ALG_ICV_ON |
		OP_ALG_DECRYPT);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		append_seq_fifo_load(sh_desc, 0x28, 0);
	else
		append_seq_fifo_load(sh_desc, 0x14, 0);
	append_seq_fifo_load(sh_desc, 0x0, FIFOLD_CLASS_CLASS1 |
		FIFOLD_TYPE_MSG | FIFOLD_TYPE_FLUSH1 | FIFOLDST_VLF);
	append_seq_fifo_load(sh_desc, 0x0C, FIFOLD_CLASS_CLASS1 |
		FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_FLUSH1 | FIFOLD_TYPE_ICV);
	append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
		0xDC << MOVE_OFFSET_SHIFT | MOVE_DEST_MATH1 | 0x10);
	append_math_imm(OR, sh_desc, REG1, REG1, IMM, 0x08,
		MATH_IFB, 0x08000000);
	append_load_imm_u32(sh_desc, 0xA00000E1, LDST_CLASS_DECO |
		LDST_SRCDST_WORD_DECO_MATH3 | 0x0404);
	append_math_shld(sh_desc, REG3, REG3, REG3, 8);
	append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_MATH1|
		MOVE_DEST_DESCBUF | 0xEC << MOVE_OFFSET_SHIFT | 0x14);
	append_jump(sh_desc, JUMP_TEST_ALL | 0x1E);
	append_jump(sh_desc, JUMP_TEST_ALL | 0xF3);
	append_seq_in_ptr_pre_rto(sh_desc, 0xFFFF, SQIN_RTO);
	append_math_sub(sh_desc, VARSEQINLEN, REG0, ZERO, 0x04)
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		append_math_add_imm_u32(sh_desc, VARSEQOUTLEN,
			REG0, IMM, 0x00000028);
	} else {
		append_math_add_imm_u32(sh_desc, VARSEQOUTLEN,
			REG0, IMM, 0x00000014);
	}
	append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
		MOVE_DEST_OUTFIFO | 0x7C << MOVE_OFFSET_SHIFT | 0x08);
	append_move(sh_desc, MOVE_SRC_OUTFIFO | 0xE0
		<< MOVE_OFFSET_SHIFT | MOVE_DEST_DESCBUF | 0x08);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		append_seq_fifo_load(sh_desc, 0x28, 0);
	else
		append_seq_fifo_load(sh_desc, 0x14, 0);
	append_seq_fifo_load(sh_desc, 0x0, FIFOLD_CLASS_CLASS2 |
		FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2 | FIFOLDST_VLF);
	append_seq_fifo_store(sh_desc, 0x0, FIFOLDST_SGF |
		FIFOST_TYPE_SKIP);
	append_seq_store(sh_desc, 0xC, LDST_CLASS_2_CCB |
		LDST_SRCDST_BYTE_CONTEXT);
	append_jump(sh_desc, JUMP_JSL | JUMP_COND_CALM | 0x0B);
	append_load_imm_u32(sh_desc, 0x202D0065,
		LDST_SRCDST_WORD_DECO_MATH0 | 0x4);
	append_seq_in_ptr_pre_rto(sh_desc, 0xFFFF, SQIN_RTO);

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		append_math_add_imm_u32(sh_desc, SEQINLEN,
			REG0, IMM, 0x00000034);
	} else {
		append_math_add_imm_u32(sh_desc, SEQINLEN,
			REG0, IMM, 0x00000020);
	}
	append_key(sh_desc, ctx->key_phys + ctx->split_key_pad_len,
		ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	append_operation(sh_desc, OP_PCLID_IPSEC | OP_TYPE_DECAP_PROTOCOL |
		alg_to_caamdesc(pSA->SAParams.ucCipherAlgo, SECFP_HMAC_MD5));

	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
				desc_bytes(ctx->sh_desc),
				DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
	return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	pr_err("\n");
	print_hex_dump(KERN_ERR, "shrdesc@"xstr(__LINE__)": ",
	DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
	desc_bytes(sh_desc), 1);
#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(sh_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
#endif
	return 0;
}

int secfp_prepareDecapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
		inSA_t *pSA, bool keys_fit_inline)
{
	u32 *jump_cmd;
	struct ipsec_decap_pdb *pdb;
	u8 *key;
	key = (u8 *) GET_CACHE_ALLIGNED(pSA->ctx.key);

#ifndef ASF_SECFP_PROTO_OFFLOAD
	init_sh_desc(sh_desc, HDR_SAVECTX | HDR_SHARE_SERIAL);
#else
	/*
	* Copy PDB options
	*/
	init_sh_desc_pdb(sh_desc,
		(HDR_SHARE_SERIAL | CMD_SHARED_DESC_HDR | HDR_ONE)
		, sizeof(*pdb));

	/* fill in pdb */
	pdb = sh_desc_pdb(sh_desc);

	pdb->ip_nh_offset = 0;

	pdb->options = PDBOPTS_ESP_OUTFMT;
	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TUNNELMODE)
		pdb->options |= PDBOPTS_ESP_TUNNEL;

	if (pSA->SAParams.bDoAntiReplayCheck) {
		if (pSA->SAParams.AntiReplayWin/32 == 1)
			pdb->options |= PDBOPTS_ESP_ARS32;
		else
			pdb->options |= PDBOPTS_ESP_ARS64;
	}

#ifdef ASF_IPV6_FP_SUPPORT
	/* NH, NH Offse, IP options */
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		pdb->hmo_ip_hdr_len = SECFP_IPV6_HDR_LEN;
		pdb->options |= PDBOPTS_ESP_IPV6;
	} else
#endif
	{
		pdb->hmo_ip_hdr_len = SECFP_IPV4_HDR_LEN;
		pdb->options |= PDBOPTS_ESP_VERIFY_CSUM;
	}
#ifndef ASF_IPV6_FP_SUPPORT
	pdb->hmo_ip_hdr_len |= PDBHMO_ESP_DECAP_DEC_TTL;
#endif

	switch (pSA->SAParams.ucCipherAlgo) {
	case SECFP_AESCTR:
		memcpy((u8 *)(&pdb->ctr.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CTR_SALT_LEN);
		/* typically initial count value is 0x00000001 */
		pdb->ctr.ctr_initial = AES_CTR_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV8:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		/* CCM salt length is 3 bytes, left shift 8 bits */
		pdb->ccm.salt >>= 8;
		pdb->ccm.iv_flags = AES_CCM_ICV8_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV12:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		pdb->ccm.salt >>= 8;
		pdb->ccm.iv_flags = AES_CCM_ICV12_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV16:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		pdb->ccm.salt >>= 8;
		pdb->ccm.iv_flags = AES_CCM_ICV16_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_GCM_ICV8:
	case SECFP_AES_GCM_ICV12:
	case SECFP_AES_GCM_ICV16:
		memcpy((u8 *)(&pdb->gcm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_GCM_SALT_LEN);
		break;
	case SECFP_NULL_AES_GMAC:
		memcpy((u8 *)(&pdb->gcm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_GMAC_SALT_LEN);
		break;
	}

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		pdb->options |= PDBOPTS_ESP_ESN;
		pdb->seq_num_ext_hi = pSA->ulHOSeqNum;
	}
	pdb->seq_num = pSA->ulLastSeqNum;
	pdb->anti_replay[0] = 0;/* Anti-Replay 1 */
	pdb->anti_replay[1] = 0;/* Anti-Replay 2 */

	ASFIPSEC_DEBUG("Created the PDB");

#endif /* ASF_SECFP_PROTO_OFFLOAD */

	if ((SECFP_DES == pSA->SAParams.ucCipherAlgo ||
		SECFP_3DES == pSA->SAParams.ucCipherAlgo) &&
		SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
		int ret = secfp_prepareDecapShareDescDesXcbc(ctx,
				sh_desc, pSA);
		return ret;
	}

	if (SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo &&
		SECFP_ESP_NULL == pSA->SAParams.ucCipherAlgo) {
		append_cmd(sh_desc, CMD_LOAD | LDST_CLASS_1_CCB |
			LDST_SRCDST_BYTE_CONTEXT | K3_NULL_XCBC_LEN |
			K3_NULL_XCBC_OFFSET << LDST_OFFSET_SHIFT);
		append_ptr(sh_desc, ctx->k3_null_xcbc_phys);

		jump_cmd = append_jump(sh_desc,
			JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD |
			JUMP_COND_SELF);
	} else {
		jump_cmd = append_jump(sh_desc,
			CLASS_BOTH | JUMP_TEST_ALL | JUMP_COND_SHRD
			| JUMP_COND_SELF);
	}

	if (pSA->SAParams.bAuth) {
		if (SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
			/* for AES_XCBC_MAC, no need for splitkey */
			/* process keys, starting with class 2/authentication */
			/* if cipher-alg is null, */
			/* xcbc key loads in class 1 key register */
			if (likely(SECFP_ESP_NULL != pSA->SAParams.ucCipherAlgo))
				append_key(sh_desc, ctx->key_phys,
					ctx->split_key_len,
					CLASS_2 | KEY_DEST_CLASS_REG);
			else
				append_key(sh_desc, ctx->key_phys,
					ctx->split_key_len,
					CLASS_1 | KEY_DEST_CLASS_REG | KEY_ENC);
		} else
			append_key(sh_desc, ctx->key_phys, ctx->split_key_len,
				CLASS_2 | KEY_DEST_MDHA_SPLIT | KEY_ENC);
	}

	if (pSA->SAParams.bEncrypt && likely(ctx->enckeylen)) {
		/* Now the class 1/cipher key */
		if (keys_fit_inline)
			append_key_as_imm(sh_desc, (void *)key +
				ctx->split_key_pad_len, ctx->enckeylen,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
		else
			append_key(sh_desc, ctx->key_phys +
				ctx->split_key_pad_len,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	}

	/* update jump cmd now that we are at the jump target */
	set_jump_tgt_here(sh_desc, jump_cmd);

#ifdef ASF_SECFP_PROTO_OFFLOAD
	ASFIPSEC_DEBUG("Enc Algorithm is %d Auth Algorithm is %d",
		pSA->SAParams.ucCipherAlgo, pSA->SAParams.ucAuthAlgo);

	/* Now insert the operation command */
	append_operation(sh_desc, OP_PCLID_IPSEC | OP_TYPE_DECAP_PROTOCOL |
			alg_to_caamdesc(pSA->SAParams.ucCipherAlgo,
			pSA->SAParams.ucAuthAlgo));
#endif
	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
					desc_bytes(ctx->sh_desc),
					DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
		return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	pr_err("\n");
	print_hex_dump(KERN_ERR, "shrdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
			desc_bytes(sh_desc), 1);
#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(sh_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
#endif
	return 0;
}

int secfp_prepareEncapShareDescDesXcbc(struct caam_ctx *ctx,
	u32 *sh_desc, outSA_t *pSA)
{
	append_jump(sh_desc, JUMP_JSL | JUMP_COND_SHRD |
		JUMP_COND_SELF | 0x03);
	append_key(sh_desc, ctx->key_phys, 0x20,
		CLASS_2 | KEY_DEST_MDHA_SPLIT);
	append_load_imm_u32(sh_desc, 0x20080065,
		LDST_SRCDST_WORD_DECO_MATH0 | 0x4);
	append_key(sh_desc, ctx->key_phys + ctx->split_key_pad_len,
		ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	append_operation(sh_desc, OP_PCLID_IPSEC | OP_TYPE_ENCAP_PROTOCOL |
		alg_to_caamdesc(pSA->SAParams.ucCipherAlgo, SECFP_HMAC_MD5));

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			0xD0 << MOVE_OFFSET_SHIFT | MOVE_DEST_MATH1 | 0x10);
	else
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			0xBC << MOVE_OFFSET_SHIFT | MOVE_DEST_MATH1 | 0x10);

	append_math_imm(AND, sh_desc, REG1, REG1, IMM, 0x08,
		MATH_IFB, 0xF7FFFFFF);
	append_load_imm_u32(sh_desc, 0xA00000E5, LDST_CLASS_DECO |
		LDST_SRCDST_WORD_DECO_MATH3 | 0x0404);
	append_math_shld(sh_desc, REG3, REG3, REG3, 8);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_MATH1|
			MOVE_DEST_DESCBUF | 0xEC << MOVE_OFFSET_SHIFT | 0x14);
	else
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_MATH1|
			MOVE_DEST_DESCBUF | 0xD8 << MOVE_OFFSET_SHIFT | 0x14);
	append_jump(sh_desc, JUMP_TEST_ALL | 0x19);
	append_load_imm_u32(sh_desc, 0x20080065,
		LDST_SRCDST_WORD_DECO_MATH0 | 0x4);
	append_seq_out_ptr_pre_rto(sh_desc, 0xFFFF, SQOUT_RTO);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			0xD8 << MOVE_OFFSET_SHIFT | MOVE_DEST_MATH0 | 0x08);
		append_math_sub_imm_u32(sh_desc, VARSEQINLEN,
			REG0, IMM, 0x00000034);
	} else {
		append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF |
			0xC4 << MOVE_OFFSET_SHIFT | MOVE_DEST_MATH0 | 0x08);
		append_math_sub_imm_u32(sh_desc, VARSEQINLEN,
			REG0, IMM, 0x00000020);
	}
	append_math_sub_imm_u32(sh_desc, VARSEQOUTLEN,
		REG0, IMM, 0x0000000C);
	append_key(sh_desc, ctx->key_phys, 0x10,
		CLASS_1 | KEY_DEST_CLASS_REG);
	append_operation(sh_desc, OP_TYPE_CLASS1_ALG |
		OP_ALG_AS_INITFINAL | OP_ALG_ALGSEL_AES |
		OP_ALG_AAI_XCBC_MAC | OP_ALG_ENCRYPT);
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		append_seq_fifo_load(sh_desc, 0x28, 0);
	else
		append_seq_fifo_load(sh_desc, 0x14, 0);
	append_seq_fifo_load(sh_desc, 0x0, FIFOLD_CLASS_CLASS1 |
		FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1 |
		FIFOLD_TYPE_FLUSH1 | FIFOLDST_VLF);
	append_seq_fifo_store(sh_desc, 0x0, FIFOLDST_SGF |
		FIFOST_TYPE_SKIP);
	append_seq_store(sh_desc, 0xC, LDST_CLASS_1_CCB |
		LDST_SRCDST_BYTE_CONTEXT);

	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
			desc_bytes(ctx->sh_desc), DMA_TO_DEVICE);

	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
		return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	pr_info("sh_desc_len %d\n", desc_len(sh_desc));
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
	DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
	desc_bytes(sh_desc), 1);
#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(sh_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
#endif
return 0;
}

int secfp_prepareEncapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
	outSA_t *pSA, bool keys_fit_inline)
{
	u32 *jump_cmd;
	u8 *key;

#ifndef ASF_SECFP_PROTO_OFFLOAD
	init_sh_desc(sh_desc, HDR_SAVECTX | HDR_SHARE_SERIAL);
#else
	struct ipsec_encap_pdb *pdb;
	u16 iphdrlen;
	struct iphdr *iph = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	struct ipv6hdr *iphv6 = 0;
	/*Deducing the IP version of SA selectors
	Assuming All SA selectors are of SAME IP versions*/
	SASel_t *pSel = NULL;
	bool bSelIPv4OrIPv6 = 0;
	if (pSA->pHeadSelList)
		pSel = &pSA->pHeadSelList->pOutSelList->srcSel;
	if (pSel && pSel->ucNumSelectors) {
		if (pSel->selNodes[0].IP_Version == 6)
			bSelIPv4OrIPv6 = 1;
	}
	key = (u8 *) GET_CACHE_ALLIGNED(pSA->ctx.key);

	/* todo take care of ip optionsa and ext header */
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		iphdrlen = SECFP_IPV6_HDR_LEN;
		init_sh_desc_pdb(sh_desc, (HDR_SHARE_SERIAL |
			CMD_SHARED_DESC_HDR | HDR_ONE),
			sizeof(*pdb) + iphdrlen);
	} else
#endif
	{
		iphdrlen = SECFP_IPV4_HDR_LEN;
		init_sh_desc_pdb(sh_desc, (HDR_SHARE_SERIAL |
			CMD_SHARED_DESC_HDR | HDR_ONE),
			sizeof(*pdb) + (iphdrlen) + pSA->usNatHdrSize);
	}

	/* Copy PDB options */
	/* fill in pdb */
	pdb = sh_desc_pdb(sh_desc);

	/* NH, NH Offse, IP options */
#ifdef ASF_IPV6_FP_SUPPORT
	if (bSelIPv4OrIPv6)
		pdb->ip_nh = SECFP_PROTO_IPV6;
	else
#endif
		pdb->ip_nh = SECFP_PROTO_IP;

	pdb->ip_nh_offset = 0;

	pdb->options = 0;
	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TUNNELMODE)
		pdb->options |= PDBOPTS_ESP_TUNNEL;

	/*OPT ESN*/
	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		pdb->options |= PDBOPTS_ESP_ESN;
		pdb->seq_num_ext_hi = atomic_read(&pSA->ulHiSeqNum);
	}

	pdb->options |= PDBOPTS_ESP_IPHDRSRC | PDBOPTS_ESP_INCIPHDR;

#ifndef ASF_IPV6_FP_SUPPORT
	pdb->hmo_rsvd = PDBHMO_ESP_ENCAP_DEC_TTL;
#endif
	pdb->spi = pSA->SAParams.ulSPI;
	pdb->seq_num = atomic_read(&pSA->ulLoSeqNum);
	pdb->ip_hdr_len = iphdrlen + pSA->usNatHdrSize;

#ifdef ASF_IPV6_FP_SUPPORT
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		if ((bSelIPv4OrIPv6) && (pSA->SAParams.bCopyDscp))
			pdb->options |= PDBOPTS_ESP_DIFFSERV;
		pdb->options |= PDBOPTS_ESP_IPV6;
		iphv6 = (struct ipv6hdr *) pdb->ip_hdr;
		iphv6->version = 6;
		iphv6->priority = 0;
		memset(iphv6->flow_lbl, 0, 3);
		iphv6->payload_len = 0;

		iphv6->nexthdr = SECFP_PROTO_ESP;
		iphv6->hop_limit = SECFP_IP_TTL;
		memcpy(iphv6->saddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		memcpy(iphv6->daddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
	} else {
		if (!bSelIPv4OrIPv6)
#endif
			if (pSA->SAParams.bCopyDscp)
				pdb->options |= PDBOPTS_ESP_DIFFSERV;
		/* encap-update ip header checksum */
		pdb->options |= PDBOPTS_ESP_UPDATE_CSUM;
		/* Outer IP Header Related */
		iph = (struct iphdr *) pdb->ip_hdr;
		iph->version = 4;
		iph->ihl = 5;
		if (!pSA->SAParams.bCopyDscp)
			iph->tos = pSA->SAParams.ucDscp;
		else
			iph->tos = 0;
		iph->tot_len = iphdrlen;
		iph->id = 0;

		switch (pSA->SAParams.handleDf) {
		case SECFP_DF_SET:
			iph->frag_off = IP_DF;
			break;
		case SECFP_DF_COPY:
			pdb->hmo_rsvd |= PDBHMO_ESP_DFBIT;
		case SECFP_DF_CLEAR:
		default:
			iph->frag_off = 0;
			break;
		}
		iph->ttl = SECFP_IP_TTL;
		iph->protocol = SECFP_PROTO_ESP;
		iph->check = 0;
		iph->saddr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		iph->daddr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

		if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
			struct udphdr *uh =
				(struct udphdr *) (pdb->ip_hdr + iph->ihl);

			ASFIPSEC_DEBUG("NAT Overhead =%d\n", pSA->usNatHdrSize);

			uh->source = pSA->SAParams.IPsecNatInfo.usSrcPort;
			uh->dest = pSA->SAParams.IPsecNatInfo.usDstPort;
			uh->len = 0;
			uh->check = 0;

			if (pSA->SAParams.IPsecNatInfo.ulNATt
					== ASF_IPSEC_IKE_NATtV1) {
				u32 *ike = (u32 *) (uh + 8);
				ike[0] = 0;
				ike[1] = 0;
			}
			iph->protocol = IPPROTO_UDP;
			iph->tot_len += pSA->usNatHdrSize;
		}
		ip_send_check(iph);
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

	switch (pSA->SAParams.ucCipherAlgo) {
	case SECFP_AESCTR:
		memcpy((u8 *)(&pdb->ctr.ctr_nonce),
			&pSA->SAParams.ucNounceIVCounter, AES_CTR_SALT_LEN);
		/* typically initial count value is 0x00000001 */
		pdb->ctr.ctr_initial = AES_CTR_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV8:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		/* CCM salt length is 3 bytes, left shift 8 bits */
		pdb->ccm.salt >>= 8;
		pdb->ccm.b0_flags = AES_CCM_ICV8_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV12:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		pdb->ccm.salt >>= 8;
		pdb->ccm.b0_flags = AES_CCM_ICV12_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_CCM_ICV16:
		memcpy((u8 *)(&pdb->ccm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_CCM_SALT_LEN);
		pdb->ccm.salt >>= 8;
		pdb->ccm.b0_flags = AES_CCM_ICV16_IV_FLAG;
		pdb->ccm.ctr_flags = AES_CCM_CTR_FLAG;
		pdb->ccm.ctr_initial = AES_CCM_INIT_COUNTER;
		break;

	case SECFP_AES_GCM_ICV8:
	case SECFP_AES_GCM_ICV12:
	case SECFP_AES_GCM_ICV16:
		memcpy((u8 *)(&pdb->gcm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_GCM_SALT_LEN);
		break;
	case SECFP_NULL_AES_GMAC:
		memcpy((u8 *)(&pdb->gcm.salt),
			&pSA->SAParams.ucNounceIVCounter, AES_GMAC_SALT_LEN);
		break;
	}
	ASFIPSEC_DEBUG("Created the PDB");

	if ((SECFP_DES == pSA->SAParams.ucCipherAlgo ||
		SECFP_3DES == pSA->SAParams.ucCipherAlgo) &&
		SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
		int ret = secfp_prepareEncapShareDescDesXcbc(ctx,
				sh_desc, pSA);
		return ret;
	}
	/* Check if the Packet Sequence number is going to overflow
		reset it to zero when Anti Replay is OFF.
		(Also true for Manual/Static SA case. */
	if (!pSA->SAParams.bDoAntiReplayCheck) {
		u32 seq_offset = 0;
		u64 counter = 0;

	counter = atomic_read(&pSA->ulHiSeqNum);
	counter = (counter << 32) + atomic_read(&pSA->ulLoSeqNum);
	append_data(sh_desc, &counter, sizeof(u64));
	seq_offset = sizeof(*pdb) + sizeof(uint32_t) + iphdrlen + pSA->usNatHdrSize;
	*(u32 *)sh_desc += 2<<16;

	append_move(sh_desc, MOVE_WAITCOMP | MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | (seq_offset << 8) | 8);
	append_math_add(sh_desc, REG0, REG0, ONE, 8);
	append_move(sh_desc, MOVE_WAITCOMP | MOVE_DEST_DESCBUF | MOVE_SRC_MATH0 | (seq_offset << 8) | 8);
	append_cmd(sh_desc, LDST_CLASS_DECO | CMD_STORE | 2 | ((seq_offset/sizeof(u32))<<8) | 0x420000);
	append_move(sh_desc, MOVE_WAITCOMP | MOVE_DEST_DESCBUF | MOVE_SRC_MATH0 | (8 << 8) | 8);
	}
#endif /*Protocol Offload */

	if (SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo &&
		SECFP_ESP_NULL == pSA->SAParams.ucCipherAlgo) {
		append_cmd(sh_desc, CMD_LOAD | LDST_CLASS_1_CCB |
			LDST_SRCDST_BYTE_CONTEXT | K3_NULL_XCBC_LEN |
			K3_NULL_XCBC_OFFSET << LDST_OFFSET_SHIFT);
		append_ptr(sh_desc, ctx->k3_null_xcbc_phys);

		jump_cmd = append_jump(sh_desc,
				JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD |
				JUMP_COND_SELF);
	} else {
		jump_cmd = append_jump(sh_desc,
				CLASS_BOTH | JUMP_TEST_ALL | JUMP_COND_SHRD
				| JUMP_COND_SELF);
	}
	if (pSA->SAParams.bAuth) {
		/* process keys, starting with class 2/authentication */
		if (SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
			/* if cipher-alg is null, xcbc key loads in class 1 key register */
			if (likely(SECFP_ESP_NULL != pSA->SAParams.ucCipherAlgo))
				append_key(sh_desc, ctx->key_phys,
					ctx->split_key_len,
					CLASS_2 | KEY_DEST_CLASS_REG);
			else
				append_key(sh_desc, ctx->key_phys,
				ctx->split_key_len,
				CLASS_1 | KEY_DEST_CLASS_REG | KEY_ENC);
		} else
			append_key(sh_desc, ctx->key_phys, ctx->split_key_len,
			CLASS_2 | KEY_DEST_MDHA_SPLIT | KEY_ENC);
	}


	if (pSA->SAParams.bEncrypt && likely(ctx->enckeylen)) {
		/* Now the class 1/cipher key */
		if (keys_fit_inline)
			append_key_as_imm(sh_desc, (void *)key +
				ctx->split_key_pad_len, ctx->enckeylen,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
		else
			append_key(sh_desc, ctx->key_phys +
				ctx->split_key_pad_len,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	}
	/* update jump cmd now that we are at the jump target */
	set_jump_tgt_here(sh_desc, jump_cmd);

	ASFIPSEC_DEBUG("Enc Algorithm is %d Auth Algorithm is %d",
		pSA->SAParams.ucCipherAlgo, pSA->SAParams.ucAuthAlgo);

#ifdef ASF_SECFP_PROTO_OFFLOAD
	/* Now insert the operation command */
	append_operation(sh_desc, OP_PCLID_IPSEC | OP_TYPE_ENCAP_PROTOCOL |
			alg_to_caamdesc(pSA->SAParams.ucCipherAlgo,
			pSA->SAParams.ucAuthAlgo));
#endif
	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
					desc_bytes(ctx->sh_desc),
					DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
		return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	pr_err("\n");
	pr_info("sh_desc_len %d\n", desc_len(sh_desc));
	print_hex_dump(KERN_ERR, "shrdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
			desc_bytes(sh_desc), 1);
#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(sh_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
#endif
	return 0;
}

#ifndef ASF_QMAN_IPSEC
int secfp_buildProtocolDesc(struct caam_ctx *ctx, void *pSA, int dir)
{
	u32 *sh_desc;
	int ret = 0;
	bool keys_fit_inline = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	/*
	* largest Job Descriptor and its Shared Descriptor
	* must both fit into the 64-word Descriptor h/w Buffer
	*/
	if ((DESC_AEAD_GIVENCRYPT_TEXT_LEN +
	DESC_AEAD_SHARED_TEXT_LEN) * CAAM_CMD_SZ +
	ctx->enckeylen + CAAM_PTR_SZ <= CAAM_DESC_BYTES_MAX)
		keys_fit_inline = 1;

	/* build shared descriptor for this session */
	ctx->sh_desc_mem = kzalloc(ASF_IPSEC_SEC_SA_SHDESC_SIZE + L1_CACHE_BYTES
		- 1,	GFP_DMA | flags);
	if (!ctx->sh_desc_mem) {
		ASFIPSEC_DPERR("Could not allocate shared descriptor");
		return -ENOMEM;
	}

	sh_desc = GET_CACHE_ALLIGNED(ctx->sh_desc_mem);

	ctx->sh_desc = sh_desc;

	/* Shared Descriptor Creation */
	if (dir == SECFP_OUT)
		ret = secfp_prepareEncapShareDesc(ctx, sh_desc,
					(outSA_t *)pSA, keys_fit_inline);
	else
		ret = secfp_prepareDecapShareDesc(ctx, sh_desc,
					(inSA_t *)pSA, keys_fit_inline);
	if (ret) {
		ASFIPSEC_DPERR("error in secfp_prepare ShareDesc dir=%d", dir);
		kfree(ctx->sh_desc_mem);
		ctx->sh_desc_mem = NULL;
		return ret;
	}

	return 0;
}
#endif

int secfp_createOutSACaamCtx(outSA_t *pSA)
{
	int ret = 0;
	u8 *key;

	if (pSA) {
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

		pSA->ctx.jrdev = caam_jr_alloc();
		if (IS_ERR(pSA->ctx.jrdev)) {
			ASFIPSEC_DEBUG("Could not allocate Job Ring Device\n");
			return -ENOMEM;
		}
		if (pSA->SAParams.bAuth && SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo) {
			pSA->ctx.split_key_pad_len =
				pSA->SAParams.AuthKeyLen;
			pSA->ctx.split_key_len =
				pSA->SAParams.AuthKeyLen;
		}
		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen +
					L1_CACHE_BYTES - 1,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not"\
				"allocate CAAM key output memory\n");
			caam_jr_free(pSA->ctx.jrdev);
			pSA->ctx.jrdev = NULL;
			return -ENOMEM;
		}

		key = (u8 *) GET_CACHE_ALLIGNED(pSA->ctx.key);

		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, key,
					pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen,
					DMA_TO_DEVICE);
		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG(" Unable to map key"\
					"i/o memory\n");
			ret = -ENOMEM;
			goto error;
		}

		pSA->ctx.enckeylen = pSA->SAParams.EncKeyLen;
		if (pSA->SAParams.bAuth) {
			if (SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo) {
				memcpy(key, &pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
				if (SECFP_ESP_NULL ==
					pSA->SAParams.ucCipherAlgo)
					secfp_genCaamSplitKey_null_xcbc(
						&pSA->ctx,
						(u8 *)&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen);
			} else {
				ret = secfp_genCaamSplitKey(&pSA->ctx,
					(u8 *)&pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
				if (ret) {
					ASFIPSEC_DEBUG("Failed\n");
					goto error;
				}
			}
		}
		if (!(SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo &&
			SECFP_ESP_NULL == pSA->SAParams.ucCipherAlgo))
				memcpy(key + pSA->ctx.split_key_pad_len,
					&pSA->SAParams.ucEncKey,
					pSA->SAParams.EncKeyLen);

		pSA->ctx.authsize = pSA->SAParams.uICVSize;
		ret = secfp_buildProtocolDesc(&pSA->ctx, pSA, SECFP_OUT);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
				pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen, DMA_TO_DEVICE);
			goto error;
		}

	} else
		ret = -EINVAL;
retrn:
	return ret;
error:
	kfree(pSA->ctx.key);
	caam_jr_free(pSA->ctx.jrdev);
	pSA->ctx.jrdev = NULL;
	pSA->ctx.key = NULL;
	goto retrn;

}

int secfp_createInSACaamCtx(inSA_t *pSA)
{
	int ret = 0;
	u8 *key;

	if (pSA) {
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
		pSA->ctx.jrdev = caam_jr_alloc();
		if (IS_ERR(pSA->ctx.jrdev)) {
			ASFIPSEC_DEBUG("Could not allocate Job Ring Device\n");
			return -ENOMEM;
		}
		if ((pSA->SAParams.bAuth) &&
			(SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo)) {
			pSA->ctx.split_key_pad_len =
				pSA->SAParams.AuthKeyLen;
			pSA->ctx.split_key_len =
				pSA->SAParams.AuthKeyLen;
		}
		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen + 
                    L1_CACHE_BYTES - 1,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not allocate"\
					"Caam key output memory\n");
			caam_jr_free(pSA->ctx.jrdev);
			pSA->ctx.jrdev = NULL;
			return -ENOMEM;
		}

		key = (u8 *) GET_CACHE_ALLIGNED(pSA->ctx.key);
		/* FOR LS1 this may need to move doen */
		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, key,
					pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen,
					DMA_TO_DEVICE);

		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG("Unable to map key"\
					"i/o memory\n");
			ret = -ENOMEM;
			goto error;
		}

		pSA->ctx.enckeylen = pSA->SAParams.EncKeyLen;
		if (pSA->SAParams.bAuth) {
			if (SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo) {
				ASFIPSEC_DEBUG("for AES_XCBC_MAC, no need for"\
					"splitkey generated\n");
				memcpy(key, &pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
				if (SECFP_ESP_NULL ==
					pSA->SAParams.ucCipherAlgo)
					secfp_genCaamSplitKey_null_xcbc(
						&pSA->ctx,
						(u8 *)&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen);

			} else {
				ret = secfp_genCaamSplitKey(&pSA->ctx,
						(u8 *)&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen);
				if (ret) {
					ASFIPSEC_DEBUG("Failed\n");
					goto error;
				}
			}
		}

		if (!(SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo &&
			SECFP_ESP_NULL == pSA->SAParams.ucCipherAlgo))
			memcpy(key + pSA->ctx.split_key_pad_len,
				&pSA->SAParams.ucEncKey,
				pSA->SAParams.EncKeyLen);

		pSA->ctx.authsize = pSA->SAParams.uICVSize;
		ret = secfp_buildProtocolDesc(&pSA->ctx, pSA, SECFP_IN);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
			pSA->ctx.split_key_pad_len +
			pSA->SAParams.EncKeyLen, DMA_TO_DEVICE);
			goto error;
		}
	} else
		ret = -EINVAL;
retrn:
	return ret;
error:
	kfree(pSA->ctx.key);
	caam_jr_free(pSA->ctx.jrdev);
	pSA->ctx.jrdev = NULL;
	pSA->ctx.key = NULL;
	goto retrn;
}

#ifndef ASF_QMAN_IPSEC

static void secfp_prepareCaamJobDescriptor(struct aead_edesc *edesc,
					struct caam_ctx *ctx,
					dma_addr_t data_in, int data_in_len,
					dma_addr_t data_out, int data_out_len, unsigned int sg,
					unsigned int dpovrd)
{
	u32 *desc = edesc->hw_desc;
	u32 options = 0;
	outSA_t *pSA = container_of(ctx, outSA_t, ctx);
#ifdef ASF_SECFP_PROTO_OFFLOAD
	if (sg)
		options = LDST_SGF;
	if ((SECFP_DES == pSA->SAParams.ucCipherAlgo ||
		SECFP_3DES == pSA->SAParams.ucCipherAlgo) &&
		SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
		options |= FIFOLDST_EXT;
		init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_REVERSE | HDR_SHARE_SERIAL);
		append_seq_out_ptr(desc, data_out, data_out_len, options);
		append_cmd(desc, data_out_len);
		append_seq_in_ptr(desc, data_in, data_in_len, options);
		append_cmd(desc, data_in_len);
	} else {
		init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_REVERSE | HDR_SHARE_SERIAL);
		append_seq_in_ptr(desc, data_in, data_in_len, options);
		append_seq_out_ptr(desc, data_out, data_out_len, options);
	}

	if (dpovrd) {
		static u32 data;
		data = 0x80000000 | dpovrd;
		if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
			data |= SECFP_IPV6_HDR_LEN << 16;
		else
			data |= SECFP_IPV4_HDR_LEN << 16;
		append_load_as_imm(desc, &data, sizeof(data), LDST_CLASS_DECO |
			LDST_SRCDST_WORD_DECO_PCLOVRD | 0x4);
	}
#ifdef ASFIPSEC_DEBUG_FRAME
		print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
		DUMP_PREFIX_ADDRESS, 16, 4, desc,
		desc_bytes(desc), 1);
#endif

#else
	int authsize = ctx->authsize;
	int ivsize;

	ivsize = pSA->SAParams.ulIvSize;

	ASFIPSEC_DEBUG("ivsize=%d authsize=%d", ivsize, authsize);

	desc = edesc->hw_desc;

	/* insert shared descriptor pointer */
	init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_SHARE_DEFER);

	/*
	* LOAD IMM Info FIFO
	* to DECO, Last, Padding, Random, Message, 16 bytes
	*/
	append_load_imm_u32(desc, NFIFOENTRY_DEST_DECO | NFIFOENTRY_LC1 |
			NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DTYPE_MSG |
			NFIFOENTRY_PTYPE_INCREMENT | ivsize,
			LDST_SRCDST_WORD_INFO_FIFO);

	/*
	* disable info fifo entries since the above serves as the entry
	* this way, the MOVE command won't generate an entry.
	* Note that this isn't required in more recent versions of
	* SEC as a MOVE that doesn't do info FIFO entries is available.
	*/
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* MOVE DECO Alignment -> C1 Context 16 bytes */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_CLASS1CTX | ivsize);

	/* re-enable info fifo entries */
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* MOVE C1 Context -> OFIFO 16 bytes */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_OUTFIFO | ivsize);

	append_fifo_store(desc, data_in + SECFP_ESP_HDR_LEN, ivsize,
					FIFOST_TYPE_MESSAGE_DATA);

	/* start auth operation */
	append_operation(desc, ctx->class2_alg_type | OP_ALG_AS_INITFINAL);

	/* Load FIFO with data for Class 2 CHA */
	options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

	append_fifo_load(desc, data_in, SECFP_ESP_HDR_LEN, options);

	/* copy iv from cipher/class1 input context to class2 infifo */
	/* Need to know the IV size */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | ivsize);

	append_operation(desc, ctx->class1_alg_type |
			OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);


	/* load payload & instruct to class2 to snoop class 1 if encrypting */
	options = 0;
	append_seq_in_ptr(desc, data_in + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		/* The ESN higher bytes are at tail which will be at data_in_len
		offset from data_in ptr. Here we are instructing the CAAM to do
		CLASS1 operation for data_in_len - ESP Hdr - ICV_LEN. The DMA is
		being done for extra 12 bytes which will include the space for
		ICV and also has 4 bytes of ESN higher seq num. CAAM will use
		IP pkt for encryption and snoop that data to CLASS2 for Auth.
		Before finishing the authentication; load FIFO with 4 bytes
		of ESN HO so that CLASS2 can be performed on the same. ICV will
		get appended at the same place as in case of NON ESN data.
		*/
		append_seq_fifo_load(desc, data_in_len - (pSA->ulSecHdrLen +
			pSA->SAParams.uICVSize), FIFOLD_CLASS_BOTH
			| FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG1OUT2);

		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2
				| FIFOLD_TYPE_MSG;
		append_fifo_load(desc, data_in + (data_in_len -
				pSA->SAParams.uICVSize),
				SECFP_HO_SEQNUM_LEN, options);
		options = 0;
		append_seq_out_ptr(desc, data_out + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);
		append_seq_fifo_store(desc, data_in_len - (pSA->ulSecHdrLen +
				pSA->SAParams.uICVSize), FIFOST_TYPE_MESSAGE_DATA);
	} else {
		append_seq_fifo_load(desc, data_in_len - (pSA->ulSecHdrLen +
			pSA->SAParams.uICVSize), FIFOLD_CLASS_BOTH |
			FIFOLD_TYPE_LASTBOTH | FIFOLD_TYPE_MSG1OUT2);
		append_seq_out_ptr(desc, data_out + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);
		append_seq_fifo_store(desc, data_in_len - (pSA->ulSecHdrLen +
				pSA->SAParams.uICVSize), FIFOST_TYPE_MESSAGE_DATA);
	}
	/* ICV */
	append_seq_store(desc, authsize, LDST_CLASS_2_CCB |
				LDST_SRCDST_BYTE_CONTEXT);
#ifdef ASFIPSEC_DEBUG_FRAME
	pr_info("job_desc_len %d\n", desc_len(desc));
	pr_err("\nData In Len %d Data Out Len %d\n",
				data_in_len, data_out_len);
	caam_desc_disasm(desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
					DUMP_PREFIX_ADDRESS, 16, 4, desc,
					desc_bytes(desc), 1);
#endif
#endif /*ASF_SECFP_PROTO_OFFLOAD */
}

/*
 * Function prepares the descriptors based on the encryption and authentication
 * algorithm. The prepared descriptor is submitted to SEC.
 */

void secfp_prepareOutDescriptor(struct sk_buff *skb, void *pData,
		void *descriptor, unsigned int ulOptionIndex)
{
	outSA_t *pSA = (outSA_t *) (pData);
#ifdef ASF_SECFP_PROTO_OFFLOAD
	unsigned int data_in_len = skb->len;
	unsigned short usPadLen = 0;
	struct iphdr *iph = ip_hdr(skb);
	unsigned int dpovrd = 0;

#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
		usPadLen = (ipv6h->payload_len + SECFP_IPV6_HDR_LEN
				+ SECFP_ESP_TRAILER_LEN)
			& (pSA->SAParams.ulBlockSize - 1);
		usPadLen = (usPadLen == 0) ? 0 :
			pSA->SAParams.ulBlockSize - usPadLen;
		if (pSA->def_sel_ver != 6) {
			ASFIPSEC_DEBUG("UPDATE DPOVRD REG with v6");
			dpovrd = SECFP_PROTO_IPV6;
		}
		/*In case of IPv6-in-IPv4 tunnel*/
		if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
			struct ipv6hdr *ipv6h1 = ipv6_hdr(skb);
			ipv6_traffic_class(*(unsigned char *) &(skb->cb[SECFP_TOS_TC_INDEX]), ipv6h1);
			*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) = SECFP_IPv6_IN_IPv4;
		} else /* In case of IPv6-in-IPv6 tunnel*/
			*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) = SECFP_IPv6_IN_IPv6;
	} else
#endif
	{
		usPadLen = (iph->tot_len + SECFP_ESP_TRAILER_LEN)
			& (pSA->SAParams.ulBlockSize - 1);
		usPadLen = (usPadLen == 0) ? 0 :
			pSA->SAParams.ulBlockSize - usPadLen;
		if (pSA->def_sel_ver != 4) {
			ASFIPSEC_DEBUG("UPDATE DPOVRD REG with v6");
			dpovrd = SECFP_PROTO_IP;
		}
		/*In case of IPv4-to-IPv6 tunnel*/
		if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
			*(unsigned char *) &(skb->cb[SECFP_TOS_TC_INDEX]) = iph->tos;
			*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) = SECFP_IPv4_IN_IPv6;
		} else /*In case of IPv4-to-IPv4 tunnel*/
			*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) = SECFP_IPv4_IN_IPv4;

	}

	ASFIPSEC_DEBUG("ulSecOverHead %d skb->len %d, data_len=%d pad_len =%d",
		pSA->ulSecOverHead, skb->len, skb->data_len, usPadLen);

#endif
	/* Check for the NR_Frags */
	if (!(skb_shinfo(skb)->nr_frags)) {
		dma_addr_t ptr;

#ifdef ASF_SECFP_PROTO_OFFLOAD
		dma_addr_t out_ptr;
		/* updating the length of packet to the length which is
		   after encryption */
		skb->len += pSA->ulSecOverHead + usPadLen;
#endif
		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb->len, DMA_BIDIRECTIONAL);
#ifdef ASF_SECFP_PROTO_OFFLOAD
		out_ptr = ptr - pSA->ulXmitHdrLen;
#endif
		ASFIPSEC_FPRINT("asso@:");
		ASFIPSEC_HEXDUMP(skb->data, 8);
		ASFIPSEC_FPRINT("presciv@:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen - 8, 8);
		ASFIPSEC_FPRINT("src @:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen, 60);

		secfp_prepareCaamJobDescriptor(descriptor, &pSA->ctx,
#ifdef ASF_SECFP_PROTO_OFFLOAD
			ptr, data_in_len, out_ptr , skb->len, 0, dpovrd);
#else
			ptr, skb->len + pSA->SAParams.uICVSize,
			ptr, skb->len + pSA->SAParams.uICVSize, 0, dpovrd);
#endif
	} else {
		skb_frag_t *frag = 0;
		outSA_t *pSA = (outSA_t *) (pData);
		struct aead_edesc *edesc =
				(struct aead_edesc *)descriptor;
		unsigned short usPadLen = 0;
		struct sec4_sg_entry *link_tbl_entry;
		dma_addr_t ptr, ptr1, ptr2 = 0;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		dma_addr_t ptr_out;
#endif

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct sec4_sg_entry) * (total_frags + 1);
		ptr1 = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb_headlen(skb) + pSA->ulCompleteOverHead,
			DMA_BIDIRECTIONAL);

#ifdef ASF_SECFP_PROTO_OFFLOAD
		link_tbl_entry = kzalloc(2*dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr1;
		link_tbl_entry->len = skb_headlen(skb);
#else
		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr1 + pSA->ulSecHdrLen;
		link_tbl_entry->len = skb_headlen(skb) - pSA->ulSecHdrLen;
#endif
		len_to_caam = link_tbl_entry->len;

		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */
		for (i = 0; i < total_frags; i++) {
			frag = &skb_shinfo(skb)->frags[i];
			if (i == total_frags - 1) {
				usPadLen = *(u8 *)
				(((u8 *)(page_address(frag->page.p) +
				frag->page_offset)) + frag->size - 2);

				ptr2 = dma_map_single(pSA->ctx.jrdev,
					(void *)page_address(frag->page.p)
					+ frag->page_offset, frag->size
#ifdef ASF_SECFP_PROTO_OFFLOAD
					+ pSA->ulCompleteOverHead -
						pSA->ulXmitHdrLen,
#else
					+ pSA->SAParams.uICVSize,
#endif
					DMA_BIDIRECTIONAL);

				(link_tbl_entry + i + 1)->ptr = ptr2;
				(link_tbl_entry + i + 1)->len = frag->size;
				len_to_caam += frag->size;
#ifdef ASF_SECFP_PROTO_OFFLOAD
				/* Preparing for out put */
				frag->size += pSA->SAParams.uICVSize + usPadLen
						+ SECFP_ESP_TRAILER_LEN;
				skb->data_len += pSA->SAParams.uICVSize +
						usPadLen + SECFP_ESP_TRAILER_LEN;
				skb->len += pSA->ulSecOverHead + usPadLen;
#endif
				(link_tbl_entry + i + 1)->len |=
					cpu_to_be32(0x40000000);

				break;
			}

			(link_tbl_entry + i + 1)->ptr =
				dma_map_single(pSA->ctx.jrdev,
				(void *)page_address(frag->page.p) +
				frag->page_offset, frag->size,
				DMA_BIDIRECTIONAL);
			(link_tbl_entry + i + 1)->len = frag->size;
			len_to_caam += (link_tbl_entry + i + 1)->len;

		}
		/* Go ahead and Submit to SEC */
		ptr = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->sec4_sg_dma = ptr;
		edesc->sec4_sg = link_tbl_entry;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		/* In case of protocol offload prepare seperate SG list for output */
		memcpy(link_tbl_entry + total_frags + 1,
			link_tbl_entry, dma_len);
		link_tbl_entry += total_frags + 1;
		link_tbl_entry->ptr -= pSA->ulXmitHdrLen;
		link_tbl_entry->len += pSA->ulXmitHdrLen;

		ptr_out = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);

		link_tbl_entry += total_frags;
		link_tbl_entry->len += (pSA->SAParams.uICVSize + usPadLen +
						SECFP_ESP_TRAILER_LEN);
		len_to_caam += pSA->ulSecOverHead + usPadLen;

		edesc->sec4_sg_bytes = 2*dma_len;

		secfp_prepareCaamJobDescriptor(descriptor, &pSA->ctx,
			ptr, data_in_len, ptr_out, len_to_caam, 1, dpovrd);
#else
		edesc->sec4_sg_bytes = dma_len;

		{
		u32 *desc = edesc->hw_desc, options;
		int ivsize = pSA->SAParams.ulIvSize;
		int authsize = pSA->ctx.authsize;
		desc = edesc->hw_desc;

		/* insert shared descriptor pointer */
		init_job_desc_shared(desc, pSA->ctx.shared_desc_phys,
			desc_len(pSA->ctx.sh_desc), HDR_SHARE_DEFER);

		/*
		* LOAD IMM Info FIFO
		* to DECO, Last, Padding, Random, Message, 16 bytes
		*/
		append_load_imm_u32(desc, NFIFOENTRY_DEST_DECO |
			NFIFOENTRY_LC1 | NFIFOENTRY_STYPE_PAD |
			NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_PTYPE_INCREMENT |
			ivsize, LDST_SRCDST_WORD_INFO_FIFO);

		/*
		* disable info fifo entries since the above serves as
		* the entry this way, the MOVE command won't generate an
		* entry. Note that this isn't required in more recent
		* versions of SEC as a MOVE that doesn't do info FIFO
		* entries is available.
		*/
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

		/* MOVE DECO Alignment -> C1 Context 16 bytes */
		append_move(desc, MOVE_SRC_INFIFO |
				MOVE_DEST_CLASS1CTX | ivsize);

		/* re-enable info fifo entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

		/* MOVE C1 Context -> OFIFO 16 bytes */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_OUTFIFO | ivsize);

		append_fifo_store(desc, ptr1 + SECFP_ESP_HDR_LEN,
				ivsize, FIFOST_TYPE_MESSAGE_DATA);

		/* start auth operation */
		append_operation(desc, pSA->ctx.class2_alg_type |
				OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

		/* Load FIFO with data for Class 2 CHA */
		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

		append_fifo_load(desc, ptr1, SECFP_ESP_HDR_LEN,	options);

		/* copy iv from cipher/class1 input
			context to class2 infifo */
		/* Need to know the IV size */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_CLASS2INFIFO | ivsize);

		append_operation(desc, pSA->ctx.class1_alg_type |
			OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);


		/* load payload & instruct to class2 to
			snoop class 1 if encrypting */
		options = 0;
		options |= LDST_SGF;

		append_seq_in_ptr(desc, ptr, len_to_caam + pSA->SAParams.uICVSize,
					options);

		append_seq_fifo_load(desc, len_to_caam,
				FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_LASTBOTH |
				FIFOLD_TYPE_MSG1OUT2);

		append_seq_out_ptr(desc, ptr, len_to_caam + pSA->SAParams.uICVSize,
							options);
		append_seq_fifo_store(desc, len_to_caam,
					FIFOST_TYPE_MESSAGE_DATA);

		/* ICV */
		append_store(desc, ptr2 + frag->size,
			authsize, LDST_CLASS_2_CCB |
			LDST_SRCDST_BYTE_CONTEXT);
#ifdef ASFIPSEC_DEBUG_FRAME
	pr_info("\nData In Len %d Data Out Len %d Auth Size: %d\n",
			len_to_caam + 12, len_to_caam, authsize);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
				DUMP_PREFIX_ADDRESS, 16, 4, desc,
				desc_bytes(desc), 1);
#endif
		}
#endif
	}
}

static void secfp_prepareInCaamJobDescriptor(struct aead_edesc *edesc,
					struct caam_ctx *ctx,
					dma_addr_t data_in, int data_in_len,
					dma_addr_t data_out, int data_out_len, unsigned int sg)
{
	u32 *desc = edesc->hw_desc;
	u32 options = 0;
	inSA_t *pSA = container_of(ctx, inSA_t, ctx);

#ifdef ASF_SECFP_PROTO_OFFLOAD
	if (sg)
		options = LDST_SGF;

	if ((SECFP_DES == pSA->SAParams.ucCipherAlgo ||
		SECFP_3DES == pSA->SAParams.ucCipherAlgo) &&
		SECFP_HMAC_AES_XCBC_MAC == pSA->SAParams.ucAuthAlgo) {
		options |= FIFOLDST_EXT;
		init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_REVERSE | HDR_SHARE_SERIAL);
		append_seq_out_ptr(desc, data_out, data_out_len, options);
		append_cmd(desc, data_out_len);
		append_seq_in_ptr(desc, data_in, data_in_len, options);
		append_cmd(desc, data_in_len);
	} else {
		init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_REVERSE | HDR_SHARE_SERIAL);
		append_seq_in_ptr(desc, data_in, data_in_len, options);
		append_seq_out_ptr(desc, data_out, data_out_len, options);
	}
#else
	int authsize = ctx->authsize;
	int ivsize;

	ivsize = pSA->SAParams.ulIvSize;
	ASFIPSEC_DEBUG("ivsize=%d authsize=%d", ivsize, authsize);

	/* insert shared descriptor pointer */
	init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_SHARE_DEFER);

	append_load(desc, data_in + SECFP_ESP_HDR_LEN, ivsize,
		LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	/* start auth operation */
	append_operation(desc, ctx->class2_alg_type | OP_ALG_AS_INITFINAL |
			OP_ALG_ICV_ON);

	/* Load FIFO with data for Class 2 CHA */
	options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

	append_fifo_load(desc, data_in, SECFP_ESP_HDR_LEN, options);
	/* copy iv from cipher/class1 input context to class2 infifo */
	/* Need to know the IV size */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | ivsize);

	{
		u32 *jump_cmd, *uncond_jump_cmd;

		/* JUMP if shared */
		jump_cmd = append_jump(desc, JUMP_TEST_ALL | JUMP_COND_SHRD);

		/* start class 1 (cipher) operation, non-shared version */
		append_operation(desc, ctx->class1_alg_type |
				OP_ALG_AS_INITFINAL);

		uncond_jump_cmd = append_jump(desc, 0);

		set_jump_tgt_here(desc, jump_cmd);

		/* start class 1 (cipher) operation, shared version */
		append_operation(desc, ctx->class1_alg_type |
				OP_ALG_AS_INITFINAL | OP_ALG_AAI_DK);
		set_jump_tgt_here(desc, uncond_jump_cmd);
	}

	/* load payload & instruct to class2 to snoop class 1 if encrypting */
	options = 0;

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		append_seq_in_ptr(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len + SECFP_HO_SEQNUM_LEN -
			(SECFP_ESP_HDR_LEN + ivsize), options);
		append_seq_fifo_load(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + pSA->SAParams.uICVSize) + SECFP_HO_SEQNUM_LEN,
			FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2 |
			FIFOLD_TYPE_MSG);

		append_fifo_load(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + pSA->SAParams.uICVSize), FIFOLD_CLASS_CLASS1 |
			FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, data_out + (SECFP_ESP_HDR_LEN +
			ivsize), data_in_len - (SECFP_ESP_HDR_LEN + ivsize),
			options);
		append_seq_fifo_store(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + pSA->SAParams.uICVSize), FIFOST_TYPE_MESSAGE_DATA);
	} else {
		append_seq_in_ptr(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len - (SECFP_ESP_HDR_LEN + ivsize), options);
		append_seq_fifo_load(desc, data_in_len - (SECFP_ESP_HDR_LEN +
				ivsize + pSA->SAParams.uICVSize), FIFOLD_CLASS_BOTH |
			FIFOLD_TYPE_LASTBOTH | FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, data_out + (SECFP_ESP_HDR_LEN +
			ivsize), data_in_len - (SECFP_ESP_HDR_LEN + ivsize),
			options);
		append_seq_fifo_store(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + pSA->SAParams.uICVSize), FIFOST_TYPE_MESSAGE_DATA);
	}

	append_seq_fifo_load(desc, authsize, FIFOLD_CLASS_CLASS2 |
			FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
#ifdef ASFIPSEC_DEBUG_FRAME
	pr_err("\nData In Len %d Data Out Len %d\n",
				data_in_len, data_out_len);
	caam_desc_disasm(desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif
#endif /*ASF_SECFP_PROTO_OFFLOAD */
}

/*
 * This function prepares the In descriptor.
 * Prepares the descriptor based on the SA encryption/authentication
 * algorithms.
 */

void secfp_prepareInDescriptor(struct sk_buff *skb,
			void *pData, void *descriptor,
			unsigned int ulIndex)
{
	inSA_t *pSA = (inSA_t *)pData;

	/* Check for the NR_Frags */
	if (unlikely(skb_shinfo(skb)->nr_frags)) {
		struct aead_edesc *edesc = descriptor;
		static struct sec4_sg_entry *link_tbl_entry;
		dma_addr_t ptr, ptr2;
		unsigned int *ptr1;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		dma_addr_t ptr_out;
#endif

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct sec4_sg_entry) * (total_frags + 1);
		ptr1 = (unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = (unsigned int) link_tbl_entry;
		ptr2 = dma_map_single(pSA->ctx.jrdev, skb->data,
				skb_headlen(skb), DMA_BIDIRECTIONAL);

#ifdef ASF_SECFP_PROTO_OFFLOAD
		link_tbl_entry = kzalloc(2*dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr2;
		link_tbl_entry->len = skb_headlen(skb);
#else
		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr2 + pSA->ulSecHdrLen;
		link_tbl_entry->len = skb_headlen(skb) - pSA->ulSecHdrLen;
#endif
		len_to_caam = link_tbl_entry->len;

		ASFIPSEC_FPRINT("\nskb->len:%d skb->data_len:%d"
				" skb_headlen(skb):%d, total_frags:%d",
				skb->len, skb->data_len,
				skb_headlen(skb), total_frags);
		ASFIPSEC_HEXDUMP(skb->data, 48);

		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */
		for (i = 0; i < total_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			(link_tbl_entry + i + 1)->ptr =
					dma_map_single(pSA->ctx.jrdev,
					(void *)page_address(frag->page.p) +
					frag->page_offset,
					frag->size, DMA_BIDIRECTIONAL);

			ASFIPSEC_HEXDUMP((void *)page_address(frag->page.p) +
					frag->page_offset , 64);

			(link_tbl_entry + i + 1)->len = frag->size;
			len_to_caam += frag->size;
			if (i == total_frags - 1)
				(link_tbl_entry + i + 1)->len |=
						cpu_to_be32(0x40000000);
		}
		/* Go ahead and Submit to SEC */
		ptr = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->sec4_sg_dma = ptr;
		edesc->sec4_sg = link_tbl_entry;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		/* In case of protocol offload prepare seperate SG list for
		   output */
		memcpy(link_tbl_entry + total_frags + 1,
			link_tbl_entry, dma_len);
		link_tbl_entry = link_tbl_entry + total_frags + 1;
#ifdef ASF_IPV6_FP_SUPPORT
		if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
			link_tbl_entry->ptr = ptr2 + SECFP_IPV6_HDR_LEN +
					pSA->ulSecHdrLen;
			link_tbl_entry->len = skb_headlen(skb) -
					SECFP_IPV6_HDR_LEN - pSA->ulSecHdrLen;
		} else
#endif
		{
			link_tbl_entry->ptr = ptr2 +
				SECFP_IPV4_HDR_LEN + pSA->ulSecHdrLen;
			link_tbl_entry->len = skb_headlen(skb) -
				SECFP_IPV4_HDR_LEN - pSA->ulSecHdrLen;
		}
		ptr_out = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);

		edesc->sec4_sg_bytes = 2*dma_len;

		secfp_prepareInCaamJobDescriptor(descriptor, &pSA->ctx,
				ptr , len_to_caam, ptr_out,
				len_to_caam, 1);
#else
		edesc->sec4_sg_bytes = dma_len;

		{
		u32 *desc, options;
		int ivsize = pSA->SAParams.ulIvSize;
		int authsize = pSA->ctx.authsize;

		desc = edesc->hw_desc;

		/* insert shared descriptor pointer */
		init_job_desc_shared(desc, pSA->ctx.shared_desc_phys,
			desc_len(pSA->ctx.sh_desc), HDR_SHARE_DEFER);

		append_load(desc, ptr2 + SECFP_ESP_HDR_LEN, ivsize,
			LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

		/* start auth operation */
		append_operation(desc, pSA->ctx.class2_alg_type |
					OP_ALG_AS_INITFINAL | OP_ALG_ICV_ON);

		/* Load FIFO with data for Class 2 CHA */
		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

		append_fifo_load(desc, ptr2, SECFP_ESP_HDR_LEN, options);

		/* copy iv from cipher/class1 input
			context to class2 infifo */
		/* Need to know the IV size */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_CLASS2INFIFO | ivsize);

		{
			u32 *jump_cmd, *uncond_jump_cmd;

			/* JUMP if shared */
			jump_cmd = append_jump(desc, JUMP_TEST_ALL |
						JUMP_COND_SHRD);

			/* start class 1 (cipher) operation,
					non-shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
					| OP_ALG_AS_INITFINAL);

			uncond_jump_cmd = append_jump(desc, 0);

			set_jump_tgt_here(desc, jump_cmd);

			/* start class 1 (cipher) operation,
				shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
				| OP_ALG_AS_INITFINAL | OP_ALG_AAI_DK);

			set_jump_tgt_here(desc, uncond_jump_cmd);
		}

		/* load payload & instruct class2 to
			snoop class 1 if encrypting */
		options = 0;
		options |= LDST_SGF;

		append_seq_in_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_load(desc, len_to_caam - authsize,
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LASTBOTH |
				FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_store(desc, len_to_caam - authsize,
					FIFOST_TYPE_MESSAGE_DATA);

		/* ICV */
		append_seq_fifo_load(desc, authsize, FIFOLD_CLASS_CLASS2 |
					FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_DEBUG("\nData In Len:%d Data Out Len:%d Auth Size:%d",
			len_to_caam, len_to_caam - 12, authsize);
		print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
		DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif
		}
#endif
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	else if (unlikely(skb_shinfo(skb)->frag_list)) {
		struct aead_edesc *edesc = descriptor;
		static struct sec4_sg_entry *link_tbl_entry;
		struct sk_buff *skb1;
		dma_addr_t ptr, ptr2;
		unsigned int *ptr1;
		int i = 0, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		unsigned int iphdrlen, ulFragpadlen = 0;
		dma_addr_t ptr_out;
#ifdef ASF_IPV6_FP_SUPPORT
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		iphdrlen = SECFP_IPV6_HDR_LEN;
	else
#endif
		iphdrlen = SECFP_IPV4_HDR_LEN;

		if ((pSA->ulSecHdrLen + iphdrlen) % 8)
			ulFragpadlen = 8 - ((pSA->ulSecHdrLen + iphdrlen)%8);
#endif
		for (total_frags = 1, skb1 = skb_shinfo(skb)->frag_list;
			 skb1->next != NULL; total_frags++, skb1 = skb1->next)
			;
		dma_len = sizeof(struct sec4_sg_entry) * (total_frags + 1);
		ptr1 = (unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = (unsigned int) link_tbl_entry;
		ptr2 = dma_map_single(pSA->ctx.jrdev, skb->data,
				skb_headlen(skb), DMA_BIDIRECTIONAL);

#ifdef ASF_SECFP_PROTO_OFFLOAD
		link_tbl_entry = kzalloc(2*dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr2;
		link_tbl_entry->len = skb_headlen(skb);
#else
		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr2 + pSA->ulSecHdrLen;
		link_tbl_entry->len = skb_headlen(skb) - pSA->ulSecHdrLen;
#endif
		len_to_caam = link_tbl_entry->len;

		ASFIPSEC_HEXDUMP(skb->data, 48);

		skb1 = skb_shinfo(skb)->frag_list;

		/* Parse the Frag list */
		/* Prepare the list for SEC */
		while (skb1) {
			ptr = dma_map_single(pSA->ctx.jrdev, skb1->data,
					skb_headlen(skb1), DMA_BIDIRECTIONAL);

#ifdef ASF_SECFP_PROTO_OFFLOAD
			(link_tbl_entry + i + 1)->ptr = ptr;
			(link_tbl_entry + i + 1)->len = skb_headlen(skb1);
#else
			(link_tbl_entry + i + 1)->ptr = ptr + pSA->ulSecHdrLen;
			(link_tbl_entry + i + 1)->len = skb_headlen(skb1) - pSA->ulSecHdrLen;
#endif
			len_to_caam += (link_tbl_entry + i + 1)->len;

			if (!skb1->next)
				(link_tbl_entry + i + 1)->len |=
						cpu_to_be32(0x40000000);
			i++;
			skb1 = skb1->next;
		}
		ASFIPSEC_FPRINT("\nlen_to_caam %d ulFragpadlen %d",
				len_to_caam, ulFragpadlen);
		/* Go ahead and Submit to SEC */
		ptr = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->sec4_sg_dma = ptr;
		edesc->sec4_sg = link_tbl_entry;
#ifdef ASF_SECFP_PROTO_OFFLOAD
		/* In case of protocol offload prepare seperate SG list for
		   output */
		memcpy(link_tbl_entry + total_frags + 1,
			link_tbl_entry, dma_len);
		link_tbl_entry = link_tbl_entry + total_frags + 1;

		link_tbl_entry->ptr = ptr2 + iphdrlen + pSA->ulSecHdrLen + ulFragpadlen;
		link_tbl_entry->len = skb_headlen(skb) - iphdrlen - pSA->ulSecHdrLen - ulFragpadlen;

		ptr_out = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		(link_tbl_entry + total_frags + 1)->len += ulFragpadlen;

		edesc->sec4_sg_bytes = 2*dma_len;

		secfp_prepareInCaamJobDescriptor(descriptor, &pSA->ctx,
				ptr , len_to_caam, ptr_out,
				len_to_caam, 1);
#else
		edesc->sec4_sg_bytes = dma_len;

		{
		u32 *desc, options;
		int ivsize = pSA->SAParams.ulIvSize;
		int authsize = pSA->ctx.authsize;

		desc = edesc->hw_desc;

		/* insert shared descriptor pointer */
		init_job_desc_shared(desc, pSA->ctx.shared_desc_phys,
			desc_len(pSA->ctx.sh_desc), HDR_SHARE_DEFER);

		append_load(desc, ptr2 + SECFP_ESP_HDR_LEN, ivsize,
			LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

		/* start auth operation */
		append_operation(desc, pSA->ctx.class2_alg_type |
					OP_ALG_AS_INITFINAL | OP_ALG_ICV_ON);

		/* Load FIFO with data for Class 2 CHA */
		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

		append_fifo_load(desc, ptr2, SECFP_ESP_HDR_LEN, options);

		/* copy iv from cipher/class1 input
			context to class2 infifo */
		/* Need to know the IV size */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_CLASS2INFIFO | ivsize);

		{
			u32 *jump_cmd, *uncond_jump_cmd;

			/* JUMP if shared */
			jump_cmd = append_jump(desc, JUMP_TEST_ALL |
						JUMP_COND_SHRD);

			/* start class 1 (cipher) operation,
					non-shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
					| OP_ALG_AS_INITFINAL);

			uncond_jump_cmd = append_jump(desc, 0);

			set_jump_tgt_here(desc, jump_cmd);

			/* start class 1 (cipher) operation,
				shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
				| OP_ALG_AS_INITFINAL | OP_ALG_AAI_DK);

			set_jump_tgt_here(desc, uncond_jump_cmd);
		}

		/* load payload & instruct class2 to
			snoop class 1 if encrypting */
		options = 0;
		options |= LDST_SGF;

		append_seq_in_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_load(desc, len_to_caam - authsize,
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LASTBOTH |
				FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_store(desc, len_to_caam - authsize,
					FIFOST_TYPE_MESSAGE_DATA);

		/* ICV */
		append_seq_fifo_load(desc, authsize, FIFOLD_CLASS_CLASS2 |
					FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_DEBUG("\nData In Len:%d Data Out Len:%d Auth Size:%d",
			len_to_caam, len_to_caam - 12, authsize);
		print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
		DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif
		}
#endif
	}
#endif
	else {
		dma_addr_t ptr;
		int hdr_len;
#ifdef ASF_IPV6_FP_SUPPORT
		if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
			hdr_len = SECFP_IPV6_HDR_LEN;
		else
#endif
			hdr_len = SECFP_IPV4_HDR_LEN;

		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb->len + SECFP_HO_SEQNUM_LEN, DMA_BIDIRECTIONAL);

		ASFIPSEC_FPRINT("ulSecHdrLen %d skb->len %d",
			pSA->ulSecHdrLen, skb->len);
		ASFIPSEC_FPRINT(" asso@:");
		ASFIPSEC_HEXDUMP(skb->data, 8);
		ASFIPSEC_FPRINT(" presciv@:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen - 8, 8);
		ASFIPSEC_FPRINT(" src @:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen, 80);

		if (!ptr) {
			ASFIPSEC_ERR("DMA MAP FAILED\n");
			return;
		}
		secfp_prepareInCaamJobDescriptor(descriptor, &pSA->ctx,
#ifdef ASF_SECFP_PROTO_OFFLOAD
				ptr , skb->len, ptr + hdr_len + pSA->ulSecHdrLen,
					skb->len, 0);
#else
				ptr , skb->len, ptr, skb->len, 0);
#endif
	}
}
#endif /*QMAN*/

#endif /*defined(CONFIG_ASF_SEC4x)*/
