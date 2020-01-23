/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include "../lib_ecc_config.h"
#ifdef WITH_HASH_SHA3_256

#ifndef __SHA3_256_H__
#define __SHA3_256_H__

#include "../words/words.h"
#include "../utils/utils.h"
#include "sha3.h"

#define SHA3_256_BLOCK_SIZE   136
#define SHA3_256_DIGEST_SIZE  32

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SHA3_256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA3_256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA3_256_BLOCK_SIZE
#endif

typedef sha3_context sha3_256_context;

void sha3_256_init(sha3_256_context *ctx);
void sha3_256_update(sha3_256_context *ctx, const u8 *input, u32 ilen);
void sha3_256_final(sha3_256_context *ctx, u8 output[SHA3_256_DIGEST_SIZE]);
void sha3_256_scattered(const u8 **inputs, const u32 *ilens,
			u8 output[SHA3_256_DIGEST_SIZE]);
void sha3_256(const u8 *input, u32 ilen, u8 output[SHA3_256_DIGEST_SIZE]);

#endif /* __SHA3_256_H__ */
#endif /* WITH_HASH_SHA3_256 */
