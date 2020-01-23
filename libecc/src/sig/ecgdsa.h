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
#include "../lib_ecc_types.h"
#ifdef WITH_SIG_ECGDSA

#ifndef __ECGDSA_H__
#define __ECGDSA_H__

#include "../words/words.h"
#include "ec_key.h"
#include "../utils/utils.h"
#include "../hash/hash_algs.h"
#include "../curves/curves.h"

#define ECGDSA_R_LEN(q_bit_len)  (BYTECEIL(q_bit_len))
#define ECGDSA_S_LEN(q_bit_len)  (BYTECEIL(q_bit_len))
#define ECGDSA_SIGLEN(q_bit_len) (ECGDSA_R_LEN(q_bit_len) + \
				  ECGDSA_S_LEN(q_bit_len))
#define ECGDSA_MAX_SIGLEN    ECGDSA_SIGLEN(CURVES_MAX_Q_BIT_LEN)

/*
 * Compute max signature length for all the mechanisms enabled
 * in the library (see lib_ecc_config.h). Having that done during
 * preprocessing sadly requires some verbosity.
 */
#ifndef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN 0
#endif
#if ((EC_MAX_SIGLEN) < (ECGDSA_MAX_SIGLEN))
#undef EC_MAX_SIGLEN
#define EC_MAX_SIGLEN ECGDSA_MAX_SIGLEN
#endif

void ecgdsa_init_pub_key(ec_pub_key *out_pub, ec_priv_key *in_priv);

u8 ecgdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize);

typedef struct {
	hash_context h_ctx;
	word_t magic;
} ecgdsa_sign_data;

struct ec_sign_context;

int _ecgdsa_sign_init(struct ec_sign_context *ctx);

int _ecgdsa_sign_update(struct ec_sign_context *ctx,
			const u8 *chunk, u32 chunklen);

int _ecgdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

typedef struct {
	hash_context h_ctx;
	nn r;
	nn s;
	word_t magic;
} ecgdsa_verify_data;

struct ec_verify_context;

int _ecgdsa_verify_init(struct ec_verify_context *ctx,
			const u8 *sig, u8 siglen);

int _ecgdsa_verify_update(struct ec_verify_context *ctx,
			  const u8 *chunk, u32 chunklen);

int _ecgdsa_verify_finalize(struct ec_verify_context *ctx);

#endif /* __ECGDSA_H__ */
#endif /* WITH_SIG_ECGDSA */
