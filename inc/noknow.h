#ifndef NOKNOW_H
#define NOKNOW_H

#define PROJ_NAME "NoKnow"
#define PROJ_AUTHOR "Austin Archer <aarcher73k@gmail.com>"  
#define PROJ_URL "https://github.com/GoodiesHQ/noknow-c"    
#define PROJ_VER "0.1.0"

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libec.h>
#include <hash/hash_algs.h>

#include "noknow/debug.h"
#include "noknow/utils/security.h"
#include "noknow/utils/display.h"

#define SALT_SIZE 16  // Salts can be RFC4122 compliant UUID
#define RANDOM_SALT NULL


typedef struct _zk_params {
  hash_alg_type alg;
  ec_params ecparams;
  u8 salt[SALT_SIZE];
} zk_params;


typedef struct _zk_sig {
  aff_pt p;
} zk_signature;


typedef struct _zk_proof {
  nn c;
  nn m;
} zk_proof;

/* Return current version */
const char * noknow_version(void);

/*
 * Supported Curves:
 *  FRP256V1
 *  SECP192R1 SECP224R1 SECP256R1 SECP384R1 SECP521R1
 *  BRAINPOOLP224R1 BRAINPOOLP256R1 BRAINPOOLP384R1 BRAINPOOLP512R1
 *  GOST256 GOST512
 *
 * Supported Hashes:
 * SHA224 SHA256 SHA384 SHA512
 * SHA3_224 SHA3_256 SHA3_384 SHA3_512
 */
bool zk_is_supported_curve(const char *curve_name, ec_params *ecparams);
bool zk_is_supported_hash_name(const char *hash_name, const hash_mapping **mapping);
bool zk_is_supported_hash_type(const hash_alg_type hash_type, const hash_mapping **mapping);

void showhex(FILE *stream, const u8 * const buf, u16 len);
bool zk_hash(u8 *buf, const zk_params * const zkparams, const hash_mapping ** const hash_map, size_t count, ...);
bool zk_create_params(zk_params *zkparams, const char * const curve_name, const char * const hash_name, const u8 * const salt);
bool zk_create_signature(const zk_params * const zkparams, zk_signature *signature, const u8 *secret, const u32 secret_len);
bool zk_create_proof(const zk_params * const zkparams, zk_proof *proof, const u8 *secret, const u32 secret_len, const u8 *data, const u32 data_len);
bool zk_verify_proof(const zk_params * const zkparams, zk_signature * const signature, const zk_proof *proof, const u8 *data, const u32 data_len);

#endif//NOKNOW_H