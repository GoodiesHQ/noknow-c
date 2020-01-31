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

#include "noknow/utils/security.h"
#include "noknow/utils/display.h"

#define SALT_SIZE 16  // Salts can be RFC4122 compliant UUID
#define NN_MAX(x, y) (x) > (y) ? (x) : (y)
#define NN_MIN(x, y) (x) < (y) ? (x) : (y)
#define NN_EXPECT_OR_BREAK(err, x, val) if((err = x) != val) { break; }
#define RANDOM_SALT NULL


/*
 * Curve parameters
 *  curve:  mbedtls_ecp_group
 *          Used for all further elliptic point operations
 *  hash:   const mbedtls_md_info_t*
 *          Hashing context used for all further digests
 *  salt:   uint8_t[SALT_SIZE]
 *          The state salt used as an addition to all hashes. Universal salt should be all \x00's
 */

typedef struct _zk_params {
  const mbedtls_md_info_t *hash;
  mbedtls_ctr_drbg_context rng_ctx;
  mbedtls_ecp_group curve;
  uint8_t salt[SALT_SIZE];
} zk_params;


/*
 * Public Signature
 *  p:      mbedtls_ecp_point
 *          Public point on the curve whos discrete log is known to the user as Hash(password||salt)
 */
typedef struct _zk_sig {
  mbedtls_ecp_point p;
} zk_signature;


/*
 * Proof of Knowledge
 *  c:      the checksum Hash( signature_point || challenge_point || additional_data ) (signature_point and additional_data are public)
 *  m:      a value that allows the verifier to derive challenge_point from (and only from) an honest prover
 */
typedef struct _zk_proof {
  mbedtls_mpi c;
  mbedtls_mpi m;
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


void zk_destroy_params(zk_params *zkparams);
void zk_destroy_signature(zk_signature *signature);

bool zk_create_params(zk_params *zkparams, const char * const curve_name, const char * const hash_name, const uint8_t * const salt);
bool zk_create_signature(zk_params * zkparams, zk_signature *signature, const uint8_t *secret, const size_t secret_len);
bool zk_create_proof(zk_params *zkparams, zk_proof *proof, const uint8_t *secret, size_t secret_len, const uint8_t *data, size_t data_len);
bool zk_verify_proof(zk_params *zkparams, zk_signature *signature, zk_proof *proof, const uint8_t *data, size_t data_len);
bool zk_hash(const zk_params * zkparams, uint8_t *hbuf, size_t count, ...);
#if 0
//void showhex(FILE *stream, const u8 * const buf, u16 len);
bool zk_hash(u8 *buf, const zk_params * const zkparams, const hash_mapping ** const hash_map, size_t count, ...);
bool zk_verify_proof(const zk_params * const zkparams, zk_signature * const signature, const zk_proof *proof, const u8 *data, const u32 data_len);
#endif

#endif//NOKNOW_H