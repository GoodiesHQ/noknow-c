#ifndef NOKNOW_SECURITY_H
#define NOKNOW_SECURITY_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <stdbool.h>

int get_random(unsigned char *buf, size_t len);

mbedtls_entropy_context *zk_entropy(void);
void zk_list_curves(FILE *stream);
void zk_list_hashes(FILE *stream);
bool zk_is_supported_curve_name(const char *curve_name, const mbedtls_ecp_curve_info ** curve_info);
bool zk_is_supported_hash_name(const char *hash_name, const mbedtls_md_info_t **mapping);
bool zk_are_equal(const uint8_t * const buf1, const uint8_t * const buf2, size_t buflen); // determines if buffers are equal in constant time
#if 0
bool zk_are_equal(const u8 * const buf1, const u8 * const buf2, u16 buflen); // determines if buffers are equal in constant time
bool zk_is_supported_hash_type(const hash_alg_type hash_type, const hash_mapping **mapping);
#endif

#endif//NOKNOW_SECURITY_H
