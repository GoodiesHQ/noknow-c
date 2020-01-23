#ifndef NOKNOW_SECURITY_H
#define NOKNOW_SECURITY_H
#include <words/words.h>
#include <stdbool.h>

int get_random(unsigned char *buf, u16 len);
bool zk_are_equal(const u8 * const buf1, const u8 * const buf2, u16 buflen); // determines if buffers are equal in constant time
bool zk_is_supported_curve_name(const char *curve_name, ec_params *ecparams);
bool zk_is_supported_hash_name(const char *hash_name, const hash_mapping **mapping);
bool zk_is_supported_hash_type(const hash_alg_type hash_type, const hash_mapping **mapping);

#endif//NOKNOW_SECURITY_H
