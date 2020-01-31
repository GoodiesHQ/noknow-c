#include <noknow.h>
#include <noknow/debug.h>

/*
 * Add salt to hash
 */
static inline void salt_hash(mbedtls_md_context_t *ctx, const zk_params *zkparams) {
  mbedtls_md_update(ctx, zkparams->salt, SALT_SIZE);
}


/*
 * Export and hash affine point x,y coordinates
 */
static void hash_point(mbedtls_md_context_t *ctx, const zk_params *zkparams, const mbedtls_ecp_point *pt) {
  uint8_t buf[MBEDTLS_ECP_MAX_BYTES << 1] = { 0 };
  size_t len;
  if(mbedtls_ecp_point_write_binary(&zkparams->curve, pt, MBEDTLS_ECP_PF_COMPRESSED, &len, buf, sizeof(buf)) == 0) {
    mbedtls_md_update(ctx, buf, len);
    memset(buf, 0, len);
  } else {
    debugf("Hash failure\n");
  }
}

/*
 * Add buffer to hash context
 */
static inline void hash_buf(mbedtls_md_context_t *ctx, const uint8_t * const buf, size_t len) {
  mbedtls_md_update(ctx, buf, len);
}


/*
 * Hash the provided variadic arguments.
 * non-deterministric prj_pt will be converted to aff_pt before hashing
 */
bool zk_hash(const zk_params * zkparams, uint8_t *hbuf, size_t count, ...) {
  size_t i;
  bool ret;

  /* Parameters that can be passed through var_args */
  va_list args;
  mbedtls_ecp_point *pt;
  const uint8_t *ptr;
  size_t ptr_len;

  /* Initialize a new MD context */
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, zkparams->hash, 0);

  va_start(args, count);
  for(i = 0; i < count; ++i) {
    switch((char)(va_arg(args, int) & 0xFFu)) {
      case 'p': // prj_pt passed
        pt = va_arg(args, mbedtls_ecp_point*);
        hash_point(&ctx, zkparams, pt);
        break;
      case 'b': // buffer passed
        ptr = va_arg(args, uint8_t*);
        ptr_len = va_arg(args, size_t);
        hash_buf(&ctx, ptr, ptr_len);
        break;
    }
  }
  va_end(args);
  salt_hash(&ctx, zkparams);

  ret = (mbedtls_md_finish(&ctx, hbuf) == 0);
  mbedtls_md_free(&ctx);
  return ret;
}