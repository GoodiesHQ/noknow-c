#include <noknow.h>

/*
 * Add buffer to hash context
 */
static void hash_buf(const hash_mapping *hash, hash_context *ctx, const u8 * const buf, size_t len)
{
  hash->hfunc_update(ctx, buf, (u32)len);
}


/*
 * Export and hash affine point x,y coordinates
 */
static void hash_aff(const hash_mapping *hash, hash_context *ctx, aff_pt_src_t pt)
{
  const size_t len = BYTECEIL(pt->crv->a.ctx->p_bitlen);
  u8 buf[BYTECEIL(CURVES_MAX_P_BIT_LEN) << 1] = { 0 };
  fp_export_to_buf(buf, len, &pt->x);
  fp_export_to_buf(buf + len, len, &pt->y);
  hash->hfunc_update(ctx, buf, len*2);
  //prevent data leaks
  memset(buf, 0, len);
}

/*
 * Convert prj_pt to aff_pt before hashing
 */
static void hash_prj(const hash_mapping *hash, hash_context *ctx, prj_pt_src_t pt)
{
  // convert to affine point prior to hashing as this will ensure portability
  aff_pt a;
  prj_pt_to_aff(&a, pt);
  hash_aff(hash, ctx, &a);
  //prevent data leaks
  aff_pt_uninit(&a);
}

/*
 * Hash the provided variadic arguments.
 * non-deterministric prj_pt will be converted to aff_pt before hashing
 */
bool zk_hash(u8 *buf, const zk_params * const params, const hash_mapping ** const hash_map, size_t count, ...)
{
  size_t i;
  const hash_mapping *hash = NULL;
  hash_context ctx;
  va_list args;

  /* Parameters that can be passed through var_args */
  aff_pt_t a;
  prj_pt_t p;
  const u8 *ptr;
  u32 ptr_len;

  if((hash = get_hash_by_type(params->alg)) == NULL)
  {
    debugf("Invalid hash type: '%i'\n", params->alg);
    return false;
  }

  hash->hfunc_init(&ctx);

  va_start(args, count);
  for(i = 0; i < count; ++i)
  {
    switch((u8)(va_arg(args, int) & 0xFFu))
    {
      case 'a': // aff_pt passed
        a = va_arg(args, aff_pt_t);
        hash_aff(hash, &ctx, a);
        break;
      case 'p': // prj_pt passed
        p = va_arg(args, prj_pt_t);
        hash_prj(hash, &ctx, p);
        break;
      case 'b': // buffer passed
        ptr = va_arg(args, u8*);
        ptr_len = va_arg(args, u32);
        hash_buf(hash, &ctx, ptr, ptr_len);
        break;
    }
  }
  va_end(args);
  hash->hfunc_update(&ctx, params->salt, SALT_SIZE);
  hash->hfunc_finalize(&ctx, buf);
  if(hash_map != NULL)
  {
    *hash_map = hash;
  }
  return true;
}