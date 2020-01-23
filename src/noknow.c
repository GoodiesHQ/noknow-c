#include <noknow.h>


/*
 * Return NoKnow project version
 */
char * noknow_version(void)
{
  return PROJ_VER;
}

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


/*
Get the standardized elliptic curve by name and return true if the curve exists, false if not.
If true, the provided parameters have been initialized. If false, they are untouched.
*/
bool zk_create_params(zk_params *zkparams, const char * const curve_name, const char * const hash_name, const u8 * const salt)
{
  const hash_mapping *hash = NULL;

  if(!zk_is_supported_curve_name(curve_name, &zkparams->ecparams))
  {
    debugf("Invalid curve name '%s'\n", curve_name);
    return false;
  }

  if(!zk_is_supported_hash_name(hash_name, &hash))
  {
    debugf("Invalid hash name '%s'\n", hash_name);
    return false;
  }
  // curve and hash are valid, we can now initialize the parameters.
  debugf("Initializing ZK parameters\n");
  if(salt == RANDOM_SALT)
  {
    debugf("Generating random salt\n");
    get_random(zkparams->salt, SALT_SIZE);
  } else {
    debugf("Using provided salt\n");
    memcpy(zkparams->salt, salt, SALT_SIZE);
  }
  zkparams->alg = hash->type;
  return true;
}

bool zk_create_signature(const zk_params * const zkparams, zk_signature *signature, const u8 * const secret, const u32 secret_len)
{
  debugf("Creating signature\n");
  const hash_mapping *hash = NULL; // store the hash algorithm provided in zkparams
  static u8 hbuf[MAX_DIGEST_SIZE] = {0}; // buffer for the resulting salted hash digest
  nn k; // store the scalar representation of the hash value, used as discrete log of public signature point
  prj_pt p; // point stored after scalar multiplication

  if(!zk_hash(hbuf, zkparams, &hash, 1, 'b', secret, secret_len))
  {
    debugf("Hash Failure\n");
    return false;
  }

  // load k from hash buffer
  nn_init_from_buf(&k, hbuf, hash->digest_size);

  debugf("Performing point multiplication and converting prj_pt to aff_pt\n");
  prj_pt_mul(&p, &k, &zkparams->ecparams.ec_gen);
  prj_pt_to_aff(&signature->p, &p);

  debugf("Clearing variables to prevent information leakage\n");
  prj_pt_uninit(&p);
  nn_uninit(&k);
  memset(hbuf, 0, sizeof(hbuf));

  return true;
}

bool zk_create_proof(const zk_params * const zkparams, zk_proof *proof, const u8 *secret, const u32 secret_len, const u8 * const data, const u32 data_len)
{
  const hash_mapping *hash;
  static u8 hbuf[MAX_DIGEST_SIZE] = { 0 }; // hash buffer (calculated from pp, pt)

  nn k, // hashed secret used as the discrete log of pp
     c, // checksum for data validity
     m, // public m
     r; // random value used as the discrete log of pr

  prj_pt pp, // public point (montgomery)
         pr; // random point (montgomery)

  prj_pt_src_t g; // curve generator
  nn_src_t p; // curve order

  debugf("Calculating digest of secret\n");
  if(!zk_hash(hbuf, zkparams, &hash, 1, 'b', secret, secret_len))
  {
    debugf("Hash failure\n");
    return false;
  }
  g = &zkparams->ecparams.ec_gen;
  p = &zkparams->ecparams.ec_gen_order;

  debugf("Loading the private digest and calculating public curve point\n");
  nn_init_from_buf(&k, hbuf, hash->digest_size);
  memset(hbuf, 0, hash->digest_size); // prevent data leak, no need to have password hash lying around

  prj_pt_mul(&pp, &k, g);

  debugf("Generating random r within the field over which curve is defined\n");
  nn_get_random_mod(&r, p);
  prj_pt_mul(&pr, &r, g);

  debugf("Calculating data integrity digest\n");
  if(!zk_hash(hbuf, zkparams, &hash, data == NULL ? 2 : 3, 'p', &pp, 'p', &pr, 'b', data, data_len))
  {
    debugf("Hash failure\n");
    return false;
  }

  // load the public integrity check c from hash buffer, multiply by k, and subtract from r
  // P = order of the curve
  nn_init_from_buf(&c, hbuf, hash->digest_size);
  nn_copy(&proof->c, &c); // store c before it has used for calculations
  // c and k must be <= p before passed to nn_mul_mod
  nn_mod(&c, &c, p);           // c = c mod P
  nn_mod(&k, &k, p);           // k = k mod P

  nn_mul_mod(&m, &c, &k, p);   // m = ck mod P
  nn_mod_sub(&m, &r, &m, p);   // m = r - (ck) mod P
  nn_copy(&proof->m, &m); // store coefficient m

  debugf("Clearing variables to prevent information leakage\n");
  prj_pt_uninit(&pr);
  prj_pt_uninit(&pp);
  nn_uninit(&r);
  nn_uninit(&m);
  nn_uninit(&c);
  nn_uninit(&k);

  return true;
}

bool zk_verify_proof(const zk_params * const zkparams, zk_signature * const signature, const zk_proof *proof, const u8 *data, const u32 data_len)
{
  const hash_mapping *hash;
  bool equal;
  static u8 cbuf[MAX_DIGEST_SIZE] = { 0 }; // hash buffer (pulled from c)
  static u8 hbuf[MAX_DIGEST_SIZE] = { 0 };
  prj_pt pp,  // public point (from signature)
         pt,  // temporary point used for calculations
         pm;  // point calculated from m
  
  debugf("Loading public point from signature\n");
  ec_shortw_aff_to_prj(&pp, &signature->p);
  prj_pt_mul(&pm, &proof->m, &zkparams->ecparams.ec_gen);

  debugf("Calculating challenge point from proof\n");
  prj_pt_mul(&pt, &proof->c, &pp); // multiply c by pp to get ck*G
  prj_pt_add(&pt, &pm, &pt);       // add pm to get (r-ck)*G + (ck)*G which is the same as r*G (aka the randomly generated point) without learnign r

  debugf("Calculating integrity digest\n");
  if(zk_hash(hbuf, zkparams, &hash, data == NULL ? 2 : 3, 'p', &pp, 'p', &pt, 'b', data, data_len))
  {
    debugf("Performing integrity check in constant time\n");
    nn_export_to_buf(cbuf, hash->digest_size, &proof->c);
    equal = zk_are_equal(hbuf, cbuf, hash->digest_size); // perform constant-time equality check
  } else {
    debugf("Hash Failure\n");
    equal = false;
  }

  debugf("Clearing variables to prevent information leakage\n");
  memset(hbuf, 0, sizeof(hbuf));
  memset(cbuf, 0, sizeof(cbuf));

  return equal;
}
