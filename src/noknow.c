#include <noknow.h>
#include <noknow/debug.h>

/*
 * Return NoKnow project version
 */
const char * noknow_version(void)
{
  return PROJ_VER;
}

void zk_destroy_signature(zk_signature *signature)
{
  ENTER;
  mbedtls_ecp_point_free(&signature->p);
  LEAVE;
}

void zk_destroy_params(zk_params *zkparams)
{
  ENTER;
  mbedtls_ctr_drbg_free(&zkparams->rng_ctx);
  mbedtls_ecp_group_free(&zkparams->curve);
  LEAVE;
}


/*
Get the standardized elliptic curve by name and return true if the curve exists, false if not.
If true, the provided parameters have been initialized. If false, they are untouched.
*/
bool zk_create_params(zk_params *zkparams, const char * const curve_name, const char * const hash_name, const uint8_t * const salt) {
  ENTER;
  const mbedtls_ecp_curve_info *curve_info;
  const mbedtls_md_info_t *hash_info;
  if(!zk_is_supported_curve_name(curve_name, &curve_info)) {
    debugf("Invalid curve name '%s'\n", curve_name);
    return false;
  }

  if(!zk_is_supported_hash_name(hash_name, &hash_info)) {
    debugf("Invalid hash name '%s'\n", hash_name);
    return false;
  }

  debugf("Using curve %s and digest %s\n", curve_name, hash_name);

  /* Initialize random number generator */
  mbedtls_ctr_drbg_init(&zkparams->rng_ctx);
  mbedtls_ctr_drbg_seed(&zkparams->rng_ctx, mbedtls_entropy_func, zk_entropy(), NULL, 0);

  /* Load curve parameters into zkparams object */
  mbedtls_ecp_group_init(&zkparams->curve);
  mbedtls_ecp_group_load(&zkparams->curve, curve_info->grp_id);
  zkparams->hash = hash_info;

  // curve and hash are valid, we can now initialize the parameters.
  debugf("Initializing ZK parameters\n");
  if(salt == RANDOM_SALT) {
    debugf("Generating random salt\n");
    get_random(zkparams->salt, SALT_SIZE);
  } else {
    debugf("Using provided salt\n");
    memcpy(zkparams->salt, salt, SALT_SIZE);
  }
  LEAVE;
  return true;
}

bool zk_create_signature(zk_params * zkparams, zk_signature *signature, const uint8_t *secret, const size_t secret_len) {
  mbedtls_mpi k;
  size_t hlen = mbedtls_md_get_size(zkparams->hash);
  uint8_t hbuf[MBEDTLS_MD_MAX_SIZE];

  if(!zk_hash(zkparams, hbuf, 1, 'b', secret, secret_len)) {
    debugf("Hash failure\n");
    return false;
  }

  mbedtls_mpi_init(&k);
  mbedtls_mpi_read_binary(&k, hbuf, hlen);
  memset(hbuf, 0, hlen); // done with hash buffer
  zkparams->curve.modp(&k);
  mbedtls_ecp_point_init(&signature->p);
  mbedtls_ecp_mul(&zkparams->curve, &signature->p, &k, &zkparams->curve.G, mbedtls_ctr_drbg_random, &zkparams->rng_ctx);
  return true;
}


bool zk_create_proof(zk_params *zkparams, zk_proof *proof, const uint8_t *secret, size_t secret_len, const uint8_t *data, size_t data_len) {
  size_t hlen;
  uint8_t buf[NN_MAX(MBEDTLS_MD_MAX_SIZE, MBEDTLS_ECP_MAX_BYTES)];

  mbedtls_mpi k,        // hashed secret used as the discrete log of pp
              c,        // checksum used for data validation
              m,        // public m
              r;        // random value used as the discrete log of pr

  mbedtls_ecp_point pp, // public point
                    pr; // random point

  debugf("Creating proof\n");
  hlen = mbedtls_md_get_size(zkparams->hash);
  if(!zk_hash(zkparams, buf, 1, 'b', secret, secret_len)) {
    debugf("Hash failure\n");
    return false;
  }
  debugf("Created secret digest\n");

  // Initialize variables
  mbedtls_mpi_init(&proof->c);
  mbedtls_mpi_init(&proof->m);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&c);
  mbedtls_mpi_init(&m);
  mbedtls_mpi_init(&r);
  mbedtls_ecp_point_init(&pp);
  mbedtls_ecp_point_init(&pr);

  // read k from hash buffer
  mbedtls_mpi_read_binary(&k, buf, hlen);
  zkparams->curve.modp(&k);  // normalize within curve's finite field
  debugf("Calculating public signature point\n");
  mbedtls_ecp_mul(&zkparams->curve, &pp, &k, &zkparams->curve.G, mbedtls_ctr_drbg_random, &zkparams->rng_ctx);

  debugf("Generaing random r\n");
  // Fill the buffer with random data and load r
  get_random(buf, sizeof(buf));
  mbedtls_mpi_read_binary(&r, buf, sizeof(buf));
  memset(buf, 0, sizeof(buf));
  zkparams->curve.modp(&r); // normalize within curve's finite field
  mbedtls_ecp_mul(&zkparams->curve, &pr, &r, &zkparams->curve.G, mbedtls_ctr_drbg_random, &zkparams->rng_ctx);

  if(zk_hash(zkparams, buf, data == NULL ? 2 : 3, 'p', &pp, 'p', &pr, 'b', data, data_len)) {
    debugf("Hash successful\n");
    mbedtls_mpi_read_binary(&c, buf, hlen);
    mbedtls_mpi_copy(&proof->c, &c);
    mbedtls_mpi_mul_mpi(&m, &k, &c);  // m = c*k
    mbedtls_mpi_sub_mpi(&m, &r, &m);  // m = r - (c*k)
    zkparams->curve.modp(&m);
    mbedtls_mpi_copy(&proof->m, &m);
  }
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&m);
  mbedtls_mpi_free(&c);
  mbedtls_mpi_free(&k);
  mbedtls_ecp_point_free(&pr);
  mbedtls_ecp_point_free(&pr);
  return true;
}

bool zk_verify_proof(zk_params *zkparams, zk_signature *signature, zk_proof *proof, const uint8_t *data, size_t data_len) {
  uint8_t hbuf[MBEDTLS_MD_MAX_SIZE];
  bool equal = false;

  mbedtls_mpi c,  // local copy of proof->c
              m,  // local copy of proof->m
              f;  // final check value

  mbedtls_ecp_point pf;

  mbedtls_mpi_init(&c);
  mbedtls_mpi_init(&m);
  mbedtls_mpi_init(&f);
  mbedtls_ecp_point_init(&pf);
  
  // calculate 
  debugf("Loading proof\n");
  mbedtls_mpi_copy(&c, &proof->c);
  mbedtls_mpi_copy(&m, &proof->m);
  zkparams->curve.modp(&c);
  zkparams->curve.modp(&m);

  debugf("Determining the challenge point\n");
  mbedtls_ecp_muladd(&zkparams->curve, &pf, &c, &signature->p, &m, &zkparams->curve.G);

  debugf("Calculating digest\n");
  if(zk_hash(zkparams, hbuf, data == NULL ? 2 : 3, 'p', &signature->p, 'p', &pf, 'b', data, data_len)) {
    debugf("Hash successful\n");
    mbedtls_mpi_read_binary(&f, hbuf, mbedtls_md_get_size(zkparams->hash));
    equal = (mbedtls_mpi_cmp_mpi(&f, &proof->c) == 0);
  }

  mbedtls_ecp_point_free(&pf);
  mbedtls_mpi_free(&f);
  mbedtls_mpi_free(&m);
  mbedtls_mpi_free(&c);
  return equal;
}