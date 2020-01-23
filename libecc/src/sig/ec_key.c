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
#include "ec_key.h"
#include "sig_algs.h"
#include "../curves/curves.h"

void priv_key_check_initialized(const ec_priv_key *A)
{
	MUST_HAVE((A != NULL) && (A->magic == PRIV_KEY_MAGIC));
}

int priv_key_is_initialized(const ec_priv_key *A)
{
	return !!((A != NULL) && (A->magic == PRIV_KEY_MAGIC));
}

void priv_key_check_initialized_and_type(const ec_priv_key *A,
					 ec_sig_alg_type sig_type)
{
	MUST_HAVE((A != NULL) && (A->magic == PRIV_KEY_MAGIC)
		  && (A->key_type == sig_type));
}

int priv_key_is_initialized_and_type(const ec_priv_key *A,
				     ec_sig_alg_type sig_type)
{
	return !!((A != NULL) && (A->magic == PRIV_KEY_MAGIC)
		   && (A->key_type == sig_type));
}

/*
 * Import a private key from a buffer with known EC parameters and algorithm
 * Note that no sanity check is performed  by the function to verify key
 * is valid for params. Also note that no deep copy of pointed params is
 * performed.
 */
void ec_priv_key_import_from_buf(ec_priv_key *priv_key,
				 const ec_params *params,
				 const u8 *priv_key_buf, u8 priv_key_buf_len,
				 ec_sig_alg_type ec_key_alg)
{
	MUST_HAVE(priv_key != NULL);

	nn_init_from_buf(&(priv_key->x), priv_key_buf, priv_key_buf_len);

	/* Set key type and pointer to EC params */
	priv_key->key_type = ec_key_alg;
	priv_key->params = (const ec_params *)params;
	priv_key->magic = PRIV_KEY_MAGIC;
}

/* Export a private key to a buffer */
int ec_priv_key_export_to_buf(const ec_priv_key *priv_key, u8 *priv_key_buf,
			      u8 priv_key_buf_len)
{
	priv_key_check_initialized(priv_key);
	nn_export_to_buf(priv_key_buf, priv_key_buf_len, &(priv_key->x));

	return 0;
}

void pub_key_check_initialized(const ec_pub_key *A)
{
	MUST_HAVE((A != NULL) && (A->magic == PUB_KEY_MAGIC));
}

int pub_key_is_initialized(const ec_pub_key *A)
{
	return !!((A != NULL) && (A->magic == PUB_KEY_MAGIC));
}

void pub_key_check_initialized_and_type(const ec_pub_key *A,
					ec_sig_alg_type sig_type)
{
	MUST_HAVE((A != NULL) && (A->magic == PUB_KEY_MAGIC) &&
		  (A->key_type == sig_type));
}

int pub_key_is_initialized_and_type(const ec_pub_key *A,
				    ec_sig_alg_type sig_type)
{
	return !!((A != NULL) && (A->magic == PUB_KEY_MAGIC) &&
		   (A->key_type == sig_type));
}

/*
 * Import a public key from a buffer with known EC parameters and algorithm
 * Note that no sanity check is performed  by the function to verify key
 * is valid for params. Also note that no deep copy of pointed params is
 * performed.
 */
int ec_pub_key_import_from_buf(ec_pub_key *pub_key, const ec_params *params,
			       const u8 *pub_key_buf, u8 pub_key_buf_len,
			       ec_sig_alg_type ec_key_alg)
{
	int ret;

	MUST_HAVE((pub_key != NULL) && (params != NULL));

	/* Import the projective point */
	ret = prj_pt_import_from_buf(&(pub_key->y),
				     pub_key_buf, pub_key_buf_len,
				     (ec_shortw_crv_src_t)&(params->ec_curve));
	if (ret < 0) {
		return -1;
	}

	/* Set key type and pointer to EC params */
	pub_key->key_type = ec_key_alg;
	pub_key->params = (const ec_params *)params;
	pub_key->magic = PUB_KEY_MAGIC;

	return 0;
}

/* Export a public key to a buffer */
int ec_pub_key_export_to_buf(const ec_pub_key *pub_key, u8 *pub_key_buf,
			     u8 pub_key_buf_len)
{
	pub_key_check_initialized(pub_key);

	return prj_pt_export_to_buf(&(pub_key->y), pub_key_buf,
				    pub_key_buf_len);
}

void key_pair_check_initialized(const ec_key_pair *A)
{
	MUST_HAVE(A != NULL);
	priv_key_check_initialized(&A->priv_key);
	pub_key_check_initialized(&A->pub_key);
}

int key_pair_is_initialized(const ec_key_pair *A)
{
	return !!((A != NULL) && priv_key_is_initialized(&A->priv_key) &&
		   pub_key_is_initialized(&A->pub_key));
}

void key_pair_check_initialized_and_type(const ec_key_pair *A,
					 ec_sig_alg_type sig_type)
{
	MUST_HAVE(A != NULL);
	priv_key_check_initialized_and_type(&A->priv_key, sig_type);
	pub_key_check_initialized_and_type(&A->pub_key, sig_type);
}

int key_pair_is_initialized_and_type(const ec_key_pair *A,
				     ec_sig_alg_type sig_type)
{
	return !!((A != NULL) &&
		   priv_key_is_initialized_and_type(&A->priv_key, sig_type) &&
		   pub_key_is_initialized_and_type(&A->pub_key, sig_type));
}

/*
 * Import a key pair from a buffer representing the private key. The associated
 * public key is computed from the private key.
 */
int ec_key_pair_import_from_priv_key_buf(ec_key_pair *kp,
					 const ec_params *params,
					 const u8 *priv_key, u8 priv_key_len,
					 ec_sig_alg_type ec_key_alg)
{
	int ret;

	MUST_HAVE(kp != NULL);

	/* Import private key */
	ec_priv_key_import_from_buf(&(kp->priv_key), params, priv_key,
				    priv_key_len, ec_key_alg);

	/* Generate associated public key. */
	ret = init_pubkey_from_privkey(&(kp->pub_key), &(kp->priv_key));

	return ret;
}

/* Import a structured private key to buffer.
 * The structure allows some sanity checks.
 */
int ec_structured_priv_key_import_from_buf(ec_priv_key *priv_key,
					   const ec_params *params,
					   const u8 *priv_key_buf,
					   u8 priv_key_buf_len,
					   ec_sig_alg_type ec_key_alg)
{
	u8 metadata_len = (3 * sizeof(u8));
	u8 crv_name_len;
	int ret;

	/* We first pull the metadata, consisting of:
	 *   - One byte = the key type (public or private)
	 *   - One byte = the algorithm type (ECDSA, ECKCDSA, ...)
	 *   - One byte = the curve type (FRP256V1, ...)
	 */
	MUST_HAVE(priv_key_buf != NULL);
	MUST_HAVE(priv_key_buf_len > metadata_len);
	MUST_HAVE(params != NULL);
	MUST_HAVE(params->curve_name != NULL);

	/* Pull and check the key type */
	if (EC_PRIVKEY != priv_key_buf[0]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the algorithm type */
	if (ec_key_alg != priv_key_buf[1]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the curve type */
	crv_name_len = (u8)local_strlen((const char *)params->curve_name) + 1;
	ret = ec_check_curve_type_and_name((ec_curve_type) (priv_key_buf[2]),
					   params->curve_name, crv_name_len);
	if (ret) {
		ret = -1;
		goto err;
	}

	ec_priv_key_import_from_buf(priv_key, params,
				    priv_key_buf + metadata_len,
				    priv_key_buf_len - metadata_len,
				    ec_key_alg);

 err:
	return ret;
}

/* Export a structured private key to buffer.
 * The structure allows some sanity checks.
 */
int ec_structured_priv_key_export_to_buf(const ec_priv_key *priv_key,
					 u8 *priv_key_buf, u8 priv_key_buf_len)
{

	u8 metadata_len = (3 * sizeof(u8));
	const u8 *curve_name;
	u8 curve_name_len;
	ec_curve_type curve_type;

	priv_key_check_initialized(priv_key);

	/*
	 * We first put the metadata, consisting on:
	 *   - One byte = the key type (public or private)
	 *   - One byte = the algorithm type (ECDSA, ECKCDSA, ...)
	 *   - One byte = the curve type (FRP256V1, ...)
	 */
	MUST_HAVE(priv_key_buf != NULL);
	MUST_HAVE(priv_key_buf_len > metadata_len);
	MUST_HAVE(priv_key->params->curve_name != NULL);

	/* Push the key type */
	priv_key_buf[0] = (u8)EC_PRIVKEY;

	/* Push the algorithm type */
	priv_key_buf[1] = (u8)priv_key->key_type;

	/* Push the curve type */
	curve_name = priv_key->params->curve_name;
	curve_name_len = (u8)local_strlen((const char *)curve_name) + 1;
	curve_type = ec_get_curve_type_by_name(curve_name, curve_name_len);
	priv_key_buf[2] = (u8)curve_type;

	/* Abort if this is an unknown curve ... */
	if ((ec_curve_type) priv_key_buf[2] == UNKNOWN_CURVE) {
		return -1;
	}

	/* Push the raw private key buffer */
	return ec_priv_key_export_to_buf(priv_key, priv_key_buf + metadata_len,
					 priv_key_buf_len - metadata_len);
}

/*
 * Import a structured pub key from buffer.
 * The structure allows some sanity checks.
 */
int ec_structured_pub_key_import_from_buf(ec_pub_key *pub_key,
					  const ec_params *params,
					  const u8 *pub_key_buf,
					  u8 pub_key_buf_len,
					  ec_sig_alg_type ec_key_alg)
{
	u8 metadata_len = (3 * sizeof(u8));
	u8 crv_name_len;
	int ret;

	/*
	 * We first pull the metadata, consisting of:
	 *   - One byte = the key type (public or private)
	 *   - One byte = the algorithm type (ECDSA, ECKCDSA, ...)
	 *   - One byte = the curve type (FRP256V1, ...)
	 */
	MUST_HAVE(pub_key_buf != NULL);
	MUST_HAVE(pub_key_buf_len > metadata_len);
	MUST_HAVE(params != NULL);
	MUST_HAVE(params->curve_name != NULL);

	/* Pull and check the key type */
	if (EC_PUBKEY != pub_key_buf[0]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the algorithm type */
	if (ec_key_alg != pub_key_buf[1]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the curve type */
	crv_name_len =(u8)local_strlen((const char *)params->curve_name) + 1;
	ret = ec_check_curve_type_and_name((ec_curve_type) (pub_key_buf[2]),
					   params->curve_name, crv_name_len);
	if (ret) {
		ret = -1;
		goto err;
	}

	ret = ec_pub_key_import_from_buf(pub_key, params,
					 pub_key_buf + metadata_len,
					 pub_key_buf_len - metadata_len,
					 ec_key_alg);
 err:
	return ret;
}

/* Export a structured pubate key to buffer.
 * The structure allows some sanity checks.
 */
int ec_structured_pub_key_export_to_buf(const ec_pub_key *pub_key,
					u8 *pub_key_buf, u8 pub_key_buf_len)
{
	u8 metadata_len = (3 * sizeof(u8));
	const u8 *curve_name;
	u8 curve_name_len;
	ec_curve_type curve_type;

	pub_key_check_initialized(pub_key);

	/*
	 * We first put the metadata, consisting of:
	 *   - One byte = the key type (public or private)
	 *   - One byte = the algorithm type (ECDSA, ECKCDSA, ...)
	 *   - One byte = the curve type (FRP256V1, ...)
	 */
	MUST_HAVE(pub_key_buf != NULL);
	MUST_HAVE(pub_key_buf_len > metadata_len);
	MUST_HAVE(pub_key->params->curve_name != NULL);

	/* Push the key type */
	pub_key_buf[0] = (u8)EC_PUBKEY;

	/* Push the algorithm type */
	pub_key_buf[1] = (u8)pub_key->key_type;

	/* Push the curve type */
	curve_name = pub_key->params->curve_name;
	curve_name_len = (u8)local_strlen((const char *)curve_name) + 1;
	curve_type = ec_get_curve_type_by_name(curve_name, curve_name_len);
	pub_key_buf[2] = (u8)curve_type;

	/* Abort if this is an unknown curve ... */
	if ((ec_curve_type) pub_key_buf[2] == UNKNOWN_CURVE) {
		return -1;
	}

	/* Push the raw pub key buffer */
	return ec_pub_key_export_to_buf(pub_key, pub_key_buf + metadata_len,
					pub_key_buf_len - metadata_len);
}

/*
 * Import a key pair from a structured private key buffer. The structure allows
 * some sanity checks.
 */
int ec_structured_key_pair_import_from_priv_key_buf(ec_key_pair *kp,
						    const ec_params *params,
						    const u8 *priv_key_buf,
						    u8 priv_key_buf_len,
						    ec_sig_alg_type ec_key_alg)
{
	u8 metadata_len = (3 * sizeof(u8));
	u8 crv_name_len;
	int ret;

	/* We first pull the metadata, consisting on:
	 *   - One byte = the key type (public or private)
	 *   - One byte = the algorithm type (ECDSA, ECKCDSA, ...)
	 *   - One byte = the curve type (FRP256V1, ...)
	 */
	MUST_HAVE(priv_key_buf != NULL);
	MUST_HAVE(priv_key_buf_len > metadata_len);
	MUST_HAVE(params != NULL);
	MUST_HAVE(params->curve_name != NULL);

	/* Pull and check the key type */
	if (EC_PRIVKEY != priv_key_buf[0]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the algorithm type */
	if (ec_key_alg != priv_key_buf[1]) {
		ret = -1;
		goto err;
	}

	/* Pull and check the curve type */
	crv_name_len = (u8)local_strlen((const char *)params->curve_name) + 1;
	ret = ec_check_curve_type_and_name((ec_curve_type) (priv_key_buf[2]),
					   params->curve_name, crv_name_len);
	if (ret) {
		ret = -1;
		goto err;
	}

	ret = ec_key_pair_import_from_priv_key_buf(kp, params,
						   priv_key_buf + metadata_len,
						   priv_key_buf_len -
						   metadata_len, ec_key_alg);

 err:
	return ret;
}

/*
 * Import a key pair from a two structured key buffer (private and public one)
 * The function does not verify the coherency between private and public parts.
 */
int ec_structured_key_pair_import_from_buf(ec_key_pair *kp,
					   const ec_params *params,
					   const u8 *priv_key_buf,
					   u8 priv_key_buf_len,
					   const u8 *pub_key_buf,
					   u8 pub_key_buf_len,
					   ec_sig_alg_type ec_key_alg)
{
	int ret;

	ret = ec_structured_pub_key_import_from_buf(&kp->pub_key, params,
						    pub_key_buf,
						    pub_key_buf_len,
						    ec_key_alg);
	if (ret) {
		return -1;
	}

	ret = ec_structured_priv_key_import_from_buf(&kp->priv_key, params,
						     priv_key_buf,
						     priv_key_buf_len,
						     ec_key_alg);
	if (ret) {
		return -1;
	}

	return 0;
}

/*
 * Generate a public/private key pair for given signature algorithm, using
 * given EC params.
 */
int ec_key_pair_gen(ec_key_pair *kp, const ec_params *params,
		    ec_sig_alg_type ec_key_alg)
{
	int ret = -1;

	MUST_HAVE(kp != NULL);
	MUST_HAVE(params != NULL);

	/* Get a random value in ]0,q[ */
	ret = nn_get_random_mod(&(kp->priv_key.x), &(params->ec_gen_order));
	if (ret) {
		goto err;
	}

	/* Set key type and pointer to EC params for private key */
	kp->priv_key.key_type = ec_key_alg;
	kp->priv_key.params = (const ec_params *)params;
	kp->priv_key.magic = PRIV_KEY_MAGIC;

	/* Generate associated public key. */
	ret = init_pubkey_from_privkey(&(kp->pub_key), &(kp->priv_key));

 err:
	return ret;
}
