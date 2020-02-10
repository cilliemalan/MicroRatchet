#include "pch.h"
#include "ecc_common.h"
#include <microratchet.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>

const mbedtls_ecp_curve_info* secp256r1_ci = 0;
mbedtls_ecp_group secp256r1_gp = { 0 };

static mr_result load_curves()
{
	secp256r1_ci = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
	FAILIF(!secp256r1_ci, MR_E_NOTFOUND, "The SECP256R1 curve was not found");
	int r = mbedtls_ecp_group_load(&secp256r1_gp, MBEDTLS_ECP_DP_SECP256R1);
	FAILIF(r, MR_E_NOTFOUND, "The SECP256R1 curve was not found");

	return MR_E_SUCCESS;
}

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	FAILIF(!f_rng || !p_rng, MR_E_INVALIDSIZE, "RNG must not be null");

	mbedtls_ecp_point_init(pub);
	int r = mbedtls_mpi_read_binary(&pub->X, otherpublickey, otherpublickeysize);

	//if (!r)
	/*
	
		result = mp_init_multi(&t1, &t2, &p, &a, &b, 0);
		result = mp_read_radix(&p, dp->prime, MP_RADIX_HEX);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")
		result = mp_read_radix(&a, dp->Af, MP_RADIX_HEX);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")
		result = mp_read_radix(&b, dp->Bf, MP_RADIX_HEX);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")


		// t1 = x^3 over p
		result = mp_sqr(pub->x, &t1);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")
		result = mp_mulmod(&t1, pub->x, &p, &t1);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")

		// t1 = t1 + a*x over p
		result = mp_mulmod(&a, pub->x, &p, &t2);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")
		result = mp_add(&t1, &t2, &t1);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")

		// t1 = t1 + b
		result = mp_add(&t1, &b, &t1);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")

		// t2 = sqrt(t1) over p
		result = mp_sqrtmod_prime(&t1, &p, &t2);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0")

		// set y. and fix if not even
		if (mp_isodd(&t2) == MP_NO)
		{
			// y = t2 over p
			result = mp_mod(&t2, &p, pub->y);
		}
		else
		{
			// y = (p - t2) over p
			result = mp_submod(&p, &t2, &p, pub->y);
		}
	*/

	mp_int t1, t2;
	mbedtls_mpi_init(&t1);
	mbedtls_mpi_init(&t2);

	// t1 = x^3 mod p
	int r = mbedtls_mpi_mul_mpi(&t1, &pub->X, &pub->X);
	if (!r) r = mbedtls_mpi_mul_mpi(&t1, &pub->X, &t1);
	if (!r) r = mbedtls_mpi_mod_mpi(&t1, &t1, &secp256r1_gp.P);

	// t1 = t1 + a * x mod p
	if (!r) r = mbedtls_mpi_mul_mpi(&t2, &secp256r1_gp.A, &pub->X);
	if (!r) r = mbedtls_mpi_mod_mpi(&t2, &t2, &secp256r1_gp.P);
	if (!r) r = mbedtls_mpi_add_mpi(&t1, &t1, &t2);

	// t1 = t1 + b
	if (!r) r = mbedtls_mpi_add_mpi(&t1, &t1, &secp256r1_gp.B);


	return MR_E_NOTIMPL;
}


mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	FAILIF(!f_rng || !p_rng, MR_E_INVALIDSIZE, "RNG must not be null");

	mr_result r = load_curves();
	if (r) return r;

	mbedtls_mpi_init(&key->d);
	mbedtls_ecp_point_init(&key->Q);

	int ret;
	for (;;)
	{
		ret = mbedtls_ecp_gen_keypair(&secp256r1_gp, &key->d, &key->Q, f_rng, p_rng);
		if (!ret)
		{
			if (mbedtls_mpi_get_bit(&key->Q.Y, 0) == 0)
			{
				break;
			}
		}
		else
		{
			break;
		}
	}

	if (!ret)
	{
		ret = mbedtls_mpi_write_binary(&key->Q.X, publickey, publickeyspaceavail);
	}

	return ret ? MR_E_INVALIDOP : MR_E_SUCCESS;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	FAILIF(!key, MR_E_INVALIDARG, "key must not be null");
	FAILIF(!data, MR_E_INVALIDARG, "data must not be null");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "space must be at least 32");
	FAILIF(!f_rng || !p_rng, MR_E_INVALIDSIZE, "RNG must not be null");

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_mpi_init(&key->d);
	mbedtls_ecp_point_init(&key->Q);
	int r = mbedtls_mpi_read_binary(&key->d, data, spaceavail);
	if (!r)
	{
		r = mbedtls_ecp_mul(&secp256r1_gp, &key->Q, &key->d, &secp256r1_gp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return r ? 0 : 32;
}

mr_result ecc_store_size_needed(const ecc_key* key)
{
	return 32;
}

mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "key must not be null");
	FAILIF(!data, MR_E_INVALIDARG, "data must not be null");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "space must be at least 32");

	int r = mbedtls_mpi_write_binary(&key->d, data, 32);

	return r ? MR_E_INVALIDOP : MR_E_SUCCESS;
}

mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_verify(const ecc_key* key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	FAILIF(!f_rng || !p_rng, MR_E_INVALIDSIZE, "RNG must not be null");

	return MR_E_NOTIMPL;
}
