#include "pch.h"
#include <microratchet.h>
#include "support.h"


#ifdef MBEDCRYPTO


#include "../microratchetmbed/ecc_common.h"
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>

extern "C" void secp256r1_sqrt(uint32_t[8], const uint32_t[8]);
extern "C" void mpi_to_nat256(uint32_t o[8], const mbedtls_mpi * z);
extern "C" void nat256_to_mpi(mbedtls_mpi * z, const uint32_t o[8]);

TEST(Ecc, DecompressGeneral) {

	mbedtls_ecp_group secp256r1_gp{};
	ASSERT_EQ(0, mbedtls_ecp_group_load(&secp256r1_gp, MBEDTLS_ECP_DP_SECP256R1));

	for (int ii = 0; ii < 100; ) {

		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context drbg;
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&drbg);
		
#ifdef MR_EMBEDDED
		mbedtls_entropy_add_source(&ctx->entropy, mr_mbedtls_entropy_f_source, 0, 32, MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

		ASSERT_EQ(0, mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, 0, 0));

		mbedtls_mpi d;
		mbedtls_ecp_point Q;
		mbedtls_ecp_point Q2;
		mbedtls_mpi_init(&d);
		mbedtls_ecp_point_init(&Q);
		mbedtls_ecp_point_init(&Q2);

		ASSERT_EQ(0, mbedtls_ecp_gen_keypair(&secp256r1_gp, &d, &Q, mbedtls_ctr_drbg_random, &drbg));
		if (Q.Y.p[0] & 1) {
			mbedtls_mpi_free(&d);
			mbedtls_ecp_point_free(&Q);
			mbedtls_entropy_free(&entropy);
			mbedtls_ctr_drbg_free(&drbg);
			continue;
		}

		uint8_t o[32]{};
		ASSERT_EQ(0, mbedtls_mpi_write_binary(&Q.X, o, sizeof(o)));
		ASSERT_EQ(MR_E_SUCCESS, ecc_import_public(o, sizeof(o), &Q2));

		uint8_t _x[32];
		uint8_t _y[32];
		mbedtls_mpi_write_binary(&Q.X, _x, sizeof(_x));
		mbedtls_mpi_write_binary(&Q.Y, _y, sizeof(_y));
		ASSERT_EQ(0, mbedtls_mpi_cmp_mpi(&Q.X, &Q2.X));
		ASSERT_EQ(0, mbedtls_mpi_cmp_mpi(&Q.Y, &Q2.Y));

		mbedtls_mpi_free(&d);
		mbedtls_ecp_point_free(&Q);
		mbedtls_ecp_point_free(&Q2);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&drbg);

		ii++;
	}
}


// Y: 0x00, 
TEST(Ecc, Decompress1) {

	uint8_t x[32] = {
		0xc0, 0x1d, 0x59, 0xab, 0x7a, 0x8e, 0x1d, 0xb5,
		0x49, 0x50, 0x21, 0x8c, 0xf3, 0x8a, 0xb4, 0x7c,
		0x63, 0x8f, 0x56, 0xce, 0x5f, 0x18, 0x73, 0x88,
		0x13, 0x94, 0xec, 0xb2, 0x95, 0x61, 0xaa, 0xbc,
	};
	uint8_t y[32];
	uint8_t _y[32] = {
		0xa9, 0xe6, 0x58, 0x79, 0x53, 0xb6, 0x77, 0x91,
		0x9e, 0x59, 0xc2, 0x4d, 0xc2, 0xae, 0xca, 0x43,
		0x53, 0x61, 0x36, 0x63, 0x48, 0xeb, 0x24, 0x9c,
		0xcb, 0x7f, 0x7a, 0x36, 0x65, 0xdd, 0x40, 0x32,
	};

	mbedtls_ecp_point Q;
	mbedtls_mpi_init(&Q.X);
	mbedtls_mpi_init(&Q.Y);
	mbedtls_mpi_init(&Q.Z);
	ASSERT_EQ(MR_E_SUCCESS, ecc_import_public(x, sizeof(x), &Q));

	mbedtls_mpi_write_binary(&Q.Y, y, sizeof(y));

	ASSERT_BUFFEREQ(y, sizeof(y), _y, sizeof(_y));
}

TEST(Ecc, Decompress2) {

	uint8_t x[32] = {
		0xc6, 0xfd, 0xf3, 0xab, 0x03, 0x1a, 0xd3, 0xd5,
		0x39, 0x9b, 0xb4, 0x02, 0x4c, 0x92, 0xdc, 0x0a,
		0xc2, 0x5d, 0xae, 0xd5, 0x46, 0xe9, 0x01, 0x46,
		0xe3, 0xc7, 0x17, 0x02, 0x4d, 0xeb, 0x08, 0xa6
	};
	uint8_t y[32];
	uint8_t _y[32] = {
		0xfc, 0xc6, 0x77, 0x97, 0xec, 0xce, 0x61, 0x35,
		0x4b, 0xc5, 0x58, 0x4a, 0x8f, 0xae, 0xb9, 0x9d,
		0xcd, 0x44, 0x49, 0x4e, 0x43, 0x09, 0xf4, 0xdf,
		0x36, 0x45, 0x9e, 0x3c, 0x8d, 0x63, 0x82, 0x74
	};

	mbedtls_ecp_point Q;
	mbedtls_mpi_init(&Q.X);
	mbedtls_mpi_init(&Q.Y);
	mbedtls_mpi_init(&Q.Z);
	ASSERT_EQ(MR_E_SUCCESS, ecc_import_public(x, sizeof(x), &Q));

	mbedtls_mpi_write_binary(&Q.Y, y, sizeof(y));

	ASSERT_BUFFEREQ(y, sizeof(y), _y, sizeof(_y));
}

TEST(Ecc, Sqrt) {
	mbedtls_ecp_group secp256r1_gp{};
	ASSERT_EQ(0, mbedtls_ecp_group_load(&secp256r1_gp, MBEDTLS_ECP_DP_SECP256R1));

	mbedtls_mpi d;
	mbedtls_mpi_init(&d);

	uint8_t i[32]{ 0xff, 0xfd, 0xfb, 0xfa, 0xfc, 0x00, 0x08, 0x15, 0x28, 0x42, 0x64, 0x8f, 0xc5, 0x05, 0x51, 0xa9, 0x32, 0xad, 0x17, 0x70, 0xb7, 0xec, 0x0c, 0x17, 0x0b, 0xe9, 0xaf, 0x5b, 0xee, 0x65, 0xc1, 0x00 };
	uint8_t e[32]{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x04, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	ASSERT_EQ(0, mbedtls_mpi_read_binary(&d, i, sizeof(i)));

	uint32_t td[8];
	mpi_to_nat256(td, &d);
	secp256r1_sqrt(td, td);
	uint8_t o[32];
	nat256_to_mpi(&d, td);
	mbedtls_mpi_write_binary(&d, o, sizeof(o));

	ASSERT_BUFFEREQ(e, sizeof(e), o, sizeof(o));


	mbedtls_mpi_free(&d);
}

#endif


#if defined(OPENSSL) || defined(CUSTOMCRYPTO)

#ifdef OPENSSL
#include "../microratchetopenssl/ecc_common.h"
#endif

#ifdef CUSTOMCRYPTO
#include "../microratchetcrypto/ecc_common.h"
#endif

static uint8_t zeroes[32] = { 0 };

TEST(Ecc, CreateDestroy) {
	ecc_initialize(nullptr);

	ecc_key key{};
	ecc_point point{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new_point(&point));

	ecc_free(&key);
	ecc_free_point(&point);

}

TEST(Ecc, Generate) {
	ecc_initialize(nullptr);

	ecc_key key{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));

	uint8_t pub[32] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key, pub, sizeof(pub)));

	EXPECT_BUFFERNES(zeroes, pub);

	ecc_free(&key);
}

TEST(Ecc, StoreLoad) {
	ecc_initialize(nullptr);

	ecc_key key1{};
	ecc_key key2{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key1));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key2));

	uint8_t pub1[32] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key1, pub1, sizeof(pub1)));

	uint8_t d[32] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_store(&key1, d, sizeof(d)));
	EXPECT_BUFFERNES(zeroes, d);

	EXPECT_EQ(32, ecc_load(&key2, d, sizeof(d)));

	uint8_t pub2[32] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_getpublickey(&key2, pub2, sizeof(pub2)));
	EXPECT_BUFFEREQS(pub1, pub2);

	ecc_free(&key1);
	ecc_free(&key2);
}

TEST(Ecc, ImportPublic) {
	ecc_initialize(nullptr);

	ecc_key key{};
	ecc_point pnt{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new_point(&pnt));
	 
	uint8_t pub[32] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key, pub, sizeof(pub)));

	EXPECT_EQ(MR_E_SUCCESS, ecc_import_public(pub, sizeof(pub), &pnt));


	ecc_free(&key);
	ecc_free_point(&pnt);
}

TEST(Ecc, SignVerify) {
	ecc_initialize(nullptr);

	uint8_t digest[32] = {
		1,2,3,4,5,6,7,8,
		9,10,11,12,13,14,15,16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32
	};

	ecc_key key{};
	ecc_point point{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new_point(&point));

	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key, 0, 0));
	EXPECT_EQ(MR_E_SUCCESS, ecc_getpublickey_point(&key, &point));

	uint8_t signature[64] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_sign(&key,
		digest, sizeof(digest),
		signature, sizeof(signature)));

	uint32_t valid = false;
	EXPECT_EQ(MR_E_SUCCESS, ecc_verify(&point,
		signature, sizeof(signature),
		digest, sizeof(digest),
		&valid));
	EXPECT_EQ(1, !!valid);

	ecc_free(&key);
	ecc_free_point(&point);
}

TEST(Ecc, SignVerifyInvalid) {
	ecc_initialize(nullptr);

	uint8_t digest[32] = {
		1,2,3,4,5,6,7,8,
		9,10,11,12,13,14,15,16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32
	};

	ecc_key key{};
	ecc_point point{};

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new_point(&point));

	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key, 0, 0));
	EXPECT_EQ(MR_E_SUCCESS, ecc_getpublickey_point(&key, &point));

	uint8_t signature[64] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_sign(&key,
		digest, sizeof(digest),
		signature, sizeof(signature)));

	// corrupt the signature
	signature[10]++;

	uint32_t valid = false;
	EXPECT_EQ(MR_E_SUCCESS, ecc_verify(&point,
		signature, sizeof(signature),
		digest, sizeof(digest),
		&valid));
	EXPECT_EQ(0, !!valid);

	ecc_free(&key);
	ecc_free_point(&point);
}

TEST(Ecc, SignVerifyOther) {
	ecc_initialize(nullptr);

	uint8_t digest[32] = {
		1,2,3,4,5,6,7,8,
		9,10,11,12,13,14,15,16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32
	};

	ecc_key key{};
	uint8_t pub[32];

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key));

	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key, pub, sizeof(pub)));

	uint8_t signature[64] = { 0 };
	EXPECT_EQ(MR_E_SUCCESS, ecc_sign(&key,
		digest, sizeof(digest),
		signature, sizeof(signature)));

	uint32_t valid = false;
	EXPECT_EQ(MR_E_SUCCESS, ecc_verify_other(
		signature, sizeof(signature),
		digest, sizeof(digest),
		pub, sizeof(pub),
		&valid));
	EXPECT_EQ(1, !!valid);

	ecc_free(&key);
}

TEST(Ecc, ComputeShared) {
	ecc_initialize(nullptr);

	ecc_key key1{};
	ecc_key key2{};
	uint8_t pubkey1[32];
	uint8_t pubkey2[32];

	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key1));
	EXPECT_EQ(MR_E_SUCCESS, ecc_new(&key2));

	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key1, pubkey1, sizeof(pubkey1)));
	EXPECT_EQ(MR_E_SUCCESS, ecc_generate(&key2, pubkey2, sizeof(pubkey2)));

	uint8_t derived1[32];
	uint8_t derived2[32];
	EXPECT_EQ(MR_E_SUCCESS, ecc_derivekey(&key1, pubkey2, SIZEOF(pubkey2), derived1, SIZEOF(derived1)));
	EXPECT_EQ(MR_E_SUCCESS, ecc_derivekey(&key2, pubkey1, SIZEOF(pubkey1), derived2, SIZEOF(derived2)));

	EXPECT_BUFFEREQ(derived1, sizeof(derived1), derived2, sizeof(derived2));

	ecc_free(&key1);
	ecc_free(&key2);
}

#endif