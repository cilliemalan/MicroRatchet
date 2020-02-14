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