#include "pch.h"
#include "ecc_common.h"
#include <microratchet.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>

mbedtls_ecp_group secp256r1_gp = { 0 };

static const uint32_t P[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };

// some of the code below is based on C# code from the bouncy castle library
// which is Copyright (c) 2000 - 2019 The Legion of the Bouncy Castle Inc.
// see https://www.bouncycastle.org/licence.html

static mr_result load_curves()
{
	if (!secp256r1_gp.id)
	{
		int r = mbedtls_ecp_group_load(&secp256r1_gp, MBEDTLS_ECP_DP_SECP256R1);
		FAILIF(r, MR_E_NOTFOUND, "The SECP256R1 curve was not found");
	}

	return MR_E_SUCCESS;
}

void mpi_to_nat256(uint32_t o[8], const mbedtls_mpi* z)
{
	for (int i = 0; i < 4; i++)
	{
		if (i < z->n)
		{
			uint64_t l = z->p[i];
			o[i * 2] = (uint32_t)l;
			o[i * 2 + 1] = l >> 32;
		}
		else
		{
			o[i * 2] = 0;
			o[i * 2 + 1] = 0;
		}
	}
}

void nat256_to_mpi(mbedtls_mpi* z, const uint32_t o[8])
{
	mbedtls_mpi_grow(z, 4);
	for (int i = 0; i < 4; i++)
	{
		z->p[i] = (((uint64_t)o[i * 2 + 1]) << 32) | o[i * 2];
	}
}

static uint32_t nat256_add(uint32_t z[8], uint32_t x[8], uint32_t y[8])
{
	uint64_t c = 0;
	c += (uint64_t)x[0] + y[0];
	z[0] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[1] + y[1];
	z[1] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[2] + y[2];
	z[2] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[3] + y[3];
	z[3] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[4] + y[4];
	z[4] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[5] + y[5];
	z[5] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[6] + y[6];
	z[6] = (uint32_t)c;
	c >>= 32;
	c += (uint64_t)x[7] + y[7];
	z[7] = (uint32_t)c;
	c >>= 32;
	return (uint32_t)c;
}

static uint32_t nat256_sub(uint32_t z[8], uint32_t x[8], uint32_t y[8])
{
	int64_t c = 0;
	c += (int64_t)x[0] - y[0];
	z[0] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[1] - y[1];
	z[1] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[2] - y[2];
	z[2] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[3] - y[3];
	z[3] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[4] - y[4];
	z[4] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[5] - y[5];
	z[5] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[6] - y[6];
	z[6] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)x[7] - y[7];
	z[7] = (uint32_t)c;
	c >>= 32;
	return (int)c;
}

static void nat256_mul(uint32_t zz[16], const uint32_t x[8], const uint32_t y[8])
{
	uint64_t y_0 = y[0];
	uint64_t y_1 = y[1];
	uint64_t y_2 = y[2];
	uint64_t y_3 = y[3];
	uint64_t y_4 = y[4];
	uint64_t y_5 = y[5];
	uint64_t y_6 = y[6];
	uint64_t y_7 = y[7];

	{
		uint64_t c = 0, x_0 = x[0];
		c += x_0 * y_0;
		zz[0] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_1;
		zz[1] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_2;
		zz[2] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_3;
		zz[3] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_4;
		zz[4] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_5;
		zz[5] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_6;
		zz[6] = (uint32_t)c;
		c >>= 32;
		c += x_0 * y_7;
		zz[7] = (uint32_t)c;
		c >>= 32;
		zz[8] = (uint32_t)c;
	}

	for (int i = 1; i < 8; ++i)
	{
		uint64_t c = 0, x_i = x[i];
		c += x_i * y_0 + zz[i + 0];
		zz[i + 0] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_1 + zz[i + 1];
		zz[i + 1] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_2 + zz[i + 2];
		zz[i + 2] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_3 + zz[i + 3];
		zz[i + 3] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_4 + zz[i + 4];
		zz[i + 4] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_5 + zz[i + 5];
		zz[i + 5] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_6 + zz[i + 6];
		zz[i + 6] = (uint32_t)c;
		c >>= 32;
		c += x_i * y_7 + zz[i + 7];
		zz[i + 7] = (uint32_t)c;
		c >>= 32;
		zz[i + 8] = (uint32_t)c;
	}
}

static void nat256_sqr(uint32_t zz[16], const uint32_t x[8])
{
	uint64_t x_0 = x[0];
	uint64_t zz_1;
	const uint64_t M = 0xFFFFFFFFUL;

	uint32_t c = 0, w;
	{
		int i = 7, j = 16;
		do
		{
			uint64_t xVal = x[i--];
			uint64_t p = xVal * xVal;
			zz[--j] = (c << 31) | (uint32_t)(p >> 33);
			zz[--j] = (uint32_t)(p >> 1);
			c = (uint32_t)p;
		} while (i > 0);

		{
			uint64_t p = x_0 * x_0;
			zz_1 = (uint64_t)(c << 31) | (p >> 33);
			zz[0] = (uint32_t)p;
			c = (uint32_t)(p >> 32) & 1;
		}
	}

	uint64_t x_1 = x[1];
	uint64_t zz_2 = zz[2];

	{
		zz_1 += x_1 * x_0;
		w = (uint32_t)zz_1;
		zz[1] = (w << 1) | c;
		c = w >> 31;
		zz_2 += zz_1 >> 32;
	}

	uint64_t x_2 = x[2];
	uint64_t zz_3 = zz[3];
	uint64_t zz_4 = zz[4];
	{
		zz_2 += x_2 * x_0;
		w = (uint32_t)zz_2;
		zz[2] = (w << 1) | c;
		c = w >> 31;
		zz_3 += (zz_2 >> 32) + x_2 * x_1;
		zz_4 += zz_3 >> 32;
		zz_3 &= M;
	}

	uint64_t x_3 = x[3];
	uint64_t zz_5 = zz[5] + (zz_4 >> 32); zz_4 &= M;
	uint64_t zz_6 = zz[6] + (zz_5 >> 32); zz_5 &= M;
	{
		zz_3 += x_3 * x_0;
		w = (uint32_t)zz_3;
		zz[3] = (w << 1) | c;
		c = w >> 31;
		zz_4 += (zz_3 >> 32) + x_3 * x_1;
		zz_5 += (zz_4 >> 32) + x_3 * x_2;
		zz_4 &= M;
		zz_6 += zz_5 >> 32;
		zz_5 &= M;
	}

	uint64_t x_4 = x[4];
	uint64_t zz_7 = zz[7] + (zz_6 >> 32); zz_6 &= M;
	uint64_t zz_8 = zz[8] + (zz_7 >> 32); zz_7 &= M;
	{
		zz_4 += x_4 * x_0;
		w = (uint32_t)zz_4;
		zz[4] = (w << 1) | c;
		c = w >> 31;
		zz_5 += (zz_4 >> 32) + x_4 * x_1;
		zz_6 += (zz_5 >> 32) + x_4 * x_2;
		zz_5 &= M;
		zz_7 += (zz_6 >> 32) + x_4 * x_3;
		zz_6 &= M;
		zz_8 += zz_7 >> 32;
		zz_7 &= M;
	}

	uint64_t x_5 = x[5];
	uint64_t zz_9 = zz[9] + (zz_8 >> 32); zz_8 &= M;
	uint64_t zz_10 = zz[10] + (zz_9 >> 32); zz_9 &= M;
	{
		zz_5 += x_5 * x_0;
		w = (uint32_t)zz_5;
		zz[5] = (w << 1) | c;
		c = w >> 31;
		zz_6 += (zz_5 >> 32) + x_5 * x_1;
		zz_7 += (zz_6 >> 32) + x_5 * x_2;
		zz_6 &= M;
		zz_8 += (zz_7 >> 32) + x_5 * x_3;
		zz_7 &= M;
		zz_9 += (zz_8 >> 32) + x_5 * x_4;
		zz_8 &= M;
		zz_10 += zz_9 >> 32;
		zz_9 &= M;
	}

	uint64_t x_6 = x[6];
	uint64_t zz_11 = zz[11] + (zz_10 >> 32); zz_10 &= M;
	uint64_t zz_12 = zz[12] + (zz_11 >> 32); zz_11 &= M;
	{
		zz_6 += x_6 * x_0;
		w = (uint32_t)zz_6;
		zz[6] = (w << 1) | c;
		c = w >> 31;
		zz_7 += (zz_6 >> 32) + x_6 * x_1;
		zz_8 += (zz_7 >> 32) + x_6 * x_2;
		zz_7 &= M;
		zz_9 += (zz_8 >> 32) + x_6 * x_3;
		zz_8 &= M;
		zz_10 += (zz_9 >> 32) + x_6 * x_4;
		zz_9 &= M;
		zz_11 += (zz_10 >> 32) + x_6 * x_5;
		zz_10 &= M;
		zz_12 += zz_11 >> 32;
		zz_11 &= M;
	}

	uint64_t x_7 = x[7];
	uint64_t zz_13 = zz[13] + (zz_12 >> 32); zz_12 &= M;
	uint64_t zz_14 = zz[14] + (zz_13 >> 32); zz_13 &= M;
	{
		zz_7 += x_7 * x_0;
		w = (uint32_t)zz_7;
		zz[7] = (w << 1) | c;
		c = w >> 31;
		zz_8 += (zz_7 >> 32) + x_7 * x_1;
		zz_9 += (zz_8 >> 32) + x_7 * x_2;
		zz_10 += (zz_9 >> 32) + x_7 * x_3;
		zz_11 += (zz_10 >> 32) + x_7 * x_4;
		zz_12 += (zz_11 >> 32) + x_7 * x_5;
		zz_13 += (zz_12 >> 32) + x_7 * x_6;
		zz_14 += zz_13 >> 32;
	}

	w = (uint32_t)zz_8;
	zz[8] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_9;
	zz[9] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_10;
	zz[10] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_11;
	zz[11] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_12;
	zz[12] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_13;
	zz[13] = (w << 1) | c;
	c = w >> 31;
	w = (uint32_t)zz_14;
	zz[14] = (w << 1) | c;
	c = w >> 31;
	w = zz[15] + (uint32_t)(zz_14 >> 32);
	zz[15] = (w << 1) | c;
}

static bool nat256_gte(const uint32_t x[8], const uint32_t y[8])
{
	for (int i = 7; i >= 0; --i)
	{
		uint32_t x_i = x[i], y_i = y[i];
		if (x_i < y_i) return false;
		if (x_i > y_i) return true;
	}
	return true;
}

static void secp256r1_pop(uint32_t z[8])
{
	int64_t c = (int64_t)z[0] + 1;
	z[0] = (uint32_t)c;
	c >>= 32;
	if (c != 0)
	{
		c += (int64_t)z[1];
		z[1] = (uint32_t)c;
		c >>= 32;
		c += (int64_t)z[2];
		z[2] = (uint32_t)c;
		c >>= 32;
	}
	c += (int64_t)z[3] - 1;
	z[3] = (uint32_t)c;
	c >>= 32;
	if (c != 0)
	{
		c += (int64_t)z[4];
		z[4] = (uint32_t)c;
		c >>= 32;
		c += (int64_t)z[5];
		z[5] = (uint32_t)c;
		c >>= 32;
	}
	c += (int64_t)z[6] - 1;
	z[6] = (uint32_t)c;
	c >>= 32;
	c += (int64_t)z[7] + 1;
	z[7] = (uint32_t)c;
	//c >>= 32;
}

static void secp256r1_reduce32(uint32_t z[8], uint32_t x)
{
	int64_t cc = 0;

	if (x != 0)
	{
		int64_t xx08 = x;

		cc += (int64_t)z[0] + xx08;
		z[0] = (uint32_t)cc;
		cc >>= 32;
		if (cc != 0)
		{
			cc += (int64_t)z[1];
			z[1] = (uint32_t)cc;
			cc >>= 32;
			cc += (int64_t)z[2];
			z[2] = (uint32_t)cc;
			cc >>= 32;
		}
		cc += (int64_t)z[3] - xx08;
		z[3] = (uint32_t)cc;
		cc >>= 32;
		if (cc != 0)
		{
			cc += (int64_t)z[4];
			z[4] = (uint32_t)cc;
			cc >>= 32;
			cc += (int64_t)z[5];
			z[5] = (uint32_t)cc;
			cc >>= 32;
		}
		cc += (int64_t)z[6] - xx08;
		z[6] = (uint32_t)cc;
		cc >>= 32;
		cc += (int64_t)z[7] + xx08;
		z[7] = (uint32_t)cc;
		cc >>= 32;
	}

	if (cc != 0 || (z[7] == 0xFFFFFFFF && nat256_gte(z, P)))
	{
		secp256r1_pop(z);
	}
}

static void secp256r1_reduce(uint32_t z[8], const uint32_t xx[16])
{
	int64_t xx08 = xx[8], xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];
	int64_t xx12 = xx[12], xx13 = xx[13], xx14 = xx[14], xx15 = xx[15];

	const int64_t n = 6;

	xx08 -= n;

	int64_t t0 = xx08 + xx09;
	int64_t t1 = xx09 + xx10;
	int64_t t2 = xx10 + xx11 - xx15;
	int64_t t3 = xx11 + xx12;
	int64_t t4 = xx12 + xx13;
	int64_t t5 = xx13 + xx14;
	int64_t t6 = xx14 + xx15;
	int64_t t7 = t5 - t0;

	int64_t cc = 0;
	cc += (int64_t)xx[0] - t3 - t7;
	z[0] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[1] + t1 - t4 - t6;
	z[1] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[2] + t2 - t5;
	z[2] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[3] + (t3 << 1) + t7 - t6;
	z[3] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[4] + (t4 << 1) + xx14 - t1;
	z[4] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[5] + (t5 << 1) - t2;
	z[5] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[6] + (t6 << 1) + t7;
	z[6] = (uint32_t)cc;
	cc >>= 32;
	cc += (int64_t)xx[7] + (xx15 << 1) + xx08 - t2 - t4;
	z[7] = (uint32_t)cc;
	cc >>= 32;
	cc += n;

	secp256r1_reduce32(z, (uint32_t)cc);
}

static void secp256r1_add(uint32_t z[8], uint32_t x[8], uint32_t y[8])
{
	uint32_t c = nat256_add(z, x, y);
	if (c != 0 || (z[7] == P[7] && nat256_gte(z, P)))
	{
		secp256r1_pop(z);
	}
}

static void secp256r1_sqr_n(uint32_t z[8], const uint32_t x[8], int n)
{
	uint32_t tt[16] = { 0 };
	nat256_sqr(tt, x);
	secp256r1_reduce(z, tt);

	while (--n > 0)
	{
		nat256_sqr(tt, z);
		secp256r1_reduce(z, tt);
	}
}

static void secp256r1_sqr(uint32_t z[8], const uint32_t x[8])
{
	uint32_t tt[16] = { 0 };
	nat256_sqr(tt, x);
	secp256r1_reduce(z, tt);
}

static void secp256r1_mul(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
{
	uint32_t tt[16] = { 0 };
	nat256_mul(tt, x, y);
	secp256r1_reduce(z, tt);
}

static void secp256r1_negate(uint32_t z[8], const uint32_t x[8])
{
	nat256_sub(z, P, x);
}

void secp256r1_sqrt(uint32_t z[8], const uint32_t x[8])
{
	uint32_t t1[8] = { 0 };
	uint32_t t2[8] = { 0 };

	// t1 = x * x
	// t1 = t1 * x
	secp256r1_sqr(t1, x);
	secp256r1_mul(t1, t1, x);

	// t2 = t1 ^^ 2
	// t2 = t1 * t2
	secp256r1_sqr_n(t2, t1, 2);
	secp256r1_mul(t2, t1, t2);

	// t1 = t2 ^^ 4
	// t1 = t2 * t1
	secp256r1_sqr_n(t1, t2, 4);
	secp256r1_mul(t1, t2, t1);

	// t2 = t1 ^^ 8
	// t2 = t1 * t2
	secp256r1_sqr_n(t2, t1, 8);
	secp256r1_mul(t2, t1, t2);

	// t1 = t2 ^^ 16
	// t1 = t2 * t1
	secp256r1_sqr_n(t1, t2, 16);
	secp256r1_mul(t1, t2, t1);

	// t1 = t1 ^^ 32
	// t1 = t1 * x
	secp256r1_sqr_n(t1, t1, 32);
	secp256r1_mul(t1, t1, x);

	// t1 = t1 ^^ 96
	// t1 = t1 * x
	secp256r1_sqr_n(t1, t1, 96);
	secp256r1_mul(t1, t1, x);

	// z = t1 ^^ 94
	// t2 = t1 * t1
	secp256r1_sqr_n(z, t1, 94);
	secp256r1_mul(t2, z, z);
}

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub)
{
	mr_result r = load_curves();
	if (r) return r;

	mbedtls_ecp_point_init(pub);
	r = mbedtls_mpi_read_binary(&pub->X, otherpublickey, otherpublickeysize);

	// y^2 = (x^2 + A) * x + b
	// 
	static const uint32_t A[8] = {
		0xFFFFFFFC,
		0xFFFFFFFF,
		0xFFFFFFFF,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000001,
		0xFFFFFFFF
	};
	uint32_t t1[8] = { 0 };
	uint32_t B[8], x[8];
	uint32_t a[8], b[8], c[8], d[8], y[8];

	mpi_to_nat256(x, &pub->X);
	mpi_to_nat256(B, &secp256r1_gp.B);
	secp256r1_sqr(a, x);
	secp256r1_add(b, a, A);
	secp256r1_mul(c, b, x);
	secp256r1_add(d, c, B);
	secp256r1_sqrt(y, d);

	if (y[0] & 1) {
		secp256r1_negate(y, y);
	}

	mp_int tmp;
	mbedtls_mpi_init(&tmp);
	nat256_to_mpi(&pub->Y, y);

	mbedtls_mpi_grow(&pub->Z, 1);
	pub->Z.p[0] = 1;

	return MR_E_SUCCESS;
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

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "key must not be null");
	FAILIF(!data, MR_E_INVALIDARG, "data must not be null");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "space must be at least 32");

	mr_result r = load_curves();
	if (r) return r;

	if (key->d.n) mbedtls_mpi_free(&key->d);
	if (key->Q.X.n) mbedtls_ecp_point_free(&key->Q);

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0);
	if (!r)
	{
		mbedtls_mpi_init(&key->d);
		mbedtls_ecp_point_init(&key->Q);
		r = mbedtls_mpi_read_binary(&key->d, data, spaceavail);
		if (!r)
		{
			r = mbedtls_ecp_mul(&secp256r1_gp, &key->Q, &key->d, &secp256r1_gp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
		}
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
	FAILIF(r, MR_E_INVALIDOP, "Failed to write private key");
	return MR_E_SUCCESS;
}

mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_verify(const ecc_key* key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDSIZE, "arguments must not be null");
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "public key must be at least 32 bytes");

	int r = mbedtls_mpi_write_binary(&key->Q.X, publickey, 32);
	FAILIF(r, MR_E_INVALIDOP, "Failed to write public key X coordinate");

	return MR_E_SUCCESS;
}
