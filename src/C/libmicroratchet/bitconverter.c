#include "pch.h"
#include "internal.h"

void be_pack64(long long value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 8, "long long must be size 8");
	target[0] = (value >> 56) & 0xff;
	target[1] = (value >> 48) & 0xff;
	target[2] = (value >> 40) & 0xff;
	target[3] = (value >> 32) & 0xff;
	target[4] = (value >> 24) & 0xff;
	target[5] = (value >> 16) & 0xff;
	target[6] = (value >> 8) & 0xff;
	target[7] = value & 0xff;
}

void be_pack32(int value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 4, "int must be size 4");
	target[0] = (value >> 24) & 0xff;
	target[1] = (value >> 16) & 0xff;
	target[2] = (value >> 8) & 0xff;
	target[3] = value & 0xff;
}

void be_pack16(short value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 2, "short must be size 2");
	target[0] = (value >> 8) & 0xff;
	target[1] = value & 0xff;
}

void le_pack64(long long value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 8, "long long must be size 8");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
	target[2] = (value >> 16) & 0xff;
	target[3] = (value >> 24) & 0xff;
	target[4] = (value >> 32) & 0xff;
	target[5] = (value >> 40) & 0xff;
	target[6] = (value >> 48) & 0xff;
	target[7] = (value >> 56) & 0xff;
}

void le_pack32(int value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 4, "int must be size 4");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
	target[2] = (value >> 16) & 0xff;
	target[3] = (value >> 24) & 0xff;
}

void le_pack16(short value, unsigned char* target)
{
	STATICASSERT(sizeof(value) == 2, "short must be size 2");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
}

long long be_unpack64(const unsigned char* d)
{
	return (long long)d[7] |
		((long long)d[6] << 8) |
		((long long)d[5] << 16) |
		((long long)d[4] << 24) |
		((long long)d[3] << 32) |
		((long long)d[2] << 40) |
		((long long)d[1] << 48) |
		((long long)d[0] << 56);
}

int be_unpack32(const unsigned char* d)
{
	return d[3] |
		d[2] << 8 |
		d[1] << 16 |
		d[0] << 24;
}

short be_unpack16(const unsigned char* d)
{
	return d[1] |
		d[0] << 8;
}

long long le_unpack64(const unsigned char* d)
{
	return (long long)d[0] |
		(long long)d[1] << 8 |
		(long long)d[2] << 16 |
		(long long)d[3] << 24 |
		(long long)d[4] << 32 |
		(long long)d[5] << 40 |
		(long long)d[6] << 48 |
		(long long)d[7] << 56;
}

int le_unpack32(const unsigned char* d)
{
	return d[0] |
		d[1] << 8 |
		d[2] << 16 |
		d[3] << 24;
}

short le_unpack16(const unsigned char* d)
{
	return d[0] |
		d[1] << 8;
}