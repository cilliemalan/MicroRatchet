#include "pch.h"
#include "internal.h"


void be_pack64(int64_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 8, "long long must be size 8");
	target[0] = (value >> 56) & 0xff;
	target[1] = (value >> 48) & 0xff;
	target[2] = (value >> 40) & 0xff;
	target[3] = (value >> 32) & 0xff;
	target[4] = (value >> 24) & 0xff;
	target[5] = (value >> 16) & 0xff;
	target[6] = (value >> 8) & 0xff;
	target[7] = value & 0xff;
}

void be_pack32(int32_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 4, "int must be size 4");
	target[0] = (value >> 24) & 0xff;
	target[1] = (value >> 16) & 0xff;
	target[2] = (value >> 8) & 0xff;
	target[3] = value & 0xff;
}

void be_pack16(int16_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 2, "short must be size 2");
	target[0] = (value >> 8) & 0xff;
	target[1] = value & 0xff;
}

void le_pack64(int64_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 8, "long long must be size 8");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
	target[2] = (value >> 16) & 0xff;
	target[3] = (value >> 24) & 0xff;
	target[4] = (value >> 32) & 0xff;
	target[5] = (value >> 40) & 0xff;
	target[6] = (value >> 48) & 0xff;
	target[7] = (value >> 56) & 0xff;
}

void le_pack32(int32_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 4, "int must be size 4");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
	target[2] = (value >> 16) & 0xff;
	target[3] = (value >> 24) & 0xff;
}

void le_pack16(int16_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 2, "short must be size 2");
	target[0] = value & 0xff;
	target[1] = (value >> 8) & 0xff;
}

int64_t be_unpack64(const uint8_t* d)
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

int32_t be_unpack32(const uint8_t* d)
{
	return d[3] |
		d[2] << 8 |
		d[1] << 16 |
		d[0] << 24;
}

int16_t be_unpack16(const uint8_t* d)
{
	return d[1] |
		d[0] << 8;
}

int64_t le_unpack64(const uint8_t* d)
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

int32_t le_unpack32(const uint8_t* d)
{
	return d[0] |
		d[1] << 8 |
		d[2] << 16 |
		d[3] << 24;
}

int16_t le_unpack16(const uint8_t* d)
{
	return d[0] |
		d[1] << 8;
}