#include "pch.h"
#include "internal.h"
#include "support.h"

extern "C" void mr_memcpy(void* dst, const void* src, size_t amt);
extern "C" void mr_memzero(void* dst, size_t amt);

static uint8_t zeroes[30]{};

static void fillmem(uint8_t* ptr, size_t amt)
{
	for (size_t i = 0; i < amt; i++)
	{
		ptr[i] = static_cast<uint8_t>(i % 254) + 1;
	}
}

static void checkmem(bool zero, uint8_t* data, uint8_t* ptr, size_t amt, size_t len)
{
	ptrdiff_t off = reinterpret_cast<size_t>(ptr) - reinterpret_cast<size_t>(data);
	for (ptrdiff_t i = 0; i < off; i++)
	{
		if (zero)
		{
			ASSERT_EQ(data[i], 0);
		}
		else
		{
			ASSERT_NE(data[i], 0);
		}
	}
	for (ptrdiff_t i = off + amt; i < len; i++)
	{
		if (zero)
		{
			ASSERT_EQ(data[i], 0);
		}
		else
		{
			ASSERT_NE(data[i], 0);
		}
	}
}

static void checkzero(uint8_t* data, uint8_t* ptr, size_t amt, size_t len)
{
	checkmem(true, data, ptr, amt, len);
}

static void checknonzero(uint8_t* data, uint8_t* ptr, size_t amt, size_t len)
{
	checkmem(false, data, ptr, amt, len);
}


TEST(Memory, MemcpyAligned) {
	MR_ALIGN(16) uint8_t dataa[16]{};
	MR_ALIGN(16) uint8_t datab[16]{};

	fillmem(dataa, 16);
	mr_memcpy(datab, dataa, sizeof(dataa));
	ASSERT_BUFFEREQ(dataa, 16, datab, 16);
	checkzero(datab, datab, 16, 16);
}

TEST(Memory, MemcpyAlignedSmall1) {
	MR_ALIGN(16) uint8_t dataa[16]{};
	MR_ALIGN(16) uint8_t datab[16]{};

	fillmem(dataa, 8);
	mr_memcpy(datab, dataa, sizeof(dataa));
	ASSERT_BUFFEREQ(dataa, 8, datab, 8);
	checkzero(datab, datab, 8, 16);
}

TEST(Memory, MemcpyAlignedSmall2) {
	MR_ALIGN(16) uint8_t dataa[16]{};
	MR_ALIGN(16) uint8_t datab[16]{};

	fillmem(dataa, 4);
	mr_memcpy(datab, dataa, sizeof(dataa));
	ASSERT_BUFFEREQ(dataa, 4, datab, 4);
	checkzero(datab, datab, 4, 16);
}

TEST(Memory, MemcpyUnAligned1) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned2) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned3) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned4) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned5) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned6) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned7) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned8) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned9) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned10) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned11) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned12) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned13) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned14) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned15) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 5;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned16) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 5;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned17) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned18) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned19) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 0;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned20) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned21) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned22) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned23) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned24) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned25) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 1;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned26) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned27) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned28) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 3;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned29) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 7;
	auto p2 = datab + 6;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned30) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 6;
	auto p2 = datab + 7;

	fillmem(p1, 16);
	mr_memcpy(p2, p1, 16);
	ASSERT_BUFFEREQ(p1, 16, p2, 16);
	checkzero(datab, p2, 16, 30);
}

TEST(Memory, MemcpyUnAligned31) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 0;

	fillmem(p1, 15);
	mr_memcpy(p2, p1, 15);
	ASSERT_BUFFEREQ(p1, 15, p2, 15);
	checkzero(datab, p2, 15, 30);
}

TEST(Memory, MemcpyUnAligned32) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 1;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned33) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 0;

	fillmem(p1, 15);
	mr_memcpy(p2, p1, 15);
	ASSERT_BUFFEREQ(p1, 15, p2, 15);
	checkzero(datab, p2, 15, 30);
}

TEST(Memory, MemcpyUnAligned34) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 2;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned35) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 0;

	fillmem(p1, 12);
	mr_memcpy(p2, p1, 12);
	ASSERT_BUFFEREQ(p1, 12, p2, 12);
	checkzero(datab, p2, 12, 30);
}

TEST(Memory, MemcpyUnAligned36) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 3;

	fillmem(p1, 11);
	mr_memcpy(p2, p1, 11);
	ASSERT_BUFFEREQ(p1, 11, p2, 11);
	checkzero(datab, p2, 11, 30);
}

TEST(Memory, MemcpyUnAligned37) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 1;

	fillmem(p1, 12);
	mr_memcpy(p2, p1, 12);
	ASSERT_BUFFEREQ(p1, 12, p2, 12);
	checkzero(datab, p2, 12, 30);
}

TEST(Memory, MemcpyUnAligned38) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned39) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned40) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 15);
	mr_memcpy(p2, p1, 15);
	ASSERT_BUFFEREQ(p1, 15, p2, 15);
	checkzero(datab, p2, 15, 30);
}

TEST(Memory, MemcpyUnAligned41) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 1;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned42) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 3;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned43) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 12);
	mr_memcpy(p2, p1, 12);
	ASSERT_BUFFEREQ(p1, 12, p2, 12);
	checkzero(datab, p2, 12, 30);
}

TEST(Memory, MemcpyUnAligned44) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 3;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned45) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 5;
	auto p2 = datab + 0;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned46) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 5;

	fillmem(p1, 15);
	mr_memcpy(p2, p1, 15);
	ASSERT_BUFFEREQ(p1, 15, p2, 15);
	checkzero(datab, p2, 15, 30);
}

TEST(Memory, MemcpyUnAligned47) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 0;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned48) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 2;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned49) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 0;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned50) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 0;
	auto p2 = datab + 3;

	fillmem(p1, 15);
	mr_memcpy(p2, p1, 15);
	ASSERT_BUFFEREQ(p1, 15, p2, 15);
	checkzero(datab, p2, 15, 30);
}

TEST(Memory, MemcpyUnAligned51) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 1;

	fillmem(p1, 14);
	mr_memcpy(p2, p1, 14);
	ASSERT_BUFFEREQ(p1, 14, p2, 14);
	checkzero(datab, p2, 14, 30);
}

TEST(Memory, MemcpyUnAligned52) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 13);
	mr_memcpy(p2, p1, 13);
	ASSERT_BUFFEREQ(p1, 13, p2, 13);
	checkzero(datab, p2, 13, 30);
}

TEST(Memory, MemcpyUnAligned53) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 1;

	fillmem(p1, 12);
	mr_memcpy(p2, p1, 12);
	ASSERT_BUFFEREQ(p1, 12, p2, 12);
	checkzero(datab, p2, 12, 30);
}

TEST(Memory, MemcpyUnAligned54) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 11);
	mr_memcpy(p2, p1, 11);
	ASSERT_BUFFEREQ(p1, 11, p2, 11);
	checkzero(datab, p2, 11, 30);
}

TEST(Memory, MemcpyUnAligned55) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 1;

	fillmem(p1, 10);
	mr_memcpy(p2, p1, 10);
	ASSERT_BUFFEREQ(p1, 10, p2, 10);
	checkzero(datab, p2, 10, 30);
}

TEST(Memory, MemcpyUnAligned56) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 1;
	auto p2 = datab + 3;

	fillmem(p1, 4);
	mr_memcpy(p2, p1, 4);
	ASSERT_BUFFEREQ(p1, 4, p2, 4);
	checkzero(datab, p2, 4, 30);
}

TEST(Memory, MemcpyUnAligned57) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 3;
	auto p2 = datab + 2;

	fillmem(p1, 3);
	mr_memcpy(p2, p1, 3);
	ASSERT_BUFFEREQ(p1, 3, p2, 3);
	checkzero(datab, p2, 3, 30);
}

TEST(Memory, MemcpyUnAligned58) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 2;
	auto p2 = datab + 3;

	fillmem(p1, 2);
	mr_memcpy(p2, p1, 2);
	ASSERT_BUFFEREQ(p1, 2, p2, 2);
	checkzero(datab, p2, 2, 30);
}

TEST(Memory, MemcpyUnAligned59) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 7;
	auto p2 = datab + 6;

	fillmem(p1, 1);
	mr_memcpy(p2, p1, 1);
	ASSERT_BUFFEREQ(p1, 1, p2, 1);
	checkzero(datab, p2, 1, 30);
}

TEST(Memory, MemcpyUnAligned60) {
	MR_ALIGN(16) uint8_t dataa[30]{};
	MR_ALIGN(16) uint8_t datab[30]{};
	auto p1 = dataa + 6;
	auto p2 = datab + 7;

	fillmem(p1, 7);
	mr_memcpy(p2, p1, 7);
	ASSERT_BUFFEREQ(p1, 7, p2, 7);
	checkzero(datab, p2, 7, 30);
}

TEST(Memory, MemzeroAligned) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 0;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned1) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 1;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned2) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 2;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned3) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 3;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned4) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 4;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned5) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 5;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned6) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 6;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned7) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 7;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned8) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 8;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned9) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 9;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned10) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 10;

	mr_memzero(p, 16);
	ASSERT_BUFFEREQ(p, 16, zeroes, 16);
	checknonzero(data, p, 16, 30);
}

TEST(Memory, MemzeroUnaligned11) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 1;

	mr_memzero(p, 15);
	ASSERT_BUFFEREQ(p, 15, zeroes, 15);
	checknonzero(data, p, 15, 30);
}

TEST(Memory, MemzeroUnaligned12) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 2;

	mr_memzero(p, 17);
	ASSERT_BUFFEREQ(p, 17, zeroes, 17);
	checknonzero(data, p, 17, 30);
}

TEST(Memory, MemzeroUnaligned13) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 3;

	mr_memzero(p, 15);
	ASSERT_BUFFEREQ(p, 15, zeroes, 15);
	checknonzero(data, p, 15, 30);
}

TEST(Memory, MemzeroUnaligned14) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 4;

	mr_memzero(p, 13);
	ASSERT_BUFFEREQ(p, 13, zeroes, 13);
	checknonzero(data, p, 13, 30);
}

TEST(Memory, MemzeroUnaligned15) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 5;

	mr_memzero(p, 3);
	ASSERT_BUFFEREQ(p, 3, zeroes, 3);
	checknonzero(data, p, 3, 30);
}

TEST(Memory, MemzeroUnaligned16) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 6;

	mr_memzero(p, 7);
	ASSERT_BUFFEREQ(p, 7, zeroes, 7);
	checknonzero(data, p, 7, 30);
}

TEST(Memory, MemzeroUnaligned17) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 7;

	mr_memzero(p, 14);
	ASSERT_BUFFEREQ(p, 14, zeroes, 14);
	checknonzero(data, p, 14, 30);
}

TEST(Memory, MemzeroUnaligned18) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 8;

	mr_memzero(p, 15);
	ASSERT_BUFFEREQ(p, 15, zeroes, 15);
	checknonzero(data, p, 15, 30);
}

TEST(Memory, MemzeroUnaligned19) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 9;

	mr_memzero(p, 11);
	ASSERT_BUFFEREQ(p, 11, zeroes, 11);
	checknonzero(data, p, 11, 30);
}

TEST(Memory, MemzeroUnaligned20) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 10;

	mr_memzero(p, 12);
	ASSERT_BUFFEREQ(p, 12, zeroes, 12);
	checknonzero(data, p, 12, 30);
}

TEST(Memory, MemzeroUnaligned21) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 1;

	mr_memzero(p, 3);
	ASSERT_BUFFEREQ(p, 3, zeroes, 3);
	checknonzero(data, p, 3, 30);
}

TEST(Memory, MemzeroUnaligned22) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 2;

	mr_memzero(p, 2);
	ASSERT_BUFFEREQ(p, 2, zeroes, 2);
	checknonzero(data, p, 2, 30);
}

TEST(Memory, MemzeroUnaligned23) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 3;

	mr_memzero(p, 1);
	ASSERT_BUFFEREQ(p, 1, zeroes, 1);
	checknonzero(data, p, 1, 30);
}

TEST(Memory, MemzeroUnaligned24) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 4;

	mr_memzero(p, 3);
	ASSERT_BUFFEREQ(p, 3, zeroes, 3);
	checknonzero(data, p, 3, 30);
}

TEST(Memory, MemzeroUnaligned25) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 5;

	mr_memzero(p, 2);
	ASSERT_BUFFEREQ(p, 2, zeroes, 2);
	checknonzero(data, p, 2, 30);
}

TEST(Memory, MemzeroUnaligned26) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 6;

	mr_memzero(p, 1);
	ASSERT_BUFFEREQ(p, 1, zeroes, 1);
	checknonzero(data, p, 1, 30);
}

TEST(Memory, MemzeroUnaligned27) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 7;

	mr_memzero(p, 2);
	ASSERT_BUFFEREQ(p, 2, zeroes, 2);
	checknonzero(data, p, 2, 30);
}

TEST(Memory, MemzeroUnaligned28) {
	MR_ALIGN(16) uint8_t data[30]{};
	fillmem(data, sizeof(data));
	auto p = data + 8;

	mr_memzero(p, 3);
	ASSERT_BUFFEREQ(p, 3, zeroes, 3);
	checknonzero(data, p, 3, 30);
}
