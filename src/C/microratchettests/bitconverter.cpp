#include "pch.h"
#include <internal.h>
#include "support.h"

TEST(BitConverter, be_pack64_1) {
	long long v = 2343244324232344432;
	uint8_t expected[8] = { 0x20, 0x84, 0xE0, 0x4C, 0x3F, 0xD1, 0xB3, 0x70 };
	uint8_t out[8];
	be_pack64(v, out);

	EXPECT_BUFFEREQ(expected, 8, out, 8);
}

TEST(BitConverter, be_pack64_2) {
	long long v = -554445;
	uint8_t expected[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF7, 0x8A, 0x33 };
	uint8_t out[8];
	be_pack64(v, out);

	EXPECT_BUFFEREQ(expected, 8, out, 8);
}

TEST(BitConverter, be_pack32_1) {
	int v = 545172154;
	uint8_t expected[4] = { 0x20, 0x7E, 0xAA, 0xBA };
	uint8_t out[4];
	be_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}

TEST(BitConverter, be_pack32_2) {
	int v = -545172154;
	uint8_t expected[4] = { 0xDF, 0x81, 0x55, 0x46 };
	uint8_t out[4];
	be_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}


TEST(BitConverter, be_pack32_3) {
	uint32_t v = 4000000000;
	uint8_t expected[4] = { 0xEE, 0x6B, 0x28, 0x00 };
	uint8_t out[4];
	be_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}

TEST(BitConverter, be_pack16_1) {
	short v = 20000;
	uint8_t expected[2] = { 0x4E, 0x20 };
	uint8_t out[2];
	be_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}

TEST(BitConverter, be_pack16_2) {
	short v = -20000;
	uint8_t expected[2] = { 0xB1, 0xE0 };
	uint8_t out[2];
	be_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}

TEST(BitConverter, be_pack16_3) {
	unsigned short v = 60000;
	uint8_t expected[2] = { 0xEA, 0x60 };
	uint8_t out[2];
	be_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}

TEST(BitConverter, le_pack64_1) {
	long long v = 2343244324232344432;
	uint8_t expected[8] = { 0x70, 0xB3, 0xD1, 0x3F, 0x4C, 0xE0, 0x84, 0x20 };
	uint8_t out[8];
	le_pack64(v, out);

	EXPECT_BUFFEREQ(expected, 8, out, 8);
}

TEST(BitConverter, le_pack64_2) {
	long long v = -554445;
	uint8_t expected[8] = { 0x33, 0x8A, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	uint8_t out[8];
	le_pack64(v, out);

	EXPECT_BUFFEREQ(expected, 8, out, 8);
}

TEST(BitConverter, le_pack32_1) {
	int v = 545172154;
	uint8_t expected[4] = { 0xBA, 0xAA, 0x7E, 0x20 };
	uint8_t out[4];
	le_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}

TEST(BitConverter, le_pack32_2) {
	int v = -545172154;
	uint8_t expected[4] = { 0x46, 0x55, 0x81, 0xDF };
	uint8_t out[4];
	le_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}


TEST(BitConverter, le_pack32_3) {
	uint32_t v = 4000000000;
	uint8_t expected[4] = { 0x00, 0x28, 0x6B, 0xEE };
	uint8_t out[4];
	le_pack32(v, out);

	EXPECT_BUFFEREQ(expected, 4, out, 4);
}

TEST(BitConverter, le_pack16_1) {
	short v = 20000;
	uint8_t expected[2] = { 0x20, 0x4E };
	uint8_t out[2];
	le_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}

TEST(BitConverter, le_pack16_2) {
	short v = -20000;
	uint8_t expected[2] = { 0xE0, 0xB1 };
	uint8_t out[2];
	le_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}

TEST(BitConverter, le_pack16_3) {
	unsigned short v = 60000;
	uint8_t expected[2] = { 0x60, 0xEA };
	uint8_t out[2];
	le_pack16(v, out);

	EXPECT_BUFFEREQ(expected, 2, out, 2);
}







TEST(BitConverter, be_unpack64_1) {
	long long expected = 2343244324232344432;
	uint8_t v[8] = { 0x20, 0x84, 0xE0, 0x4C, 0x3F, 0xD1, 0xB3, 0x70 };

	auto out = be_unpack64(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack64_2) {
	long long expected = -554445;
	uint8_t v[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF7, 0x8A, 0x33 };

	auto out = be_unpack64(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack32_1) {
	int expected = 545172154;
	uint8_t v[4] = { 0x20, 0x7E, 0xAA, 0xBA };

	auto out = be_unpack32(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack32_2) {
	int expected = -545172154;
	uint8_t v[4] = { 0xDF, 0x81, 0x55, 0x46 };

	auto out = be_unpack32(v);

	EXPECT_EQ(out, expected);
}


TEST(BitConverter, be_unpack32_3) {
	uint32_t expected = 4000000000;
	uint8_t v[4] = { 0xEE, 0x6B, 0x28, 0x00 };

	auto out = be_unpack32(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack16_1) {
	short expected = 20000;
	uint8_t v[2] = { 0x4E, 0x20 };

	auto out = be_unpack16(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack16_2) {
	short expected = -20000;
	uint8_t v[2] = { 0xB1, 0xE0 };

	auto out = be_unpack16(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, be_unpack16_3) {
	unsigned short expected = 60000;
	uint8_t v[2] = { 0xEA, 0x60 };

	unsigned short out = be_unpack16(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack64_1) {
	long long expected = 2343244324232344432;
	uint8_t v[8] = { 0x70, 0xB3, 0xD1, 0x3F, 0x4C, 0xE0, 0x84, 0x20 };

	auto out = le_unpack64(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack64_2) {
	long long expected = -554445;
	uint8_t v[8] = { 0x33, 0x8A, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	auto out = le_unpack64(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack32_1) {
	int expected = 545172154;
	uint8_t v[4] = { 0xBA, 0xAA, 0x7E, 0x20 };

	auto out = le_unpack32(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack32_2) {
	int expected = -545172154;
	uint8_t v[4] = { 0x46, 0x55, 0x81, 0xDF };

	auto out = le_unpack32(v);

	EXPECT_EQ(out, expected);
}


TEST(BitConverter, le_unpack32_3) {
	uint32_t expected = 4000000000;
	uint8_t v[4] = { 0x00, 0x28, 0x6B, 0xEE };

	auto out = le_unpack32(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack16_1) {
	short expected = 20000;
	uint8_t v[2] = { 0x20, 0x4E };

	auto out = le_unpack16(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack16_2) {
	short expected = -20000;
	uint8_t v[2] = { 0xE0, 0xB1 };

	auto out = le_unpack16(v);

	EXPECT_EQ(out, expected);
}

TEST(BitConverter, le_unpack16_3) {
	unsigned short expected = 60000;
	uint8_t v[2] = { 0x60, 0xEA };

	unsigned short out = le_unpack16(v);

	EXPECT_EQ(out, expected);
}