using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class BigEndianBitConverterTests
    {
        [InlineData(1, new byte[] { 0, 0, 0, 1 })]
        [InlineData(-1, new byte[] { 255, 255, 255, 255 })]
        [InlineData(124123, new byte[] { 0, 1, 228, 219 })]
        [InlineData(-55455544, new byte[] { 252, 177, 208, 200 })]
        [Theory]
        public static void Int32ToBytesTest(int n, byte[] expected)
        {
            Assert.Equal(expected, BigEndianBitConverter.GetBytes(n));
        }

        [InlineData(1, new byte[] { 0, 0, 0, 1 })]
        [InlineData(1234745678, new byte[] { 73, 152, 185, 78 })]
        [InlineData(124123, new byte[] { 0, 1, 228, 219 })]
        [InlineData((uint)3987456977, new byte[] { 237, 171, 195, 209 })]
        [Theory]
        public static void UInt32ToBytesTest(uint n, byte[] expected)
        {
            Assert.Equal(expected, BigEndianBitConverter.GetBytes(n));
        }

        [InlineData(1, new byte[] { 0, 0, 0, 1 })]
        [InlineData(-1, new byte[] { 255, 255, 255, 255 })]
        [InlineData(124123, new byte[] { 0, 1, 228, 219 })]
        [InlineData(-55455544, new byte[] { 252, 177, 208, 200 })]
        [Theory]
        public static void BytesToInt32Test(int expected, byte[] n)
        {
            Assert.Equal(expected, BigEndianBitConverter.ToInt32(n));
        }

        [InlineData(1, new byte[] { 0, 0, 0, 1 })]
        [InlineData(1234745678, new byte[] { 73, 152, 185, 78 })]
        [InlineData(124123, new byte[] { 0, 1, 228, 219 })]
        [InlineData((uint)3987456977, new byte[] { 237, 171, 195, 209 })]
        [Theory]
        public static void BytesToUInt32Test(uint expected, byte[] n)
        {
            Assert.Equal(expected, BigEndianBitConverter.ToUInt32(n));
        }
    }
}
