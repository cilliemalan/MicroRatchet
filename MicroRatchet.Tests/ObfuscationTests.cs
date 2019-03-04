using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class ObfuscationTests
    {
        [Theory]
        [InlineData(1)]
        [InlineData(-1)]
        [InlineData(123)]
        [InlineData(6435)]
        [InlineData(-8345233)]
        [InlineData(2147483647)]
        [InlineData(-2147483647)]
        [InlineData(-52343123)]
        [InlineData(5424312)]
        [InlineData(-5424312)]
        [InlineData(-907653)]
        [InlineData(2134523)]
        [InlineData(-1233)]
        [InlineData(153635453)]
        [InlineData(-4524232)]
        public static void ObfuscateBasicTest(int n)
        {
            var kd = new KeyDerivation();
            var rng = new RandomNumberGenerator();
            byte[] nonce = BigEndianBitConverter.GetBytes(n);
            byte[] key = rng.Generate(32);
            byte[] ad = rng.Generate(64);

            var obfuscated = kd.Obfuscate(nonce, key, ad);
            var unobfuscated = kd.UnObfuscate(obfuscated, key, ad);

            int value = BigEndianBitConverter.ToInt32(nonce);

            Assert.Equal(4, obfuscated.Length);
            Assert.Equal(n, value);
        }
    }
}
