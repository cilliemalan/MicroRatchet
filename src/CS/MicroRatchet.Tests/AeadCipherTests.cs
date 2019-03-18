using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class AeadCipherTests
    {
        [Fact]
        public void BasicTest()
        {
            var r = new Random();
            byte[] key = new byte[32];
            byte[] nonce = new byte[32];
            byte[] message = new byte[100];
            r.NextBytes(key);
            r.NextBytes(nonce);
            r.NextBytes(message);

            AeadCipher c = new AeadCipher(key);
            var encrypted = c.Encrypt(nonce, message);
            var decrypted = c.Decrypt(nonce, encrypted);

            Assert.Equal(message, decrypted);
        }

        [Theory]
        [InlineData(100, 128)]
        [InlineData(128, 128)]
        [InlineData(90, 128)]
        [InlineData(64, 128)]
        [InlineData(32, 128)]
        [InlineData(80, 128)]
        [InlineData(60, 128)]
        [InlineData(40, 128)]
        [InlineData(100, 96)]
        [InlineData(128, 96)]
        [InlineData(64, 96)]
        [InlineData(32, 96)]
        [InlineData(80, 96)]
        [InlineData(60, 96)]
        [InlineData(40, 96)]
        [InlineData(1000, 96)]
        public void CiphertextSizeTest(int messageSize, int macSize)
        {
            var r = new Random();
            byte[] key = new byte[32];
            byte[] nonce = new byte[32];
            byte[] message = new byte[messageSize];
            r.NextBytes(key);
            r.NextBytes(nonce);
            r.NextBytes(message);

            AeadCipher c = new AeadCipher(key, macSize);
            var encrypted = c.Encrypt(nonce, message);
            Assert.Equal(message.Length + (macSize / 8), encrypted.Length);
        }

        [Fact]
        public void RepeatibilityTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] key = new byte[32];
                byte[] nonce = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(key);
                r.NextBytes(nonce);
                r.NextBytes(message);

                AeadCipher c = new AeadCipher(key);
                var encrypted = c.Encrypt(nonce, message);
                var decrypted = c.Decrypt(nonce, encrypted);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void AssociatedDataTest()
        {
            var r = new Random();
            byte[] key = new byte[32];
            byte[] nonce = new byte[32];
            byte[] ad = new byte[32];
            byte[] message = new byte[100];
            r.NextBytes(key);
            r.NextBytes(nonce);
            r.NextBytes(ad);
            r.NextBytes(message);

            AeadCipher c = new AeadCipher(key);
            var encrypted = c.Encrypt(nonce, message, ad);
            var decrypted = c.Decrypt(nonce, encrypted, ad);

            Assert.Equal(message, decrypted);
        }

        [Fact]
        public void AssociatedDataMissingTest()
        {
            var r = new Random();
            byte[] key = new byte[32];
            byte[] nonce = new byte[32];
            byte[] ad = new byte[32];
            byte[] message = new byte[100];
            r.NextBytes(key);
            r.NextBytes(nonce);
            r.NextBytes(ad);
            r.NextBytes(message);

            AeadCipher c = new AeadCipher(key);
            var encrypted = c.Encrypt(nonce, message, ad);
            var decrypted = c.Decrypt(nonce, encrypted);

            Assert.Null(decrypted);
        }

        [Fact]
        public void AdRepeatibilityTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] key = new byte[32];
                byte[] nonce = new byte[32];
                byte[] ad = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(key);
                r.NextBytes(nonce);
                r.NextBytes(ad);
                r.NextBytes(message);

                AeadCipher c = new AeadCipher(key);
                var encrypted = c.Encrypt(nonce, message, ad);
                var decrypted = c.Decrypt(nonce, encrypted, ad);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void AlterFailsTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] key = new byte[32];
                byte[] nonce = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(key);
                r.NextBytes(nonce);
                r.NextBytes(message);

                AeadCipher c = new AeadCipher(key);
                var encrypted = c.Encrypt(nonce, message);
                encrypted[r.Next(encrypted.Length)]++;
                var decrypted = c.Decrypt(nonce, encrypted);

                Assert.Null(decrypted);
            }
        }

        [Fact]
        public void AlterNonceFailsTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] key = new byte[32];
                byte[] nonce = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(key);
                r.NextBytes(nonce);
                r.NextBytes(message);

                AeadCipher c = new AeadCipher(key);
                var encrypted = c.Encrypt(nonce, message);
                nonce[r.Next(nonce.Length)]++;
                var decrypted = c.Decrypt(nonce, encrypted);

                Assert.Null(decrypted);
            }
        }

        [Fact]
        public void AlterAdFailsTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] key = new byte[32];
                byte[] nonce = new byte[32];
                byte[] ad = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(key);
                r.NextBytes(nonce);
                r.NextBytes(ad);
                r.NextBytes(message);

                AeadCipher c = new AeadCipher(key);
                var encrypted = c.Encrypt(nonce, message, ad);
                ad[r.Next(ad.Length)]++;
                var decrypted = c.Decrypt(nonce, encrypted, ad);

                Assert.Null(decrypted);
            }
        }

        [Fact]
        public void DisposeTest()
        {
            AeadCipher c = new AeadCipher(new byte[32]);
            c.Dispose();
            Assert.Throws<ObjectDisposedException>(() => c.Encrypt(new byte[0], new byte[0]));
            Assert.Throws<ObjectDisposedException>(() => c.Decrypt(new byte[0], new byte[0]));
        }
    }
}
