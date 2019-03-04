using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class CipherTests
    {
        [Fact]
        public void BasicTest()
        {
            var r = new Random();
            byte[] iv = new byte[32];
            byte[] key = new byte[32];
            byte[] message = new byte[100];
            r.NextBytes(iv);
            r.NextBytes(key);
            r.NextBytes(message);

            Cipher c = new Cipher(key, iv);
            var encrypted = c.Encrypt(message);
            var decrypted = c.Decrypt(encrypted);

            Assert.Equal(message, decrypted);
        }

        [Fact]
        public void RepeatibilityTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] iv = new byte[32];
                byte[] key = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(iv);
                r.NextBytes(key);
                r.NextBytes(message);

                Cipher c = new Cipher(key, iv);
                var encrypted = c.Encrypt(message);
                var decrypted = c.Decrypt(encrypted);

                Assert.Equal(message, decrypted);
            }
        }

        [Fact]
        public void AlterTest()
        {
            var r = new Random();

            for (int i = 0; i < 100; i++)
            {
                byte[] iv = new byte[32];
                byte[] key = new byte[32];
                byte[] message = new byte[100];
                r.NextBytes(iv);
                r.NextBytes(key);
                r.NextBytes(message);

                Cipher c = new Cipher(key, iv);
                var encrypted = c.Encrypt(message);
                encrypted[r.Next(encrypted.Length)]++;
                var decrypted = c.Decrypt(encrypted);

                Assert.NotNull(decrypted);
                Assert.NotEqual(message, decrypted);
            }
        }

        [Fact]
        public void DisposeTest()
        {
            Cipher c = new Cipher(new byte[32], new byte[32]);
            c.Dispose();
            Assert.Throws<ObjectDisposedException>(() => c.Encrypt(new byte[0]));
            Assert.Throws<ObjectDisposedException>(() => c.Decrypt(new byte[0]));
        }
    }
}
