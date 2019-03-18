using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;

namespace MicroRatchet
{
    internal class AeadCipher : IDisposable, IAeadCipher
    {
        private byte[] key;

        public int MacSize { get; }
        public int BlockSize => 128;

        public AeadCipher(byte[] key, int macSize = 128)
        {
            this.key = key;
            this.MacSize = macSize;
        }

        public byte[] Encrypt(byte[] nonce, ArraySegment<byte> data, byte[] ad = null)
        {
            if (key == null) throw new ObjectDisposedException(nameof(AeadCipher));

            var encryptor = new GcmBlockCipher(new AesEngine());
            encryptor.Init(true, new AeadParameters(new KeyParameter(key), MacSize, nonce, ad));
            var output = new byte[encryptor.GetOutputSize(data.Count)];
            var len = encryptor.ProcessBytes(data.Array, data.Offset, data.Count, output, 0);
            encryptor.DoFinal(output, len);

            //Debug.WriteLine($"--AEAD encrypting--");
            //Debug.WriteLine($"   KEY:     {Convert.ToBase64String(key)}");
            //Debug.WriteLine($"   NONCE:   {Convert.ToBase64String(nonce ?? new byte[0])}");
            //Debug.WriteLine($"   AD:      {Convert.ToBase64String(ad ?? new byte[0])}");
            //Debug.WriteLine($"   PAYLOAD: {Convert.ToBase64String(data.Array, data.Offset, data.Count)}");
            //Debug.WriteLine($"   OUTPUT:  {Convert.ToBase64String(output ?? new byte[0])}");
            //Debug.WriteLine($"--AEAD encrypting--");
            return output;
        }

        public byte[] Decrypt(byte[] nonce, ArraySegment<byte> data, byte[] ad = null)
        {
            if (key == null) throw new ObjectDisposedException(nameof(AeadCipher));

            var decryptor = new GcmBlockCipher(new AesEngine());
            decryptor.Init(false, new AeadParameters(new KeyParameter(key), MacSize, nonce, ad));
            var output = new byte[decryptor.GetOutputSize(data.Count)];

            try
            {
                var len = decryptor.ProcessBytes(data.Array, data.Offset, data.Count, output, 0);
                decryptor.DoFinal(output, len);
            }
            catch (InvalidCipherTextException)
            {
                output = null;
            }

            //Debug.WriteLine($"--AEAD decrypting--");
            //Debug.WriteLine($"   KEY:     {Convert.ToBase64String(key)}");
            //Debug.WriteLine($"   NONCE:   {Convert.ToBase64String(nonce ?? new byte[0])}");
            //Debug.WriteLine($"   AD:      {Convert.ToBase64String(ad ?? new byte[0])}");
            //Debug.WriteLine($"   PAYLOAD: {Convert.ToBase64String(data.Array, data.Offset, data.Count)}");
            //Debug.WriteLine($"   OUTPUT:  {Convert.ToBase64String(output ?? new byte[0])}");
            //Debug.WriteLine($"--AEAD decrypting--");
            return output;
        }

        public void Dispose()
        {
            if (key != null)
            {
                Array.Clear(key, 0, key.Length);
                key = null;
            }
        }
    }
}
