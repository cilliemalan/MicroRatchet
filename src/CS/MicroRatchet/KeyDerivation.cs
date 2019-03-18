using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class KeyDerivation : IKeyDerivation
    {
        private IDigest _digest;
        
        public KeyDerivation(IDigest digest)
        {
            _digest = digest;
        }

        public byte[] GenerateBytes(byte[] key, byte[] info, int howManyBytes)
        {
            var _hmac = new HMac(_digest);
            int _hashLen = _digest.DigestSize / 8;
            _hmac.Init(key);

            byte[] output = new byte[howManyBytes];
            byte[] bytes = null;

            int offset = 0;
            int i = 0;
            
            while (offset < howManyBytes)
            {
                if (bytes != null) _hmac.Process(bytes);
                if (info != null) _hmac.Process(info);
                _hmac.Process(new[] { (byte)(i + 1) });
                bytes = _hmac.Compute();

                int left = howManyBytes - offset;
                if (left > _hashLen) left = _hashLen;
                Array.Copy(bytes, 0, output, offset, left);
                offset += left;
                i++;
            }

            return output;
        }
    }
}
