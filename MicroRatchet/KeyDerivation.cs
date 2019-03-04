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
        public byte[] GenerateBytes(byte[] key, byte[] info, int howManyBytes)
        {
            HMac _hmac = new HMac(new Sha256Digest());
            int _hashLen = _hmac.GetMacSize();
            _hmac.Init(new KeyParameter(key));

            byte[] output = new byte[howManyBytes];
            byte[] bytes = null;

            int offset = 0;
            int i = 0;
            
            while (offset < howManyBytes)
            {
                if (bytes != null) _hmac.BlockUpdate(bytes, 0, _hashLen);
                else bytes = new byte[_hashLen];
                if (info != null) _hmac.BlockUpdate(info, 0, info.Length);
                _hmac.Update((byte)(i + 1));
                _hmac.DoFinal(bytes, 0);

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
