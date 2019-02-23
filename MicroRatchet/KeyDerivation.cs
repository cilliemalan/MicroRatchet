using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class KeyDerivation : IDisposable, IKeyDerivation
    {
        private HMac _hmac;
        private int _hashLen;
        private byte[] _info;

        public KeyDerivation(byte[] key, byte[] info)
            : this()
        {
            Reset(key, info);
        }

        public KeyDerivation()
        {
            _hmac = new HMac(new Sha256Digest());
            _hashLen = _hmac.GetMacSize();
        }

        private void Reset(byte[] newKey, byte[] newInfo)
        {
            if (_hmac == null) throw new ObjectDisposedException(nameof(KeyDerivation));
            
            if (_info != null) Array.Clear(_info, 0, _info.Length);
            _info = new byte[newInfo.Length];
            Array.Copy(newInfo, _info, _info.Length);
            
            _hmac.Init(new KeyParameter(newKey));
        }

        public byte[] GenerateBytes(int howmany)
        {
            if (_hmac == null) throw new ObjectDisposedException(nameof(KeyDerivation));

            byte[] output = new byte[howmany];
            byte[] bytes = null;
            
            int offset = 0;
            int i = 0;

            void ExpandNext()
            {
                if (bytes != null) _hmac.BlockUpdate(bytes, 0, _hashLen);
                else bytes = new byte[_hashLen];
                if (_info != null) _hmac.BlockUpdate(_info, 0, _info.Length);
                _hmac.Update((byte)(i + 1));
                _hmac.DoFinal(bytes, 0);
            }

            while (offset < howmany)
            {
                ExpandNext();
                int left = howmany - offset;
                if (left > _hashLen) left = _hashLen;
                Array.Copy(bytes, 0, output, offset, left);
                offset += left;
                i++;
            }

            return output;
        }

        public void Dispose()
        {
            _hmac?.Init(new KeyParameter(new byte[32]));
            _hmac = null;
        }
    }
}
