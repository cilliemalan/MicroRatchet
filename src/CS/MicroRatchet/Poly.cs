using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class Poly : IMac
    {
        private int _macSize;
        private Org.BouncyCastle.Crypto.Macs.Poly1305 _poly;

        public byte[] Compute()
        {
            var mac = new byte[_poly.GetMacSize()];
            _poly.DoFinal(mac, 0);

            if (_macSize == mac.Length)
            {
                return mac;
            }
            else
            {
                var output = new byte[_macSize];
                Array.Copy(mac, output, output.Length);
                return output;
            }
        }

        public void Init(byte[] key, byte[] iv, int macSize)
        {
            _macSize = macSize / 8;
            _poly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            _poly.Init(new KeyParameter(key));
        }

        public void Process(ArraySegment<byte> data)
        {
            _poly.BlockUpdate(data.Array, data.Offset, data.Count);
        }
    }
}
