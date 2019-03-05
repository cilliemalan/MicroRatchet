using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class GMac : IMac
    {
        private Org.BouncyCastle.Crypto.Macs.GMac _gmac;

        public byte[] Compute()
        {
            byte[] output = new byte[_gmac.GetMacSize()];
            _gmac.DoFinal(output, 0);
            return output;
        }

        public void Init(byte[] key, byte[] iv, int macSize)
        {
            _gmac = new Org.BouncyCastle.Crypto.Macs.GMac(new GcmBlockCipher(new AesEngine()), macSize);
            _gmac.Init(new ParametersWithIV(new KeyParameter(key), iv));
        }

        public void Process(ArraySegment<byte> data)
        {
            _gmac.BlockUpdate(data.Array, data.Offset, data.Count);
        }
    }
}
