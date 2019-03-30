using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
                Log.Verbose($"   MAC:     {Log.ShowBytes(mac)}");
                Log.Verbose($"--maccing--");
                return mac;
            }
            else
            {
                var output = new byte[_macSize];
                Array.Copy(mac, output, output.Length);
                Log.Verbose($"   MAC:     {Log.ShowBytes(output)}");
                Log.Verbose($"--maccing--");
                return output;
            }
        }

        public void Init(byte[] key, byte[] iv, int macSize)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (macSize < 96 || macSize > 128) throw new InvalidOperationException("The Poly1305 MAC must be between 96 and 128 bits");

            if (key.Length == 16)
            {
                var nk = new byte[32];
                for (int i = 0; i < 16; i++) nk[i + 9] = key[i];
                for (int i = 0; i < 16; i++) nk[(i + 25) % 32] = (byte)(key[i] ^ 0xC3);
                key = nk;
            }
            
            _macSize = macSize / 8;
            _poly = new Poly1305(new AesEngine());
            if (iv.Length != 16)
            {
                byte[] newIv = new byte[16];
                Array.Copy(iv, 0, newIv, 0, Math.Min(iv.Length, 16));
                iv = newIv;
            }
            _poly.Init(new ParametersWithIV(new KeyParameter(key), iv));

            Log.Verbose($"--maccing--");
            Log.Verbose($"   IV:      {Log.ShowBytes(iv)}");
            Log.Verbose($"   KEY:     {Log.ShowBytes(key)}");
        }

        public void Process(ArraySegment<byte> data)
        {
            Log.Verbose($"   MAC INPUT:     {Log.ShowBytes(data.Array, data.Offset, data.Count)}");
            _poly.BlockUpdate(data.Array, data.Offset, data.Count);
        }
    }
}
