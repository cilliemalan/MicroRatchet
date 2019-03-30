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
                //Debug.WriteLine($"   MAC:     {Convert.ToBase64String(mac)}");
                //Debug.WriteLine($"--maccing--");
                return mac;
            }
            else
            {
                var output = new byte[_macSize];
                Array.Copy(mac, output, output.Length);
                //Debug.WriteLine($"   MAC:     {Convert.ToBase64String(output)}");
                //Debug.WriteLine($"--maccing--");
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
                key = key.Concat(key).ToArray();
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

            //Debug.WriteLine($"--maccing--");
            //Debug.WriteLine($"   KEY:     {Convert.ToBase64String(key)}");
        }

        public void Process(ArraySegment<byte> data)
        {
            //Debug.WriteLine($"   MAC INPUT:     {Convert.ToBase64String(data.Array, data.Offset, data.Count)}");
            _poly.BlockUpdate(data.Array, data.Offset, data.Count);
        }
    }
}
