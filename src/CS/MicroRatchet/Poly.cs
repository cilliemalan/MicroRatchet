using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            if (iv != null) throw new InvalidOperationException("IV not supported.");
            _macSize = macSize / 8;
            _poly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            _poly.Init(new KeyParameter(key));

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
