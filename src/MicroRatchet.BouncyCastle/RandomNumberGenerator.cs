using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    public class RandomNumberGenerator : IRandomNumberGenerator
    {
        private SecureRandom sr = new SecureRandom();

        public void Generate(ArraySegment<byte> arr) =>
            sr.NextBytes(arr.Array, arr.Offset, arr.Count);
    }
}
