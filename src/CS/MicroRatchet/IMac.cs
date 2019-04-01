using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IMac
    {
        void Init(byte[] key, ArraySegment<byte> iv, int macSize);
        void Process(ArraySegment<byte> data);
        byte[] Compute();
    }
}
