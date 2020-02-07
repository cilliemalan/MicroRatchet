using System;

namespace MicroRatchet
{
    public interface IDigest
    {
        int DigestSize { get; }
        void Reset();
        void Process(ArraySegment<byte> data);
        byte[] Compute();
    }
}