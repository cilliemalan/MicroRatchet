using System;

namespace MicroRatchet
{
    public interface IDigest
    {
        int DigestSize { get; }
        byte[] ComputeDigest(ArraySegment<byte> data);
    }
}