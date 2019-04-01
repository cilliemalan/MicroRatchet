using System;

namespace MicroRatchet
{
    public interface IKeyDerivation
    {
        byte[] GenerateBytes(ArraySegment<byte> key, ArraySegment<byte> info, int howManyBytes);
    }
}