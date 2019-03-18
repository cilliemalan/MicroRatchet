using System;

namespace MicroRatchet
{
    public interface IRandomNumberGenerator
    {
        void Generate(ArraySegment<byte> arr);
    }
}