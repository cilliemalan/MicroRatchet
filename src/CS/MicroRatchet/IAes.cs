using System;

namespace MicroRatchet
{
    public interface IAes
    {
        void Initialize(bool encryption, ArraySegment<byte> key);
        void Process(ArraySegment<byte> input, ArraySegment<byte> output);
    }
}