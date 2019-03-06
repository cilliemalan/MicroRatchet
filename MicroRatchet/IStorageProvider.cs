using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IStorageProvider
    {
        int HotSpace { get; }
        int ColdSpace { get; }
        void WriteHot(int storeOffset, ArraySegment<byte> data);
        void WriteCold(int storeOffset, ArraySegment<byte> data);
        void ReadHot(int readOffset, ArraySegment<byte> destination);
        void ReadCold(int readOffset, ArraySegment<byte> destination);
    }
}
