using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet.Tests
{
    internal class InMemoryStorage : IStorageProvider
    {
        private byte[] memory;
        public InMemoryStorage(int space = 8192) => memory = new byte[space];
        public System.IO.Stream Lock() => new System.IO.MemoryStream(memory);
    }
}
