using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IStorageProvider
    {
        void Store(byte[] data);
        byte[] Load();
        byte[] ReadLocalPublicKey();
    }
}
