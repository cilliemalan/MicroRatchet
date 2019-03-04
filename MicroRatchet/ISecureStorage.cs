using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace MicroRatchet
{
    public interface ISecureStorage
    {
        void StoreAsync(byte[] data);
        byte[] LoadAsync();
    }
}
