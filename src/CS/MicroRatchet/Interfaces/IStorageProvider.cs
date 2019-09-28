using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace MicroRatchet
{
    public interface IStorageProvider
    {
        Stream Lock();
    }
}
