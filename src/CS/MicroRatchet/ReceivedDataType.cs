using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public enum ReceivedDataType
    {
        Normal,
        Invalid,
        InitializationWithResponse,
        Multipart
    }
}
