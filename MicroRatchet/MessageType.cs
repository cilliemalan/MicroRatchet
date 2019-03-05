using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal enum MessageType
    {
        Normal = 0,
        NormalWithEcdh = 1,
        InitializationRequest = 3,
        InitializationResponse = 7,
    }
}
