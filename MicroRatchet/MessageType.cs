using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal enum MessageType
    {
        Normal = 0b000,
        NormalWithEcdh = 0b001,
        InitializationRequest = 0b100,
        InitializationResponse = 0b101,
    }
}
