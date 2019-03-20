﻿using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal enum MessageType
    {
        Normal = 0b000,
        NormalWithEcdh = 0b001,
        MultiPartMessageEncrypted = 0b010,
        MultiPartMessageUnencrypted = 0b011,
        InitializationRequest = 0b100,
        InitializationWithoutEcdh = 0b100,
        InitializationResponse = 0b101,
        InitializationWithEcdh = 0b101,
        // Reserved - 0b110
        MultiPartRetransmissionRequest = 0b111
    }
}
