using System;
using System.Collections.Generic;
using System.Text;

#pragma warning disable CA1819 // Properties should not return arrays

namespace MicroRatchet
{
    public class ReceiveResult
    {
        public byte[] Payload { get; set; }
        public byte[] ToSendBack { get; set; }
    }
}
