using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public class ReceiveResult
    {
        public ReceivedDataType ReceivedDataType { get; set; }
        public byte[] Payload { get; set; }
        public byte[] ToSendBack { get; set; }
    }
}
