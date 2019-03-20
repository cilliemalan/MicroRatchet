using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public class ReceiveResult
    {
        public ReceivedDataType ReceivedDataType { get; set; }
        public byte[] Payload { get; set; }
        public MessageInfo ToSendBack { get; set; }
        public int MultipartSequence { get; set; }
        public int MessageNumber { get; set; }
        public int TotalMessages { get; set; }
    }
}
