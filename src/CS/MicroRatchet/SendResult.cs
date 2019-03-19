using System;

namespace MicroRatchet
{
    public class SendResult
    {
        public byte[] Message => !IsMultipartMessage ? Messages[0] : throw new InvalidOperationException("The send result has multiple parts");
        public byte[][] Messages { get; set; }
        public bool IsMultipartMessage => Messages.Length > 1;
    }
}