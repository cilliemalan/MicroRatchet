using System;

namespace MicroRatchet
{
    public class MessageInfo
    {
        public byte[] Message => !IsMultipartMessage ? Messages[0] : throw new InvalidOperationException("The message has multiple parts");
        public byte[][] Messages { get; set; }
        public bool IsMultipartMessage => Messages.Length > 1;
    }
}