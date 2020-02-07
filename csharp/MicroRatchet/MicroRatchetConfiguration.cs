using System;
using System.Collections.Generic;
using System.Text;

#pragma warning disable CA1819 // Properties should not return arrays
namespace MicroRatchet
{
    public class MicroRatchetConfiguration
    {
        public int MaximumMessageSize { get; set; } = 256;
        public int MinimumMessageSize { get; set; } = 32;
        public bool IsClient { get; set; } = true;
        public int NumberOfRatchetsToKeep { get; set; } = 7;
        public byte[] ApplicationKey { get; set; } = new byte[32];
    }
}
