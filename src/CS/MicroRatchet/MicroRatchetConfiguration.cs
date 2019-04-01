using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public class MicroRatchetConfiguration
    {

        public int Mtu { get; set; } = 1000;
        public bool IsClient { get; set; } = true;
        public int NumberOfRatchetsToKeep { get; set; } = 7;
        public int MaxLostKeys { get; set; } = 100;
        public int MaximumBufferedPartialMessageSize { get; set; } = 50 * 1024;
        public int PartialMessageTimeout { get; set; } = 20;
    }
}
