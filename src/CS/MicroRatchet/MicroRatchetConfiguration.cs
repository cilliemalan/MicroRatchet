using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public class MicroRatchetConfiguration
    {

        public int Mtu { get; set; } = 1000;
        public bool IsClient { get; set; } = true;
        public bool UseAes256 { get; set; } = false;
        public int NumberOfRatchetsToKeep { get; set; } = 7;
        public int MaxLostKeys { get; set; } = 100;
    }
}
