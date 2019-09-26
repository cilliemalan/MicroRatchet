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
    }
}
