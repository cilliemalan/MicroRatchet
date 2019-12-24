using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MicroRatchet.Examples
{
    static class Server
    {
        const int PORT = 3422;

        public static async Task Run(CancellationToken cancellationToken)
        {
            using var udp = new UdpClient(PORT);
        }
    }
}
