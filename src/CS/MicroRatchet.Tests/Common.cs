using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet.Tests
{
    internal class Common
    {
        public static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize(int mtu = 80, bool allowImplicitMultipart = false)
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var packet = client.InitiateInitialization();

            while (!client.IsInitialized || !server.IsInitialized)
            {
                foreach (var m in packet.Messages)
                {
                    var newPacket = server.Receive(m).ToSendBack;
                    if (newPacket != null)
                    {
                        packet = newPacket;
                    }
                }

                if (packet != null)
                {
                    foreach (var m in packet.Messages)
                    {
                        var newPacket = client.Receive(m).ToSendBack;
                        if (newPacket != null)
                        {
                            packet = newPacket;
                        }
                    }
                }
            }

            client.SaveState();
            server.SaveState();

            var clientConfig = new MicroRatchetConfiguration { IsClient = true, AllowImplicitMultipartMessages = allowImplicitMultipart, Mtu = mtu };
            var serverConfig = new MicroRatchetConfiguration { IsClient = false, AllowImplicitMultipartMessages = allowImplicitMultipart, Mtu = mtu };
            return (new MicroRatchetClient(clientServices, clientConfig), new MicroRatchetClient(serverServices, serverConfig));
        }
    }
}
