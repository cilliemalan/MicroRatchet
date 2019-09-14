using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    internal static class Common
    {
        public static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize(int mtu = 80, int maximumBufferedPartialMessageSize = 50 * 1024)
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var packet = client.InitiateInitialization();

            while (!client.IsInitialized || !server.IsInitialized)
            {
                packet = server.Receive(packet.Message).ToSendBack;
                if (packet != null)
                {
                    packet = client.Receive(packet.Message).ToSendBack;
                }
            }

            client.SaveState();
            server.SaveState();

            var clientConfig = new MicroRatchetConfiguration
            {
                IsClient = true,
                Mtu = mtu,
                MaximumBufferedPartialMessageSize = maximumBufferedPartialMessageSize,
                PartialMessageTimeout = maximumBufferedPartialMessageSize / mtu
            };
            var serverConfig = new MicroRatchetConfiguration
            {
                IsClient = false,
                Mtu = mtu,
                MaximumBufferedPartialMessageSize = maximumBufferedPartialMessageSize,
                PartialMessageTimeout = maximumBufferedPartialMessageSize / mtu
            };
            return (new MicroRatchetClient(clientServices, clientConfig), new MicroRatchetClient(serverServices, serverConfig));
        }

        public static IAesFactory AesFactory { get; } = new _AesFactory();

        private class _AesFactory : IAesFactory
        {
            public IAes GetAes(bool forEncryption, byte[] key)
            {
                var a = new Aes();
                a.Initialize(forEncryption, key);
                return a;
            }
        }
    }
}
