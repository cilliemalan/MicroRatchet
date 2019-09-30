using MicroRatchet.BouncyCastle;
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
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var packet = client.InitiateInitialization();

            while (!client.IsInitialized || !server.IsInitialized)
            {
                packet = server.Receive(packet).ToSendBack;
                if (packet != null)
                {
                    packet = client.Receive(packet).ToSendBack;
                }
            }

            client.SaveState();
            server.SaveState();

            var clientConfig = new MicroRatchetConfiguration
            {
                IsClient = true,
                MaximumMessageSize = mtu
            };
            var serverConfig = new MicroRatchetConfiguration
            {
                IsClient = false,
                MaximumMessageSize = mtu
            };
            return (new MicroRatchetClient(clientServices, clientConfig), new MicroRatchetClient(serverServices, serverConfig));
        }

        public static IAesFactory AesFactory { get; } = new _AesFactory();

        private class _AesFactory : IAesFactory
        {
            public int[] AcceptedKeySizes { get; } = new[] { 16, 32 };

            public int BlockSize => 16;

            public IAes GetAes(bool forEncryption, ArraySegment<byte> key)
            {
                var a = new Aes();
                a.Initialize(forEncryption, key);
                return a;
            }
        }
    }
}
