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
            var clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());
            var serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());

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

            var cs = client.SaveStateAsByteArray();
            var ss = server.SaveStateAsByteArray();

            return (new MicroRatchetClient(clientServices, true, mtu, stateBytes: cs),
                new MicroRatchetClient(serverServices, false, mtu, stateBytes: ss));
        }

        public static IAesFactory AesFactory { get; } = new _AesFactory();

        private class _AesFactory : IAesFactory
        {
            public int[] GetAcceptedKeySizes() => new[] { 16, 32 };

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
