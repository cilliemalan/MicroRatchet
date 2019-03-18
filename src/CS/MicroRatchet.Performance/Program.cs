using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace MicroRatchet.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            int messageCount = 100000;
            double clientDropChance = 0.0;
            double serverDropChance = 0.0;

            Random r = new Random();
            RandomNumberGenerator rng = new RandomNumberGenerator();
            KeyDerivation kdf = new KeyDerivation(new Digest());
            Stopwatch sw = new Stopwatch();


            {
                Console.WriteLine("Testing 128 bit ratchet speed...");
                SymmetricRacthet sr = new SymmetricRacthet();
                sr.ChainKey = rng.Generate(32);
                sr.KeySize = 16;
                var d = sr.RatchetForSending(kdf);
                d = sr.RatchetForSending(kdf);
                d = sr.RatchetForSending(kdf);
                Console.WriteLine("Doing 1000000 sending ratchets");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < 1000000; i++) _ = sr.RatchetForSending(kdf);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({1000000 / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                Console.WriteLine("Testing 256 bit ratchet speed...");
                SymmetricRacthet sr = new SymmetricRacthet();
                sr.ChainKey = rng.Generate(32);
                sr.KeySize = 32;
                var d = sr.RatchetForSending(kdf);
                d = sr.RatchetForSending(kdf);
                d = sr.RatchetForSending(kdf);
                Console.WriteLine("Doing 1000000 sending ratchets");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < 1000000; i++) _ = sr.RatchetForSending(kdf);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({1000000 / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                Console.WriteLine("Testing one way message send speed...");
                var (client, server) = CreateAndInitialize();
                var messagesToSend = Enumerable.Range(0, messageCount).Select(_ => rng.Generate(32)).ToArray();
                var messagesSent = new List<byte[]>(messageCount);
                var m1 = client.Send(new byte[32]);
                var m2 = client.Send(new byte[32]);
                var m3 = client.Send(new byte[32]);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) messagesSent.Add(client.Send(messagesToSend[i]));
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");


                Console.WriteLine("Testing one way message receive speed...");
                server.Receive(m1);
                server.Receive(m2);
                server.Receive(m3);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) server.Receive(messagesSent[i]);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                Console.WriteLine("Testing ratchet speed...");
                var (client, server) = CreateAndInitialize(false);
                var messagesToSend = Enumerable.Range(0, messageCount / 200).Select(_ => rng.Generate(32)).ToArray();
                server.Receive(client.Send(new byte[32]));
                client.Receive(server.Send(new byte[32]));
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount / 200; i++)
                {
                    var m1 = client.Send(messagesToSend[i]);
                    server.Receive(m1);
                    var m2 = server.Send(messagesToSend[i]);
                    client.Receive(m2);
                }
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(messageCount / 100) / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                var (client, server) = CreateAndInitialize();
                var clientMessages = new HashSet<byte[]>(Enumerable.Range(0, messageCount).Select(_ => rng.Generate(32)));
                var serverMessages = new HashSet<byte[]>(Enumerable.Range(0, messageCount).Select(_ => rng.Generate(32)));
                Queue<byte[]> clientMessagesToSend = new Queue<byte[]>(clientMessages);
                Queue<byte[]> serverMessagesToSend = new Queue<byte[]>(serverMessages);
                var messagesSentFromClient = new Queue<byte[]>();
                var messagesSentFromServer = new Queue<byte[]>();
                HashSet<byte[]> messagesReceivedByClient = new HashSet<byte[]>();
                HashSet<byte[]> messagesReceivedByServer = new HashSet<byte[]>();

                byte[] DoubleInSize(byte[] payload) => payload.Concat(payload).ToArray();

                int clientSent = 0, serverSent = 0, clientReceived = 0, serverReceived = 0, clientDropped = 0, serverDropped = 0;
                Console.WriteLine($"Sending {messageCount}/{clientDropChance:P0} and {messageCount}/{serverDropChance:P0}");

                sw.Reset();
                sw.Start();
                double oldTime = 0;
                int oldCnt = 0;
                for (int i = 0; ; i++)
                {
                    bool anyMessagesToReceive = messagesSentFromClient.TryPeek(out var _) || messagesSentFromServer.TryPeek(out var _);
                    bool anyMessagesToSend = clientMessagesToSend.TryPeek(out var _) || serverMessagesToSend.TryPeek(out var _);
                    if (!anyMessagesToReceive && !anyMessagesToSend)
                    {
                        break;
                    }

                    if (i % 1000 == 0)
                    {
                        var totalReceived = clientReceived + serverReceived + clientDropped + serverDropped;
                        var totalAll = messageCount + messageCount;
                        var percentage = (double)totalReceived / totalAll;

                        var newTime = sw.Elapsed.TotalSeconds;
                        var deltaTime = newTime - oldTime;
                        var deltaCnt = totalReceived - oldCnt;

                        double perSecond = 0;
                        if (oldTime != 0)
                        {
                            perSecond = deltaCnt / deltaTime;
                        }
                        Console.Write($"\r{percentage:P0} - c: {clientSent}/{clientDropped} -> {serverReceived}  s: {serverSent}/{serverDropped} -> {clientReceived}   ({perSecond:F0}/s)  ");

                        oldCnt = totalReceived;
                        oldTime = newTime;
                    }

                    var clientOrServer = r.Next(2);
                    var sendOrReceive = r.Next(2);
                    double ratio = (double)messageCount / messageCount;
                    int maxClient = 100;
                    int maxServer = (int)(100 / ratio);
                    var maxMessages = r.Next(clientOrServer == 0 ? maxClient : maxServer) + 1;

                    if (anyMessagesToSend && (sendOrReceive == 0 || !anyMessagesToReceive))
                    {
                        if (clientOrServer == 0) // send from client
                        {
                            while (maxMessages-- > 0)
                            {
                                clientMessagesToSend.TryDequeue(out var payload);
                                if (payload != null)
                                {
                                    payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                                    var message = client.Send(payload);
                                    if (r.NextDouble() > clientDropChance)
                                    {
                                        clientSent++;
                                        messagesSentFromClient.Enqueue(message);
                                    }
                                    else
                                    {
                                        clientDropped++;
                                    }
                                }
                            }
                        }
                        else
                        {
                            while (maxMessages-- > 0)
                            {
                                serverMessagesToSend.TryDequeue(out var payload);
                                if (payload != null)
                                {
                                    payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                                    var message = server.Send(payload);
                                    if (r.NextDouble() > serverDropChance)
                                    {
                                        serverSent++;
                                        messagesSentFromServer.Enqueue(message);
                                    }
                                    else
                                    {
                                        serverDropped++;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        if (clientOrServer != 0)  // receive by client
                        {
                            while (maxMessages-- > 0)
                            {
                                messagesSentFromServer.TryDequeue(out var message);
                                if (message != null)
                                {
                                    var payload = client.Receive(message);
                                    messagesReceivedByClient.Add(payload);
                                    clientReceived++;
                                }
                            }
                        }
                        else // receive by server
                        {
                            while (maxMessages-- > 0)
                            {
                                messagesSentFromClient.TryDequeue(out var message);
                                if (message != null)
                                {
                                    var payload = server.Receive(message);
                                    messagesReceivedByServer.Add(payload);
                                    serverReceived++;
                                }
                            }
                        }
                    }
                }

                Console.WriteLine("Done");
            }
        }

        private static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize(bool aes256 = false)
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);
            client.Configuration.UseAes256 = aes256;
            server.Configuration.UseAes256 = aes256;

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            var firstPacket = client.ProcessInitialization(responsePacket);
            var firstResponse = server.ProcessInitialization(firstPacket);
            var lastResult = client.ProcessInitialization(firstResponse);
            client.SaveState();
            server.SaveState();

            return (
                new MicroRatchetClient(clientServices, new MicroRatchetConfiguration { IsClient = true, Mtu = 80, UseAes256 = aes256 }),
                new MicroRatchetClient(serverServices, new MicroRatchetConfiguration { IsClient = false, Mtu = 80, UseAes256 = aes256 }));
        }
    }
}
