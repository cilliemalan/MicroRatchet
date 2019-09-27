using Org.BouncyCastle.Crypto.Parameters;
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
            int messageCount = 1000000;
            double clientDropChance = 0.0;
            double serverDropChance = 0.0;

            Random r = new Random();
            RandomNumberGenerator rng = new RandomNumberGenerator();
            Stopwatch sw = new Stopwatch();
            
            Console.WriteLine("Generating data...");
            byte[] keys = new byte[16 * 1000000];
            byte[] blocks = new byte[16 * 1000000];
            byte[] output = new byte[32 * 1000000];
            rng.Generate(keys);
            rng.Generate(blocks);

            Thread.Sleep(1000);
            {
                var sha = System.Security.Cryptography.SHA256.Create();
                sha.ComputeHash(blocks, 10000, 16);
                Console.WriteLine("Doing SHA256 hashes (dotnet)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < blocks.Length; i += 16)
                {
                    sha.ComputeHash(blocks, i, 16);
                }

                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                var sha = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
                sha.BlockUpdate(blocks, 10000, 16);
                sha.DoFinal(output, 10000);
                Console.WriteLine("Doing SHA256 hashes (bc)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < blocks.Length; i += 16)
                {
                    sha.BlockUpdate(blocks, i, 16);
                    sha.DoFinal(output, i * 2);
                }

                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                var aes = System.Security.Cryptography.Aes.Create();
                aes.Mode = System.Security.Cryptography.CipherMode.ECB;
                var key = new byte[16];
                Array.Copy(keys, 10000, key, 0, 16);
                aes.CreateEncryptor(key, null);
                Console.WriteLine("Calculating AES keys (dotnet)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < keys.Length; i += 16)
                {
                    Array.Copy(keys, i, key, 0, 16);
                    aes.CreateEncryptor(key, null);
                }

                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                var aes = System.Security.Cryptography.Aes.Create();
                aes.Mode = System.Security.Cryptography.CipherMode.ECB;
                var key = new byte[16];
                Array.Copy(keys, key, 16);
                var enc = aes.CreateEncryptor(key, null);
                enc.TransformBlock(blocks, 10000, 16, output, 10000);
                Console.WriteLine("Processing AES blocks (dotnet");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < blocks.Length; i += 16) enc.TransformBlock(blocks, i, 16, output, i);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                Org.BouncyCastle.Crypto.Engines.AesEngine aes = new Org.BouncyCastle.Crypto.Engines.AesEngine();
                aes.Init(true, new KeyParameter(keys, 10000, 16));
                aes.Init(true, new KeyParameter(keys, 20000, 16));
                Console.WriteLine("Calculating AES keys (bc)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < keys.Length; i += 16) aes.Init(true, new KeyParameter(keys, i, 16));
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                Org.BouncyCastle.Crypto.Engines.AesEngine aes = new Org.BouncyCastle.Crypto.Engines.AesEngine();
                aes.Init(true, new KeyParameter(keys, 12300, 16));
                aes.ProcessBlock(blocks, 10000, output, 10000);
                Console.WriteLine("Processing AES blocks (bc)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < blocks.Length; i += 16) aes.ProcessBlock(blocks, i, output, i);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                var aes = new Org.BouncyCastle.Crypto.Engines.AesLightEngine();
                aes.Init(true, new KeyParameter(keys, 10000, 16));
                aes.Init(true, new KeyParameter(keys, 20000, 16));
                Console.WriteLine("Calculating AES keys (bc light)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < keys.Length; i += 16) aes.Init(true, new KeyParameter(keys, i, 16));
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }
            Thread.Sleep(1000);
            {
                var aes = new Org.BouncyCastle.Crypto.Engines.AesLightEngine();
                aes.Init(true, new KeyParameter(keys, 12340, 16));
                aes.ProcessBlock(blocks, 10000, output, 10000);
                Console.WriteLine("Processing AES blocks (bc light)");
                sw.Reset();
                sw.Start();
                for (int i = 0; i < blocks.Length; i += 16) aes.ProcessBlock(blocks, i, output, i);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(keys.Length / 16) / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            Thread.Sleep(1000);
            {
                SymmetricRacthet sr = new SymmetricRacthet();
                var (client, server) = CreateAndInitialize();
                var kdf = new AesKdf(client.Services.AesFactory);
                sr.Initialize(rng.Generate(32));
                Console.WriteLine("Testing Symmetric Ratchet Speed");
                sr.RatchetForSending(kdf);
                sr.RatchetForSending(kdf);
                sr.RatchetForSending(kdf);
                sr.RatchetForSending(kdf);
                sw.Reset();
                sw.Start();
                int cnt = 1000000;
                for (int i = 0; i < cnt; i++) sr.RatchetForSending(kdf);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({cnt / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"It would take { (double)int.MaxValue / 2 / (cnt / sw.Elapsed.TotalSeconds) / 60:F0} minutes to do 2^32 ratchets");
            }

            Thread.Sleep(1000);
            {
                Console.WriteLine("Testing one way message send speed (small: 16 bytes)...");
                var (client, server) = CreateAndInitialize();
                var messagesToSend = Enumerable.Range(0, messageCount).Select(_ => rng.Generate(16)).ToArray();
                var messagesSent = new List<byte[]>(messageCount);
                var m1 = client.Send(new byte[16]).Message;
                var m2 = client.Send(new byte[16]).Message;
                var m3 = client.Send(new byte[16]).Message;
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) messagesSent.Add(client.Send(messagesToSend[i]).Message);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");


                Thread.Sleep(1000);
                Console.WriteLine("Testing one way message receive speed (small: 16 bytes)...");
                server.Receive(m1);
                server.Receive(m2);
                server.Receive(m3);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) server.Receive(messagesSent[i]);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");
            }

            Thread.Sleep(2000);
            {
                Console.WriteLine("Testing one way message send speed (large: 64 bytes)...");
                var (client, server) = CreateAndInitialize();
                var messagesToSend = Enumerable.Range(0, messageCount).Select(_ => rng.Generate(64)).ToArray();
                var messagesSent = new List<byte[]>(messageCount);
                var m1 = client.Send(new byte[16]).Message;
                var m2 = client.Send(new byte[16]).Message;
                var m3 = client.Send(new byte[16]).Message;
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) messagesSent.Add(client.Send(messagesToSend[i]).Message);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");


                Thread.Sleep(1000);
                Console.WriteLine("Testing one way message receive speed (large: 64 bytes)...");
                server.Receive(m1);
                server.Receive(m2);
                server.Receive(m3);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) server.Receive(messagesSent[i]);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");
            }

            messageCount /= 10;
            Thread.Sleep(2000);
            {
                Console.WriteLine("Testing one way message send speed (IP: 1350 bytes)...");
                var (client, server) = CreateAndInitialize(1350);
                var messagesToSend = Enumerable.Range(0, messageCount).Select(_ => rng.Generate(1300)).ToArray();
                var messagesSent = new List<byte[]>(messageCount);
                var m1 = client.Send(new byte[16]).Message;
                var m2 = client.Send(new byte[16]).Message;
                var m3 = client.Send(new byte[16]).Message;
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) messagesSent.Add(client.Send(messagesToSend[i]).Message);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");


                Thread.Sleep(1000);
                Console.WriteLine("Testing one way message receive speed (IP: 1350 bytes)...");
                server.Receive(m1);
                server.Receive(m2);
                server.Receive(m3);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount; i++) server.Receive(messagesSent[i]);
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({messageCount / sw.Elapsed.TotalSeconds:F0}/s)");
                Console.WriteLine($"Bandwidth: { messagesToSend.Sum(x => x.Length * 8) / sw.Elapsed.TotalSeconds / (1024 * 1024):F0} Mbps");
            }

            Thread.Sleep(1000);
            {
                Console.WriteLine("Testing ECDHratchet speed...");
                var (client, server) = CreateAndInitialize(1350);
                var messagesToSend = Enumerable.Range(0, messageCount / 4000).Select(_ => rng.Generate(32)).ToArray();
                server.Receive(client.Send(new byte[32]).Message);
                client.Receive(server.Send(new byte[32]).Message);
                sw.Reset();
                sw.Start();
                for (int i = 0; i < messageCount / 4000; i++)
                {
                    var m1 = client.Send(messagesToSend[i]).Message;
                    server.Receive(m1);
                    var m2 = server.Send(messagesToSend[i]).Message;
                    client.Receive(m2);
                }
                sw.Stop();
                Console.WriteLine($"Took {sw.Elapsed.TotalSeconds:F2}s ({(messageCount / 2000) / sw.Elapsed.TotalSeconds:F0}/s)");
            }

            messageCount *= 10;
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
                                    var message = client.Send(payload).Message;
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
                                    var message = server.Send(payload).Message;
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
                                    var payload = client.Receive(message).Payload;
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
                                    var payload = server.Receive(message).Payload;
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

        private static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize(int? mtu = null)
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var packet = client.InitiateInitialization();

            while (packet != null && !client.IsInitialized || !server.IsInitialized)
            {
                packet = server.Receive(packet.Message).ToSendBack;
                if (packet != null)
                {
                    packet = client.Receive(packet.Message).ToSendBack;
                }
            }

            if (!client.IsInitialized || !server.IsInitialized) throw new InvalidOperationException("Initialization failed");

            client.SaveState();
            server.SaveState();

            return (
                new MicroRatchetClient(clientServices, new MicroRatchetConfiguration { IsClient = true, MaximumMessageSize = mtu ?? 80 }),
                new MicroRatchetClient(serverServices, new MicroRatchetConfiguration { IsClient = false, MaximumMessageSize = mtu ?? 80 }));
        }
    }
}
