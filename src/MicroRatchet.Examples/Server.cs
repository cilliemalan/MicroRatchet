using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
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
            // generate a key pair
            byte[] privateKey = KeyGeneration.GeneratePrivateKey();
            byte[] publicKey = KeyGeneration.GetPublicKeyFromPrivateKey(privateKey);

            // configuring as a server with the default application key.
            // messages will be padded to 64 bytes and cannot exceed
            // 256 bytes.
            var config = new MicroRatchetConfiguration
            {
                ApplicationKey = new byte[32],
                IsClient = false,
                MaximumMessageSize = 256,
                MinimumMessageSize = 64
            };

            // create the MicroRatchet context
            var services = new BouncyCastleServices(privateKey);
            using var context = new MicroRatchetContext(services, config, null);

            Console.WriteLine($"Starting Server with public key: {publicKey.ToHexString()}");

            // Create UDP client. For the server we set
            // the local endpoint to be localhost,
            // listening on the configured port.
            var serverEndpoint = new IPEndPoint(IPAddress.Loopback, PORT);
            IPEndPoint clientEndpoint = null;
            using var udp = new UdpClient(serverEndpoint);

            if (!cancellationToken.IsCancellationRequested)
            {
                // in order to get the console, udp stuff, and MR stuff to work
                // together (even though nothing was written for async), we need
                // some synchronization.
                // A background thread reads from the console and pushes messages
                // into a queue which then in turn get sent to the server by the
                // Send task.
                // A receive task handles messages from the server


                // The receive task handles incoming UDP messages.
                var messages = new ConcurrentQueue<string>();
                var semaphore = new SemaphoreSlim(0);
                async Task ReceiveTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var received = await udp.ReceiveAsync(cancellationToken);
                        Console.WriteLine($"RECEIVED {received.Buffer.Length} bytes");

                        try
                        {
                            // pass the received data to the MR context
                            var message = context.Receive(received.Buffer);

                            // if ToSendBack is not null, the context has accepted
                            // an incoming initialization message and now is bound
                            // to the session from that client key.
                            if (message.ToSendBack != null)
                            {
                                // send the response back
                                await udp.SendAsync(message.ToSendBack, message.ToSendBack.Length, received.RemoteEndPoint);
                                Console.WriteLine($"SENT {message.ToSendBack.Length} bytes RESPONSE");

                                if (context.IsInitialized)
                                {
                                    // message.ToSendBack != null && context.IsInitialized
                                    // typically happens once per session.
                                    clientEndpoint = received.RemoteEndPoint;
                                    Console.WriteLine($"Server initialized with remote public key {context.GetRemotePublicKey().ToHexString()}.");
                                    Console.WriteLine("Type stuff in and press enter to send to the client.\n\n");
                                }
                            }
                            else if (message.Payload != null)
                            {
                                // if a payload is given, the message contains
                                // data sent by the client, which we print to the console.

                                // The message is always padded to the minimum message size, 
                                // so read the incoming message as a null-terminated
                                // string.
                                string msg = message.Payload.DecodeNullTerminatedString();

                                // Print the decrypted and decoded message to the console
                                Console.WriteLine($"RECEIVED MESSAGE: {msg}");
                            }
                        }
                        catch (Exception ex)
                        {
                            // one exception you would see in this situation is if second client
                            // tries to initialize a session. Because the context is bound to a remote
                            // public key as soon as a message comes in, and this demo application
                            // contains no logic to handle that situation, it will simply stay bound
                            // to the first session and throw an exception if another client tries to
                            // connect.
                            Console.WriteLine($"An exception was encountered when receiving a message: {ex}");
                        }
                    }
                }

                // the send task dequeues messages, encrypts, and sends
                // them to the server endpoint as UDP messages.
                async Task SendTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        // wait for a message
                        await semaphore.WaitAsync();
                        messages.TryDequeue(out var payload);

                        // encrypt the message using the context. The message
                        // will be padded to the minimum configured message size.
                        var payloadBytes = Encoding.UTF8.GetBytes(payload);
                        var message = context.Send(payloadBytes);

                        // send as UDP message to the server endpoint.
                        await udp.SendAsync(message, clientEndpoint, cancellationToken);
                        Console.WriteLine($"SENT {payloadBytes.Length} bytes PAYLOAD, resulting in {message.Length} bytes ENCRYPTED MESSAGE");
                    }
                }

                // The console thread reades lines one at a time and
                // enqueues them for sending.
                var consoleReadThread = new Thread(_ =>
                {
                    for (; ; )
                    {
                        string line = Console.ReadLine();
                        if (clientEndpoint != null)
                        {
                            messages.Enqueue(line);
                            semaphore.Release();
                        }
                        else
                        {
                            Console.WriteLine("Cannot send message as no client has initialized a session");
                        }
                    }
                });
                // background threads are terminated when the program exits
                consoleReadThread.IsBackground = true;
                consoleReadThread.Start();

                await Task.WhenAll(ReceiveTask(), SendTask());
            }
        }
    }
}
