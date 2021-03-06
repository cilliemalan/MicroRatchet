﻿using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MicroRatchet.Examples
{
    public static class Program
    {
        const string mutexName = "6efce0f439614d43ab88588798691a5f";

        static async Task Main(string[] args)
        {
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => cts.Cancel();

            if (args.Length == 0)
            {
                using var mutex = new Mutex(true, mutexName);
                if (mutex.WaitOne(0, false))
                {
                    Console.WriteLine("No server started yet so starting server");
                    await Server.Run(cts.Token);
                }
                else
                {
                    Console.WriteLine("Server started already so starting client");
                    await Client.Run(cts.Token);
                }
            }

            await ((args[0]) switch
            {
                "server" => Server.Run(cts.Token),
                "client" => Client.Run(cts.Token)
                _ => PrintUsage(),
            });
        }

        static Task PrintUsage()
        {
            Console.WriteLine(@"

MicroRatchet examples. Usage:

    mrexamples              Starts a server or client based on whether
                            another instance is already running.
    mrexamples server       Starts a UDP server on 127.0.0.1:3422.
    mrexamples client       Starts a UDP client that will connect to
                            localhost on port 127.0.0.1:3422.
");
            return Task.CompletedTask;
        }

        #region Helper Methods

        public static Task<UdpReceiveResult> ReceiveAsync(this UdpClient c, CancellationToken cancellationToken)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var tcs = new TaskCompletionSource<UdpReceiveResult>();
            cts.Token.Register(() => tcs.TrySetCanceled());
            c.BeginReceive(ar =>
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        IPEndPoint ipep = default;
                        var data = c.EndReceive(ar, ref ipep);
                        tcs.TrySetResult(new UdpReceiveResult(data, ipep));
                    }
                    catch (OperationCanceledException)
                    {
                        tcs.TrySetCanceled();
                    }
                    catch (ObjectDisposedException)
                    {
                        tcs.TrySetCanceled();
                    }
                    catch (Exception ex)
                    {
                        tcs.TrySetException(ex);
                    }
                }
            }, null);

            return tcs.Task;
        }

        public static Task<int> SendAsync(this UdpClient c, ReadOnlySpan<byte> data, IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var tcs = new TaskCompletionSource<int>();
            cts.Token.Register(() => tcs.TrySetCanceled());
            c.BeginSend(data.ToArray(), data.Length, remoteEndPoint, ar =>
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var result = c.EndSend(ar);
                        tcs.TrySetResult(result);
                    }
                    catch (OperationCanceledException)
                    {
                        tcs.TrySetCanceled();
                    }
                    catch (ObjectDisposedException)
                    {
                        tcs.TrySetCanceled();
                    }
                    catch (Exception ex)
                    {
                        tcs.TrySetException(ex);
                    }
                }
            }, null);

            return tcs.Task;
        }

        private static readonly uint[] _lookup32 = CreateLookup32();

        private static uint[] CreateLookup32()
        {
            var result = new uint[256];
            for (int i = 0; i < 256; i++)
            {
                string s = i.ToString("X2", CultureInfo.InvariantCulture);
                result[i] = (s[0]) + ((uint)s[1] << 16);
            }
            return result;
        }

        internal static string ToHexString(this byte[] bytes) =>
            ToHexString(bytespan: bytes);

        internal static string ToHexString(this ReadOnlySpan<byte> bytespan)
        {
            var lookup32 = _lookup32;
            Span<char> result = stackalloc char[bytespan.Length * 2];
            for (int i = 0; i < bytespan.Length; i++)
            {
                var val = lookup32[bytespan[i]];
                result[2 * i] = (char)val;
                result[2 * i + 1] = (char)(val >> 16);
            }
            return new string(result);
        }

        internal static string DecodeNullTerminatedString(this byte[] payload) =>
            DecodeNullTerminatedString(bytespan: payload);

        internal static string DecodeNullTerminatedString(this ReadOnlySpan<byte> bytespan)
        {
            for (int i = 1; i < bytespan.Length; i++)
            {
                if (bytespan[i] == 0)
                {
                    return Encoding.UTF8.GetString(bytespan.Slice(0, i));
                }
            }

            return Encoding.UTF8.GetString(bytespan);
        }

        #endregion
    }
}
