using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal static class Extensions
    {
        public static byte[] ToArray(this ArraySegment<byte> arr)
        {
            var b = new byte[arr.Count];
            Array.Copy(arr.Array, arr.Offset, b, 0, arr.Count);
            return b;
        }

        public static byte[] Send(this MicroRatchetClient mrc, byte[] payload) =>
            mrc.Send(new ArraySegment<byte>(payload));

        public static byte[] Send(this MicroRatchetClient mrc, byte[] payload, int offset, int length) =>
            mrc.Send(new ArraySegment<byte>(payload, offset, length));

        public static byte[] ComputeDigest(this IDigest digest, ArraySegment<byte> data)
        {
            digest.Reset();
            digest.Process(data);
            return digest.Compute();
        }

        public static byte[] ComputeDigest(this IDigest digest, byte[] data) =>
            digest.ComputeDigest(new ArraySegment<byte>(data));

        public static byte[] ComputeDigest(this IDigest digest, byte[] data, int offset, int length) =>
            digest.ComputeDigest(new ArraySegment<byte>(data, offset, length));

        public static bool Matches(this byte[] bytes, byte[] other)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (other == null) throw new ArgumentNullException(nameof(other));

            if (bytes.Length != other.Length) return false;
            for (int i = 0; i < bytes.Length; i++) if (bytes[i] != other[i]) return false;
            return true;
        }

        public static bool Matches(this byte[] bytes, ArraySegment<byte> other)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (other == null) throw new ArgumentNullException(nameof(other));

            if (bytes.Length != other.Count) return false;
            for (int i = 0; i < bytes.Length; i++) if (bytes[i] != other.Array[other.Offset + i]) return false;
            return true;
        }

        public static bool Matches(this byte[] bytes, byte[] other, int offset, int length) =>
            Matches(bytes, new ArraySegment<byte>(other, offset, length));

            public static bool Matches(this ArraySegment<byte> bytes, byte[] other)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (other == null) throw new ArgumentNullException(nameof(other));

            if (bytes.Count != other.Length) return false;
            for (int i = 0; i < bytes.Count; i++) if (bytes.Array[bytes.Offset + i] != other[i]) return false;
            return true;
        }

        public static bool Matches(this ArraySegment<byte> bytes, ArraySegment<byte> other)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (other == null) throw new ArgumentNullException(nameof(other));

            if (bytes.Count != other.Count) return false;
            for (int i = 0; i < bytes.Count; i++) if (bytes.Array[bytes.Offset + i] != other.Array[other.Offset + i]) return false;
            return true;
        }

        public static bool Matches(this ArraySegment<byte> bytes, byte[] other, int offset, int length) =>
            Matches(bytes, new ArraySegment<byte>(other, offset, length));

        public static void Generate(this IRandomNumberGenerator rng, byte[] data) =>
            rng.Generate(new ArraySegment<byte>(data));

        public static void Generate(this IRandomNumberGenerator rng, byte[] data, int offset, int count) =>
            rng.Generate(new ArraySegment<byte>(data, offset, count));

        public static byte[] Generate(this IRandomNumberGenerator rng, int howmuch)
        {
            byte[] data = new byte[howmuch];
            rng.Generate(data);
            return data;
        }

        public static byte[] Sign(this ISignature sig, byte[] data) =>
            sig.Sign(new ArraySegment<byte>(data));

        public static byte[] Sign(this ISignature sig, byte[] data, int offset, int length) =>
            sig.Sign(new ArraySegment<byte>(data, offset, length));

        public static bool Verify(this IVerifier sig, byte[] data, ArraySegment<byte> signature) =>
            sig.Verify(new ArraySegment<byte>(data), signature);

        public static bool Verify(this IVerifier sig, byte[] data, int offset, int count, ArraySegment<byte> signature) =>
            sig.Verify(new ArraySegment<byte>(data, offset, count), signature);

        public static bool VerifySignedMessage(this IVerifier sig, IDigest digest, byte[] message) =>
            VerifySignedMessage(sig, digest, new ArraySegment<byte>(message));

        public static bool VerifySignedMessage(this IVerifier sig, IDigest digest, byte[] message, int offset, int length) =>
            VerifySignedMessage(sig, digest, new ArraySegment<byte>(message, offset, length));

        public static bool VerifySignedMessage(this IVerifier sig, IDigest digest, ArraySegment<byte> message)
        {
            if (message.Count <= sig.SignatureSize) throw new InvalidOperationException("The message size is smaller than or equal to the size of a signature");

            var hash = digest.ComputeDigest(
                new ArraySegment<byte>(message.Array, message.Offset, message.Count - sig.SignatureSize));
            return sig.Verify(
                new ArraySegment<byte>(hash),
                new ArraySegment<byte>(message.Array, message.Offset + message.Count - sig.SignatureSize, sig.SignatureSize));
        }

        public static byte[][] GenerateKeys(this IKeyDerivation kdf, byte[] key, byte[] info, int numKeys, int keySize)
        {
            byte[] totalKeyBytes = kdf.GenerateBytes(key, info, keySize * numKeys);
            byte[][] keys = new byte[numKeys][];

            for (int i = 0; i < numKeys; i++)
            {
                keys[i] = new byte[keySize];
                Array.Copy(totalKeyBytes, i * keySize, keys[i], 0, keySize);
            }

            return keys;
        }

        public static void Init(this IMac mac, byte[] key, byte[] iv, int macSize) =>
            mac.Init(key, new ArraySegment<byte>(iv), macSize);

        public static void Init(this IMac mac, byte[] key, byte[] iv, int ivoffset, int ivlen, int macSize) =>
            mac.Init(key, new ArraySegment<byte>(iv, ivoffset, ivlen), macSize);

        public static void Process(this IMac mac, byte[] data) =>
            mac.Process(new ArraySegment<byte>(data));

        public static void Process(this IMac mac, byte[] data, int offset, int length) =>
            mac.Process(new ArraySegment<byte>(data, offset, length));

        public static IAes GetAes(this IAesFactory aes, bool forEncryption, byte[] key) =>
            aes.GetAes(forEncryption, new ArraySegment<byte>(key));

        public static void Initialize(this IAes aes, bool forEncryption, byte[] key) =>
            aes.Initialize(forEncryption, new ArraySegment<byte>(key));

        public static void Shred(this byte[] data)
        {
            for (int i = 0; i < data.Length; i++) data[i] = 0;
        }

        public static void Shred(this ArraySegment<byte> data)
        {
            for (int i = 0; i < data.Count; i++) data.Array[data.Offset + i] = 0;
        }
    }
}
