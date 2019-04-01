using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal static class Extensions
    {
        public static byte[] ComputeDigest(this IDigest digest, ArraySegment<byte> data)
        {
            digest.Reset();
            digest.Process(data);
            return digest.Compute();
        }

        public static byte[] ComputeDigest(this IDigest digest, byte[] data) =>
            digest.ComputeDigest(new ArraySegment<byte>(data));

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

        public static bool VerifySignedMessage(this IVerifier sig, IDigest digest, ArraySegment<byte> message)
        {
            if (message.Count <= sig.SignatureSize) throw new InvalidOperationException("The message size is smaller than or equal to the size of a signature");

            var hash = digest.ComputeDigest(
                new ArraySegment<byte>(message.Array, message.Offset, message.Count - sig.SignatureSize));
            return sig.Verify(
                new ArraySegment<byte>(hash),
                new ArraySegment<byte>(message.Array, message.Offset + message.Count - sig.SignatureSize, sig.SignatureSize));
        }

        public static byte[][] GenerateKeys(this IKeyDerivation kdf, ArraySegment<byte> key, ArraySegment<byte> info, int numKeys, int keySize)
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
    }
}
