using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal static class Extensions
    {
        public static byte[] Decrypt(this ICipher cipher, byte[] data) =>
            cipher.Decrypt(new ArraySegment<byte>(data));

        public static byte[] Decrypt(this ICipher cipher, byte[] data, int offset, int count) =>
            cipher.Decrypt(new ArraySegment<byte>(data, offset, count));

        public static byte[] Encrypt(this ICipher cipher, byte[] data) =>
            cipher.Encrypt(new ArraySegment<byte>(data));

        public static byte[] Encrypt(this ICipher cipher, byte[] data, int offset, int count) =>
            cipher.Encrypt(new ArraySegment<byte>(data, offset, count));

        public static byte[] Decrypt(this IAeadCipher cipher, byte[] nonce, byte[] data, byte[] ad = null) =>
            cipher.Decrypt(nonce, new ArraySegment<byte>(data), ad);

        public static byte[] Decrypt(this IAeadCipher cipher, byte[] nonce, byte[] data, int offset, int count, byte[] ad = null) =>
            cipher.Decrypt(nonce, new ArraySegment<byte>(data, offset, count), ad);

        public static byte[] Encrypt(this IAeadCipher cipher, byte[] nonce, byte[] data, byte[] ad = null) =>
            cipher.Encrypt(nonce, new ArraySegment<byte>(data), ad);

        public static byte[] Encrypt(this IAeadCipher cipher, byte[] nonce, byte[] data, int offset, int count, byte[] ad = null) =>
            cipher.Encrypt(nonce, new ArraySegment<byte>(data, offset, count), ad);

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

        public static byte[] ComputeDigest(this IDigest digest, byte[] data) =>
            digest.ComputeDigest(new ArraySegment<byte>(data));

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

        public static bool Verify(this IVerifier sig, byte[] data, byte[] signature) =>
            sig.Verify(new ArraySegment<byte>(data), signature);

        public static bool Verify(this IVerifier sig, byte[] data, int offset, int count, byte[] signature) =>
            sig.Verify(new ArraySegment<byte>(data, offset, count), signature);

        public static bool VerifySignedMessage(this IVerifier sig, byte[] message)
        {
            if (message.Length <= sig.SignatureSize) throw new InvalidOperationException("The message size is smaller than or equal to the size of a signature");

            var signature = new byte[sig.SignatureSize];
            Array.Copy(message, message.Length - sig.SignatureSize, signature, 0, sig.SignatureSize);
            return sig.Verify(new ArraySegment<byte>(message, 0, message.Length - sig.SignatureSize), signature);
        }

        public static byte[][] GenerateKeys(this IKeyDerivation kdf, byte[] key, byte[] info, int numKeys, int keySize = 32)
        {
            int i = 0;
            return kdf.GenerateBytes(key, info, keySize * numKeys)
                .GroupBy(x => i++ / keySize)
                .Select(x => x.ToArray())
                .ToArray();
        }


        public static byte[] Obfuscate(this IKeyDerivation kd, byte[] toObfuscate, byte[] key, byte[] associatedData)
        {
            uint RotateRight(uint x, int n) => (((x) >> (n)) | ((x) << (32 - (n))));

            if (toObfuscate.Length != 4) throw new ArgumentException("Can only obfuscate a thing of length 4");
            var asInt = BigEndianBitConverter.ToUInt32(toObfuscate, 0);

            var obfuscator = kd.GenerateBytes(key, associatedData, 32);
            uint int0 = BigEndianBitConverter.ToUInt32(obfuscator, 0);
            uint int1 = BigEndianBitConverter.ToUInt32(obfuscator, 4);
            uint int2 = BigEndianBitConverter.ToUInt32(obfuscator, 8);
            uint int3 = BigEndianBitConverter.ToUInt32(obfuscator, 12);
            uint int4 = BigEndianBitConverter.ToUInt32(obfuscator, 16);
            uint int5 = BigEndianBitConverter.ToUInt32(obfuscator, 20);
            uint int6 = BigEndianBitConverter.ToUInt32(obfuscator, 24);
            uint int7 = BigEndianBitConverter.ToUInt32(obfuscator, 28);

            asInt = RotateRight(asInt, 7) ^ int0;
            asInt = RotateRight(asInt, 7) ^ int1;
            asInt = RotateRight(asInt, 7) ^ int2;
            asInt = RotateRight(asInt, 7) ^ int3;
            asInt = RotateRight(asInt, 7) ^ int4;
            asInt = RotateRight(asInt, 7) ^ int5;
            asInt = RotateRight(asInt, 7) ^ int6;
            asInt = RotateRight(asInt, 7) ^ int7;
            return BigEndianBitConverter.GetBytes(asInt);
        }

        public static byte[] UnObfuscate(this IKeyDerivation kd, byte[] toUnObfuscate, byte[] key, byte[] associatedData)
        {
            uint RotateLeft(uint x, int n) => (((x) << (n)) | ((x) >> (32 - (n))));

            if (toUnObfuscate.Length != 4) throw new ArgumentException("Can only unobfuscate a thing of length 4");
            var asInt = BigEndianBitConverter.ToUInt32(toUnObfuscate, 0);

            var obfuscator = kd.GenerateBytes(key, associatedData, 32);
            uint int0 = BigEndianBitConverter.ToUInt32(obfuscator, 0);
            uint int1 = BigEndianBitConverter.ToUInt32(obfuscator, 4);
            uint int2 = BigEndianBitConverter.ToUInt32(obfuscator, 8);
            uint int3 = BigEndianBitConverter.ToUInt32(obfuscator, 12);
            uint int4 = BigEndianBitConverter.ToUInt32(obfuscator, 16);
            uint int5 = BigEndianBitConverter.ToUInt32(obfuscator, 20);
            uint int6 = BigEndianBitConverter.ToUInt32(obfuscator, 24);
            uint int7 = BigEndianBitConverter.ToUInt32(obfuscator, 28);

            asInt = RotateLeft(asInt ^ int7, 7);
            asInt = RotateLeft(asInt ^ int6, 7);
            asInt = RotateLeft(asInt ^ int5, 7);
            asInt = RotateLeft(asInt ^ int4, 7);
            asInt = RotateLeft(asInt ^ int3, 7);
            asInt = RotateLeft(asInt ^ int2, 7);
            asInt = RotateLeft(asInt ^ int1, 7);
            asInt = RotateLeft(asInt ^ int0, 7);
            return BigEndianBitConverter.GetBytes(asInt);
        }
    }
}
