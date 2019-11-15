using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
#pragma warning disable CA1810 // Initialize reference type static fields inline

namespace MicroRatchet.BouncyCastle
{
    /// <summary>
    /// ECDH key agreement using secp256r1/NIST P-256
    /// </summary>
    public sealed class KeyAgreement : IDisposable, IKeyAgreement
    {
        private static readonly ECDomainParameters domainParms;
        private static readonly Func<int, BigInteger, ECPoint> _decompress;
        private byte[] _privateKey;
        private byte[] _publicKey;
        private ECPrivateKeyParameters _pk;
        private Sha256Digest _sha = new Sha256Digest();

        public int Id { get; }

        static KeyAgreement()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            domainParms = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var m = domainParms.Curve.GetType().GetMethod("DecompressPoint", BindingFlags.NonPublic | BindingFlags.Instance);
            _decompress = (i, b) => (ECPoint)m.Invoke(domainParms.Curve, new object[] { i, b });
        }

        public KeyAgreement(byte[] privateKey, ArraySegment<byte> publicKey = default)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != 32) throw new ArgumentException("private key is strictly 32 bytes long");
            _privateKey = privateKey.ToArray();
            var pkn = new BigInteger(privateKey);
            _pk = new ECPrivateKeyParameters(pkn, domainParms);
            _publicKey = publicKey.Array != null ? publicKey.ToArray() : null;
        }

        public byte[] DeriveKey(ArraySegment<byte> otherPublicKey)
        {
            if (_pk == null) throw new ObjectDisposedException(nameof(KeyAgreement));

            if (otherPublicKey == null) throw new ArgumentNullException(nameof(otherPublicKey));
            if (otherPublicKey.Count != 32) throw new ArgumentException("The other public key needs to be compressed with the first byte omitted. Only even public keys are accepted");

            var pubk = DecodePublicKey(otherPublicKey);

            var ecdh = new ECDHBasicAgreement();
            ecdh.Init(_pk);
            var key = ecdh.CalculateAgreement(pubk);
            var keyBytes = key.ToByteArray();

            if (keyBytes.Length != 32)
            {
                byte[] output = new byte[32];
                int l = keyBytes.Length;
                int o = Math.Max(0, l - 32);
                int t = Math.Min(32, l);
                int w = 32 - t;
                Array.Copy(keyBytes, o, output, w, t);
                keyBytes = output;
            }

            return keyBytes;
        }

        private static ECPublicKeyParameters DecodePublicKey(ArraySegment<byte> pub)
        {
            if (pub.Count != 32) throw new ArgumentException("The public key needs to be compressed with the first byte omitted. The length must be 32.");
            var X = new BigInteger(1, pub.Array, pub.Offset, pub.Count);
            var p = _decompress(0, X);
            if (!p.IsValid()) throw new ArgumentException("Invalid point");
            return new ECPublicKeyParameters(p, domainParms);
        }

        public void Dispose()
        {
            _sha?.Reset();
            _sha = null;

            if (_pk != null)
            {
                var tbigint = typeof(BigInteger);
                var tPriv = typeof(ECPrivateKeyParameters);
                var tints = typeof(int[]);
                var tint = typeof(int);
                foreach (var f in tPriv.GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
                    .Where(x => x.FieldType == tbigint))
                {
                    BigInteger v = (BigInteger)f.GetValue(_pk);
                    f.SetValue(_pk, BigInteger.Zero);

                    foreach (var g in tbigint.GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
                    {
                        if (g.FieldType == tint)
                        {
                            g.SetValue(v, 0);
                        }
                        else if (g.FieldType == tints)
                        {
                            Array bytes = (Array)g.GetValue(v);
                            Array.Clear(bytes, 0, bytes.Length);
                        }
                    }
                }

                _pk = null;
            }
        }

        public byte[] GetPublicKey()
        {
            if (_publicKey == null)
            {
                _publicKey = KeyGeneration.GetPublicKeyFromPrivateKey(_pk);
            }

            return _publicKey;
        }

        public void Serialize(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            if (_privateKey.Length != 32) throw new InvalidOperationException("Private key must be 32 bytes");
            stream.Write(_privateKey, 0, 32);
        }

        public static KeyAgreement Deserialize(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            byte[] pri = new byte[32];
            stream.Read(pri, 0, 32);
            return new KeyAgreement(pri);
        }
    }
}
