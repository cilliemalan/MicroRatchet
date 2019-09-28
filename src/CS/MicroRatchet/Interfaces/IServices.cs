using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IServices
    {
        /// <summary>
        /// SHA256 hash
        /// </summary>
        IDigest Digest { get; }

        /// <summary>
        /// AES
        /// </summary>
        IAesFactory AesFactory { get; }

        /// <summary>
        /// ECDSA with unique private key
        /// </summary>
        ISignature Signature { get; }

        /// <summary>
        /// Random number generator for initialization
        /// </summary>
        IRandomNumberGenerator RandomNumberGenerator { get; }

        /// <summary>
        /// Storage for state
        /// </summary>
        IStorageProvider Storage { get; }

        /// <summary>
        /// ECDH for key exchange
        /// </summary>
        IKeyAgreementFactory KeyAgreementFactory { get; }

        /// <summary>
        /// Verifier that can verify signatures
        /// </summary>
        IVerifierFactory VerifierFactory { get; }
    }
}
