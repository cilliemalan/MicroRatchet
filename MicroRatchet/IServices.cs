using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IServices
    {
        IDigest Digest { get; }
        ISignature Signature { get; }
        IRandomNumberGenerator RandomNumberGenerator { get; }
        ISecureStorage SecureStorage { get; }
        IKeyAgreementFactory KeyAgreementFactory { get; }
        ICipherFactory CipherFactory { get; }
        IVerifierFactory VerifierFactory { get; }
    }
}
