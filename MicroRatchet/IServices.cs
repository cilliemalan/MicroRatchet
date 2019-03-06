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
        IStorageProvider Storage { get; }
        IKeyAgreementFactory KeyAgreementFactory { get; }
        ICipher Cipher { get; }
        IVerifierFactory VerifierFactory { get; }
        IMac Mac { get; }
    }
}
