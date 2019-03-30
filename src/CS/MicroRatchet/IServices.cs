using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IServices
    {
        IDigest Digest { get; }
        IAesFactory AesFactory { get; }
        ISignature Signature { get; }
        IRandomNumberGenerator RandomNumberGenerator { get; }
        IStorageProvider Storage { get; }
        IKeyAgreementFactory KeyAgreementFactory { get; }
        IVerifierFactory VerifierFactory { get; }
        IMac Mac { get; }
    }
}
