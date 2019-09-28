using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    public interface IKeyAgreementFactory
    {
        int PublicKeySize { get; }
        IKeyAgreement GenerateNew();
        IKeyAgreement Deserialize(Stream stream);
    }
}
