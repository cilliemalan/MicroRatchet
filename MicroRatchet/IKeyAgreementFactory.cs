using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IKeyAgreementFactory
    {
        IKeyAgreement GenerateNew();
        IKeyAgreement Deserialize(byte[] data);
    }
}
