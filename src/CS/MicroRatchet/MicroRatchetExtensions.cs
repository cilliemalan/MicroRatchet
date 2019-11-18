using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    public static class MicroRatchetExtensions
    {
        public static byte[] SaveStateAsByteArray(this MicroRatchetClient mr)
        {
            if (mr == null) throw new ArgumentNullException(nameof(mr));

            using var ms = new MemoryStream();
            mr.SaveState(ms);
            return ms.ToArray();
        }

        internal static byte[] StoreAsByteArray(this State s, int numRatchetsToStore)
        {
            using var ms = new MemoryStream();
            s.Store(ms, numRatchetsToStore);
            return ms.ToArray();
        }
    }
}
