using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface INonceCache
    {
        /// <summary>
        /// Adds a nonce to the cache. Returns true if the nonce
        /// was added. Returns false if the nonce was already present.
        /// </summary>
        bool CheckNonce(ArraySegment<byte> nonce);
    }
}
