using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    /// <summary>
    /// The ECDH key ratcheting process.
    /// </summary>
    internal class EcdhRatchet
    {
        private List<EcdhRatchetStep> _steps = new List<EcdhRatchetStep>();

        public EcdhRatchetStep this[int index] => _steps[index];
        public int Count => _steps.Count;
        public bool IsEmpty => _steps.Count == 0;
        public EcdhRatchetStep Last => _steps.LastOrDefault();
        public EcdhRatchetStep SecondToLast
        {
            get
            {
                if (_steps.Count == 0) return null;
                else if (_steps.Count == 1) return _steps[0];
                else return _steps[_steps.Count - 2];
            }
        }

        public void Add(params EcdhRatchetStep[] steps)
        {
            _steps.AddRange(steps);

            if (_steps.Count > 2)
            {
                // the third-to-last step and older will never again be used for sending
                var oldstep = _steps[_steps.Count - 3];
                oldstep.SendingChain.Reset();
                oldstep.NextSendHeaderKey = null;
                oldstep.SendHeaderKey = null;
            }
        }

        public void Trim(int maxSteps, int trimTo)
        {
            if (_steps.Count > maxSteps)
            {
                int cnt = _steps.Count - trimTo;
                for (int i = 0; i < cnt; i++)
                {
                    ShredRatchet(_steps[i]);
                }

                _steps.RemoveRange(0, _steps.Count - trimTo);
            }
        }

        public void Clear()
        {
            for (int i = 0; i < _steps.Count; i++)
            {
                ShredRatchet(_steps[i]);
            }
            _steps.Clear();
        }

        private static void ShredRatchet(EcdhRatchetStep r)
        {
            (r.EcdhKey as IDisposable)?.Dispose();
            r.EcdhKey = null;
            r.NextReceiveHeaderKey?.Shred();
            r.NextReceiveHeaderKey = null;
            r.NextRootKey?.Shred();
            r.NextRootKey = null;
            r.NextSendHeaderKey?.Shred();
            r.NextSendHeaderKey = null;
            r.ReceiveHeaderKey?.Shred();
            r.ReceiveHeaderKey = null;
            r.SendHeaderKey?.Shred();
            r.SendHeaderKey = null;
            r.ReceivingChain.ChainKey?.Shred();
            r.ReceivingChain.ChainKey = null;
            r.ReceivingChain.OldChainKey?.Shred();
            r.ReceivingChain.OldChainKey = null;
            r.SendingChain.ChainKey?.Shred();
            r.SendingChain.ChainKey = null;
            r.SendingChain.OldChainKey?.Shred();
            r.SendingChain.OldChainKey = null;
        }

        public IEnumerable<EcdhRatchetStep> Enumerate() =>
            _steps.Where(x => x.ReceiveHeaderKey != null)
            .Reverse();

        public IEnumerable<EcdhRatchetStep> AsEnumerable() => _steps.AsEnumerable();
    }
}
