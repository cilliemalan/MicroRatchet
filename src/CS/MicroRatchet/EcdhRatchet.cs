using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
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
            }
        }

        public void Trim(int maxSteps, int trimTo)
        {
            if(_steps.Count > maxSteps)
            {
                _steps.RemoveRange(0, _steps.Count - trimTo);
            }
        }

        public void Clear() => _steps.Clear();

        public IEnumerable<EcdhRatchetStep> Enumerate() =>
            _steps.Where(x => x.ReceivingChain.HeaderKey != null)
            .Reverse();

        public IEnumerable<EcdhRatchetStep> AsEnumerable() => _steps.AsEnumerable();
    }
}
