using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal class EcdhRatchet
    {
        // the number of past ratchets to retain
        public const int RetainCount = 7;

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

            if (_steps.Count > RetainCount)
            {
                _steps.RemoveRange(0, _steps.Count - RetainCount);
            }
        }

        public IEnumerable<EcdhRatchetStep> Enumerate() =>
            _steps.Where(x => x.ReceivingChain.HeaderKey != null)
            .Reverse();

        public void Serialize(BinaryWriter bw)
        {
            bw.Write(_steps.Count);
            foreach (var e in _steps)
            {
                e.Serialize(bw);
            }
        }

        public static EcdhRatchet Deserialize(BinaryReader br)
        {
            var ratchet = new EcdhRatchet();
            int numSteps = br.ReadInt32();
            for (int i = 0; i < numSteps; i++)
            {
                ratchet._steps.Add(EcdhRatchetStep.Deserialize(br));
            }

            return ratchet;
        }
    }
}
