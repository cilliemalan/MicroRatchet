using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal class MultipartMessageReconstructor
    {
        private int _maximumDataStored;
        private int _timeout;
        private int _mtu;
        private int _ctr = 0;
        Dictionary<int, (int ctr, int total)> _messages = new Dictionary<int, (int ctr, int total)>();
        Dictionary<(int seq, int num), byte[]> _payloads = new Dictionary<(int seq, int num), byte[]>();

        public MultipartMessageReconstructor(int payloadMtu, int maximumDataStored = 1024, int timeout = 20)
        {
            _maximumDataStored = maximumDataStored;
            _timeout = timeout;
            _mtu = payloadMtu;
        }

        public byte[] Ingest(byte[] partialPayload, int seq, int num, int total)
        {
            if (!_messages.TryGetValue(seq, out var msg))
            {
                int totalMessageSize = _mtu * total;
                if (totalMessageSize > _maximumDataStored)
                {
                    throw new InvalidOperationException("No space for a message this big");
                }

                // make sure there is enouogh space
                int totalSpaceReserved = _messages.Sum(x => x.Value.total);
                int currentSpaceAvail = _maximumDataStored - totalSpaceReserved;

                if (currentSpaceAvail < totalMessageSize)
                {
                    // free up space by deleting oldest messages first
                    int minimumToRemove = totalMessageSize - currentSpaceAvail;

                    // remove until
                    int totalSizeLeft = _maximumDataStored - totalMessageSize;
                    int totalSizeRemoved = 0;
                    var toDeleteMsg = _messages.OrderByDescending(x => x.Value.ctr)
                        .TakeWhile(_m =>
                        {
                            if (totalSizeRemoved > minimumToRemove)
                            {
                                return false;
                            }
                            else
                            {
                                totalSizeRemoved += _m.Value.total;
                                return true;
                            }
                        }).Select(x => x.Key).ToArray();
                    var toDeletePay = _payloads.Where(x => toDeleteMsg.Contains(x.Key.seq)).Select(x => x.Key).ToArray();
                    foreach (var d in toDeleteMsg) _messages.Remove(d);
                    foreach (var d in toDeletePay) _payloads.Remove(d);
                }

                _messages[seq] = msg = (_ctr, total);
            }

            var key = (seq, num);
            if (!_payloads.ContainsKey(key))
            {
                _payloads[key] = partialPayload;

                var haveAllPayloads = _payloads.Count(x => x.Key.seq == seq) == msg.total;
                if (haveAllPayloads)
                {
                    var currentPayloads = _payloads.Where(x => x.Key.seq == seq)
                        .OrderBy(x => x.Key.num)
                        .ToArray();
                    var totalSize = currentPayloads.Sum(x => x.Value.Length);
                    byte[] totalPayload = new byte[totalSize];
                    int amt = 0;

                    foreach (var p in currentPayloads)
                    {
                        Array.Copy(p.Value, 0, totalPayload, amt, p.Value.Length);
                        amt += p.Value.Length;
                        _payloads.Remove(p.Key);
                    }

                    _messages.Remove(seq);

                    return totalPayload;
                }
            }

            return null;
        }

        public void Tick()
        {
            _ctr++;

            int minCtr = _ctr - _timeout;
            var toDeleteMsg = _messages.Where(x => x.Value.ctr < minCtr).Select(x => x.Key).ToArray();
            var toDeletePay = _payloads.Where(x => toDeleteMsg.Contains(x.Key.seq)).Select(x => x.Key).ToArray();
            foreach (var d in toDeleteMsg) _messages.Remove(d);
            foreach (var d in toDeletePay) _payloads.Remove(d);
        }
    }
}
