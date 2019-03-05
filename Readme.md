# Micro Ratchet
Micro Ratchet is a secure messaging protocol for embedded environments based
on [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).
Micro Ratchet doesn't require retransmission of dropped packets, doesn't wait
for out-of-order packets, and can operate with an overhead as low as 16 bytes
per message. Micro Ratchet provides strong message confidentiality, authentication,
and forward secrecy.

### Forward Secrecy Note
Forward secrecy is facilitated by periodically exchanging new ECDH keys. These
keys are automatically included if one can fit in the message. This means
that applications that always have big payloads should periodically send a
smaller (or empty) message to allow for ECDH key exchange. Servers that don't
typically communicate with devices should periodically send a message, if solely
to facilitate a key exchange.

# License
See [LICENSE](LICENSE)
