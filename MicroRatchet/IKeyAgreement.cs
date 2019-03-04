namespace MicroRatchet
{
    public interface IKeyAgreement
    {
        int Id { get; }
        int PublicKeySize { get; }
        int PrivateKeySize { get; }
        byte[] DeriveKey(byte[] otherPublicKey);
        byte[] GetPublicKey();
        byte[] Serialize();
    }
}