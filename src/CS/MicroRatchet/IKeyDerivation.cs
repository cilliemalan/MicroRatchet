namespace MicroRatchet
{
    public interface IKeyDerivation
    {
        byte[] GenerateBytes(byte[] key, byte[] info, int howManyBytes);
    }
}