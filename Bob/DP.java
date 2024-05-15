import java.io.Serializable;

public class DP implements Serializable{
	byte[] m;
	byte[] k;
	byte[] a;
	public DP(byte[] message, byte[] encryptedAESKey, byte[] MAC)
	{
		this.m = message;
		this.k = encryptedAESKey;
		this.a = MAC;
	}
    public byte[] GetMessage()
    {
        return m;
    }
    public byte[] GetAES()
    {
        return k;
    }
    public byte[] GetMAC()
    {
        return a;
    }
}