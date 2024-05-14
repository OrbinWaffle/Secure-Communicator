import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSA {
    public static void GenerateRSA()
    {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();
            System.out.println(privateKey);
            System.out.println(publicKey);
            Communicator.WriteFile("private_key", privateKey.getEncoded());
            Communicator.WriteFile("public_key", publicKey.getEncoded());
        } 
        catch (NoSuchAlgorithmException e) {
            System.err.println(e);
        }
    }
    public static void main(String[] args) {
        GenerateRSA();
    }
}
