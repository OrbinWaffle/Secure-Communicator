import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.KeyStore;

public class RSA {
    public static void GenerateKeys()
    {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();
            // System.out.println(privateKey);
            // System.out.println(publicKey);
		    String name = Paths.get("").toAbsolutePath().getFileName().toString();
            //System.out.println(name);
            StoreKeys(publicKey, privateKey, name);
        } 
        catch (NoSuchAlgorithmException e) {
            System.err.println(e);
        }
    }
    public static void StoreKeys(PublicKey publicKey, PrivateKey privateKey, String name)
    {
        try {
		    Path currentRelativePath = Paths.get("");
            String parent = currentRelativePath.toAbsolutePath().getParent().toString();
            FileOutputStream fosPub = new FileOutputStream(parent + "/Public Keys/" + name.toUpperCase() + "_public.key");
            fosPub.write(publicKey.getEncoded());
            FileOutputStream fosPri = new FileOutputStream("private.key");
            fosPri.write(privateKey.getEncoded());
        }
        catch (IOException e) {
            System.err.println(e);
        }
    }
    public static PublicKey readPublicKey(String name)
    {
        try {
            Path currentRelativePath = Paths.get("");
            String parent = currentRelativePath.toAbsolutePath().getParent().toString();
            File publicKeyFile = new File(parent + "/Public Keys/" + name.toUpperCase() + "_public.key");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println(e);
            return null;
        }
        catch (IOException e) {
            System.err.println(e);
            return null;
        }
        catch (InvalidKeySpecException e) {
            System.err.println(e);
            return null;
        }
    }public static PrivateKey readPrivateKey()
    {
        try {
            File privateKeyFile = new File("private.key");
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return keyFactory.generatePrivate(publicKeySpec);
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println(e);
            return null;
        }
        catch (IOException e) {
            System.err.println(e);
            return null;
        }
        catch (InvalidKeySpecException e) {
            System.err.println(e);
            return null;
        }
    }
    public static byte[] Encrypt(byte[] msg, PublicKey publicKey)
    {
        try {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(msg); 
            return encryptedMessageBytes;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e);
            return null;
        }
        catch (NoSuchPaddingException e) {
            System.out.println(e);
            return null;
        }
        catch (InvalidKeyException e) {
            System.out.println(e);
            return null;
        }
        catch (IllegalBlockSizeException e) {
            System.out.println(e);
            return null;
        }
        catch (BadPaddingException e) {
            System.out.println(e);
            return null;
        }
    }
    public static byte[] Decrypt(byte[] msg, PrivateKey privateKey)
    {
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessageBytes = decryptCipher.doFinal(msg);
            return decryptedMessageBytes;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e);
            return null;
        }
        catch (NoSuchPaddingException e) {
            System.out.println(e);
            return null;
        }
        catch (InvalidKeyException e) {
            System.out.println(e);
            return null;
        }
        catch (IllegalBlockSizeException e) {
            System.out.println(e);
            return null;
        }
        catch (BadPaddingException e) {
            System.out.println("Cannot read message.");
            //e.printStackTrace();
            System.exit(0);
            System.out.println(e);
            return null;
        }
    }
    public static void main(String[] args) {
        GenerateKeys();
    }
}
