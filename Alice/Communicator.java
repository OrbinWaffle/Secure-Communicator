// Java program to calculate SHA hash value

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import javax.sound.midi.SysexMessage;
import javax.xml.crypto.Data;

public class Communicator {
    
	// Hashes bytes
	public static byte[] shaHash(byte[] input, String algo)
	{
		try {
			MessageDigest md = MessageDigest.getInstance(algo);

			byte[] messageDigest = md.digest(input);

			return messageDigest;
		}

		catch (NoSuchAlgorithmException e) {
			System.out.printf("Algorithm \"%s\" not regonized.", algo);
			return null;
		}
	}
    // Converts a byte array to a hex string
	public static String BytesToHex(byte[] bytes) {

		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();

	}
	
	public static String BytesToString(byte[] bytes) {

		String result = new String(bytes);
		return result;

	}

    // Returns true if the input is in the validStrings. False otherwise.
	public static boolean VerifyInput(String input, String[] validStrings) {
		List validList = Arrays.asList(validStrings);
		if(validList.contains(input)) {
			return true;
		}
		return false;
	}

    // Reads a file into a byte array
	public static byte[] ReadFile(String filename) {
		try {
			Path path = Paths.get(filename);
			if (Files.exists(path)) {
				byte[] data = Files.readAllBytes(path);
				return data;
			}
			else {
				throw new FileNotFoundException();
			}
		}
		catch (FileNotFoundException e)  {
			System.out.printf("Could not find file \"%s\"\n", filename);
			return null;
		}
		catch (IOException e) {
			System.out.println(e);
			return null;
		}
	}
    
    // Writes a byte array into a file
	public static boolean WriteFile(String filename, byte[] bytes) {
		try {
			Path path = Paths.get(filename);
			if (Files.exists(path)) {
				Files.write(path, bytes);
				return true;
			}
			else {
				File newFile = new File(filename);
				newFile.createNewFile();
				Files.write(path, bytes);
				//throw new FileNotFoundException();
				return true;
			}
		}
		catch (FileNotFoundException e)  {
			System.out.printf("Could not find file \"%s\"\n", filename);
			return false;
		}
		catch (IOException e) {
			System.out.println(e);
			return false;
		}
	}
	public static byte[] objToByte(DP dataPacket)
	{
		try {
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			ObjectOutputStream objStream = new ObjectOutputStream(byteStream);
			objStream.writeObject(dataPacket);
	
			return byteStream.toByteArray();
		} catch (Exception e) {
			System.err.println(e);
			return null;
		}
	}

	public static DP byteToObj(byte[] bytes)
	{
		try {
			ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
			ObjectInputStream objStream = new ObjectInputStream(byteStream);
	
			return (DP)objStream.readObject();
		} catch (Exception e) {
			System.err.println(e);
			return null;
		}
	}

	public static void SendMessage(String recipient)
	{
		Path currentRelativePath = Paths.get("");
		String parent = currentRelativePath.toAbsolutePath().getParent().toString();
		//String s = currentRelativePath.toAbsolutePath().toString();
		//System.out.println(s);
        byte[] data = ReadFile("outbox.txt");
		byte[] aesKey = AES256.GenerateKey();

		PublicKey recipeintPublicKey = RSA.readPublicKey(recipient);

		byte[] encryptedData = AES256.encrypt(data, aesKey);

		byte[] encryptedKey = RSA.Encrypt(aesKey, recipeintPublicKey);

		DP packet = new DP(encryptedData, encryptedKey, encryptedKey);

		byte[] packetBytes = objToByte(packet);
		System.out.println(packetBytes);
		//System.out.print(parent);
		WriteFile(parent + "/public_channel", packetBytes);
		System.out.println("Output written to public channel.");
	}
	public static void ReceiveMessage()
	{
		Path currentRelativePath = Paths.get("");
		String parent = currentRelativePath.toAbsolutePath().getParent().toString();
        byte[] packetBytes = ReadFile(parent + "/public_channel");

		DP dataPacket = byteToObj(packetBytes);

		byte[] encryptedData = dataPacket.GetMessage();
		byte[] encryptedAESKey = dataPacket.GetAES();
		byte[] MAC = dataPacket.GetMAC();

		PrivateKey myKey = RSA.readPrivateKey();
		byte[] decryptedAESKey = RSA.Decrypt(encryptedAESKey, myKey);

		byte[] decryptedData = AES256.decrypt(encryptedData, decryptedAESKey);

		WriteFile("inbox.txt", decryptedData);
		System.out.println("Incoming message written to \"inbox.txt\".");
	}

	public static void GenerateKeys()
	{
		RSA.GenerateKeys();
		System.out.println("Keys generated.");
	}

	// Driver code
	public static void main(String args[]) throws NoSuchAlgorithmException
	{
		String command = args[0];
		switch (command) {
			case "send":			
				String receiver = args[1];
				SendMessage(receiver);
				break;
			case "receive":
				ReceiveMessage();
				break;
			case "generate":
				GenerateKeys();
				break;
			default:
				break;
		}
	}
}