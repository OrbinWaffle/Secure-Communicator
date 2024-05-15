import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MAC {
   public static byte[] GenerateMAC(byte[] msg, byte[] key)
   {  
      try {
         //Creating a Mac object
         Mac mac = Mac.getInstance("HmacSHA256");
   
         //Initializing the Mac object
         mac.init(new SecretKeySpec(key, "PBKDF2WithHmacSHA256"));
         byte[] macResult = mac.doFinal(msg);
         return macResult;
      } catch (Exception e) {
         System.err.println(e);
         return null;
      }
   }
   public static boolean VerifyMAC(byte[] msg, byte[] key, byte[] mac)
   {
      byte[] msgMAC = GenerateMAC(msg, key);
      if(!Arrays.equals(msgMAC, mac)){
         // System.out.println(new String(msgMAC));
         // System.out.println(new String(mac));
         return false;
      }
      System.out.println("Message authenticated.");
      return true;
   }
   public static void main(String args[]) throws Exception{ 
   }
}