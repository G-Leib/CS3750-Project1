import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.nio.ByteBuffer;
import java.nio.file.*;

public class Receiver {

    private static int BUFFER_SIZE = 32 * 1024;
    public static String symmetricKey;
    public static byte[] symmetricBytes;
    public static PublicKey XpubKey;
    //public static String decMsg;
    public static byte[] digSig;


    public static void main(String[] args) throws Exception {
        // Step 1:
        // Copy X Public key and symmetric key into Receiver folder (Done)

        // Step 2:
        // Read X Public key and symmetric key
        XpubKey = readPubKeyFromFile("XPublic.key");
        symmetricKey = keyToUTF8("symmetric.key");

        // Step 3:
        // Get output file name from user
        Scanner scan = new Scanner(System.in);    
        String messageFile;
        System.out.println("Input the name of the message file: ");
        messageFile = scan.nextLine();

        // Step 4:
        // Read file and decrypt using symmetric key and AES decryption
        byte[] decPlaintextBytes = aesDecrypt("message.aescipher");
        
        // Step 5:
        // Parse digital signature and message from decrypted file
        // Save message to user specified message file
        parseDecryptedMsg("message.ds-msg", messageFile);

    }

    static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
            --i;
        return Arrays.copyOf(bytes, i );
    }

    public static String keyToUTF8(String fileName) throws IOException {
        System.out.println("Symmetric.key string for AES En(): ");
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
            symmetricKey = sb.toString();
            System.out.print(symmetricKey);
            return sb.toString();
        } finally {
            br.close();
            System.out.println("128-bit UTF-8 encoding of Symmetric.key for AES: ");
            symmetricBytes = symmetricKey.getBytes("UTF-8");
            symmetricBytes = trim(symmetricBytes);
            for (byte x: symmetricBytes) {
                System.out.print(x + " ");
            }
            System.out.println("\n");
        }
    }

    public static byte[] aesDecrypt(String encryptedFile) throws Exception {
        // Reading file as bytes
        byte[] cipherBytes = stringToByteArray(encryptedFile);
        System.out.println("file: " + cipherBytes);
        byte[] iv = new byte[16];
        String IV = "AAAAAAAAAAAAAAAA"; // do not need for AES/ECB/PKCS5Padding mode
        //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));
        PrintWriter ds_out = new PrintWriter("message.ds-msg");
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        //System.out.println(cipherText);
        System.out.print("cipherBytes:  \n");
        for (int i = 0, j = 0; i < cipherBytes.length; i++, j++) {
            System.out.format("%02X ", cipherBytes[i]);
            //ds_out.format("%02X ", cipherBytes[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

        System.out.println("\nDecrypted bytes: " + plainBytes);
        for (int i = 0, j = 0; i < plainBytes.length; i++, j++) {
            System.out.format("%02X ", plainBytes[i]);
            ds_out.format("%02X ", plainBytes[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

        ds_out.close();
        return plainBytes;
    }

    public static void parseDecryptedMsg(String dsMsgFname, String fOutName) throws IOException {
        int dsSize = 128 * 3;
        byte[] decBytes = stringToByteArray(dsMsgFname);
        byte[] digSig[] = Arrays.copyOfRange(decBytes, 0, dsSize);
        String dsString = new String(decDS);
        byte[] decMsgBytes = Arrays.copyOfRange(decBytes, dsSize, decBytes.length);
        String decMsg = new String(decMsgBytes);

        System.out.println("Dec text: " + decBytes.toString());
        System.out.println("Digital signature: " + digSig.toString());
        System.out.println("Message: " + decMsg.toString());

        return decMsg;
    }

    public static byte[] stringToByteArray(String fname) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(fname));
        String str = br.readLine();
        String[] splitText = str.split("\\s+");
        int byteInt;
        byte[] byteArr = new byte[splitText.length];
        for (int i = 0; i < splitText.length; i++) {
            byteInt = Integer.parseInt(splitText[i], 16);
            byteArr[i] = (byte) byteInt;
        }
        return byteArr;
    }

    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {

        InputStream in =
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
}
