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

public class Receiver {

    private static int BUFFER_SIZE = 32 * 1024;
    public static String messageHash;
    public static byte[] hashByte;
    public static String symmetricKey;
    public static byte[] symmetricBytes;
    public static String dsMsg;
    public static PrivateKey XprivKey2;
    Scanner scan = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
              
        String encryptedFile;
        System.out.println("Input the name of the message file: ");
        encryptedFile = scan.nextLine();

        


    }
}