import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
import java.util.Scanner;
import java.nio.file.*;

public class KeyGen {
    public static void main(String[] args) throws Exception {

        Scanner scan = new Scanner(System.in);
        System.out.println("Enter 16-character key: ");
        String K = scan.next();

        // save to symmetric.key file
        byte[] Ksymmetric = K.getBytes("UTF8");
        for (byte x: Ksymmetric) {
            System.out.print(x + " ");
        }
        System.out.println();
        BufferedOutputStream sym_out = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        sym_out.write(Ksymmetric);
        sym_out.close();

        //Generate a pair of keys
        SecureRandom Xrandom = new SecureRandom();
        SecureRandom Yrandom = new SecureRandom();
        KeyPairGenerator Xgenerator = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator Ygenerator = KeyPairGenerator.getInstance("RSA");
        Xgenerator.initialize(1024, Xrandom);  //128: key size in bits
        Ygenerator.initialize(1024, Yrandom);  //128: key size in bits
        KeyPair Xpair = Xgenerator.generateKeyPair();
        KeyPair Ypair = Ygenerator.generateKeyPair();
        Key XpubKey = Xpair.getPublic(); // gets key
        Key XprivKey = Xpair.getPrivate(); // gets key
        Key YpubKey = Ypair.getPublic(); // gets key
        Key YprivKey = Ypair.getPrivate(); // gets key

    /* next, store the keys to files, read them back from files. */

        //get the parameters of the keys: modulus and exponent
        KeyFactory Xfactory = KeyFactory.getInstance("RSA"); // create key factory instance
        KeyFactory Yfactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec XpubKSpec = Xfactory.getKeySpec(XpubKey,
                RSAPublicKeySpec.class); // pub key converted into pub key "specification instance - pubKSpec"
        RSAPrivateKeySpec XprivKSpec = Xfactory.getKeySpec(XprivKey,
                RSAPrivateKeySpec.class); // priv key

        RSAPublicKeySpec YpubKSpec = Yfactory.getKeySpec(YpubKey,
                RSAPublicKeySpec.class); // pub key converted into pub key "specification instance - pubKSpec"
        RSAPrivateKeySpec YprivKSpec = Yfactory.getKeySpec(YprivKey,
                RSAPrivateKeySpec.class); // priv key

        //save the parameters of the keys to the files. Store keys to key files, then later read keys from file.
        saveToFile("XPublic.key", XpubKSpec.getModulus(),
                XpubKSpec.getPublicExponent()); // method gives us "n" from RSA slide - pubKSpec.getPublicExponent()
        saveToFile("XPrivate.key", XprivKSpec.getModulus(),
                XprivKSpec.getPrivateExponent()); // method gives us "e" from RSA slide - privKSpec.getPrivateExponent()

        saveToFile("YPublic.key", YpubKSpec.getModulus(),
                YpubKSpec.getPublicExponent()); // method gives us "n" from RSA slide - pubKSpec.getPublicExponent()
        saveToFile("YPrivate.key", YprivKSpec.getModulus(),
                YprivKSpec.getPrivateExponent()); // method gives us "e" from RSA slide - privKSpec.getPrivateExponent()

        // up to this point - we've generated keys.

        //now, read the keys back from the files
    }


    //save the prameters of the public and private keys to file
    public static void saveToFile(String fileName,
                                  BigInteger mod, BigInteger exp) throws IOException {

        System.out.println("Write to " + fileName + ": modulus = " +
                mod.toString() + ", exponent = " + exp.toString() + "\n");

        // only used for the public/private keys. Dont use for symmetric keys.
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }
}

