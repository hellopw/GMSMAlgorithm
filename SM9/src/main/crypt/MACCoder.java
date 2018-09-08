package main.crypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by hellopw on 2018/8/28.
 */
public class MACCoder {

    private static byte[] generate(byte[] data,SecretKey secretKey){
        Mac mac = null;
        byte[] digest = new byte[0];
        try {
            mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            digest = mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return digest;
    }

    public static byte[] encodeHmacMD2(byte[] data,byte[] key){
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey = new SecretKeySpec(key, "HmacMD2");

        return generate(data,secretKey);
    }

    public static byte[] encodeHmacMD4(byte[] data,byte[] key){
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey = new SecretKeySpec(key, "HmacMD4");

        return generate(data,secretKey);
    }

    public static byte[] encodeHmacSHA224(byte[] data,byte[] key){
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA224");

        return generate(data,secretKey);
    }

}
