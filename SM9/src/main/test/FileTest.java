package main.test;

import main.common.Tools;
import main.crypt.Crypt;
import main.KGC.keyImpl.SM9KeyPairGenerator;
import main.KGC.keyImpl.SM9PrivateKeyImpl;
import main.KGC.keyImpl.SM9PublicKeyImpl;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.KeyPair;

/**
 * pgp 是随机生成enckey 然后公钥加密  贴在密文前面， 发给b  b先提取enckey的密文，用私钥解密得到enckey，再用enckey解密密文
 * sm9 可以用公钥封装 enckey，然后加密，然后将一个随机数和密文放一块 发送给b, b先提取密文中的随机数，利用随机数和私钥解封装enckey,然后再解密
 * sm9 并不是这样用。
 *
 * Created by hellopw on 2018/9/5.
 *
 */
public class FileTest {

    public static void main(String[] args) throws IOException {

        System.out.println("\n-------------秘钥产生阶段----------------");
        String ida = "hello";
        String idb = "peter";

        SM9KeyPairGenerator keyPairGenerator = new SM9KeyPairGenerator("SM9/src/res/a.properties", ida,(byte)0x3);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        SM9PublicKeyImpl pub_a = (SM9PublicKeyImpl) keyPair.getPublic();
        SM9PrivateKeyImpl pri_a = (SM9PrivateKeyImpl) keyPair.getPrivate();
        System.out.println("甲方公钥:\n" + pub_a);
        System.out.println("甲方私钥:\n" + pri_a);

        SM9KeyPairGenerator keyPairGenerator2 = new SM9KeyPairGenerator("SM9/src/res/a.properties", idb,(byte)0x3);
        KeyPair keyPair2 = keyPairGenerator2.generateKeyPair();
        SM9PublicKeyImpl pub_b = (SM9PublicKeyImpl) keyPair.getPublic();
        SM9PrivateKeyImpl pri_b = (SM9PrivateKeyImpl) keyPair.getPrivate();
        System.out.println("乙方公钥:\n" + pub_b);
        System.out.println("乙方私钥:\n" + pri_b);

        System.out.println("\n-------------文件加密阶段----------------");
        String path = "pairing/src/res/a.properties";
        byte[] source = toByteArray(path);
        Tools.printArray(source);

        //a->b  dest
        byte[] dest = Crypt.encrypt(pub_b,idb, source, (byte) 1);
        Tools.printArray(dest);

        System.out.println("\n-------------文件解密阶段----------------");

        byte[] source2 = Crypt.decrypt(pri_b,idb,dest, (byte) 1);
        Tools.printArray(source2);


    }

    /**
     * 把文件读成字节数组
     * @param filename
     * @return
     * @throws IOException
     */
    public static byte[] toByteArray(String filename) throws IOException {

        File f = new File(filename);
        if (!f.exists()) {
            throw new FileNotFoundException(filename);
        }

        FileChannel channel = null;
        FileInputStream fs = null;
        try {
            fs = new FileInputStream(f);
            channel = fs.getChannel();
            ByteBuffer byteBuffer = ByteBuffer.allocate((int) channel.size());
            while ((channel.read(byteBuffer)) > 0) {
                //do nothing
                //Tools.printArray(byteBuffer.array());
                //System.out.println("next");
            }
            return byteBuffer.array();
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        } finally {
            try {
                channel.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                fs.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


}