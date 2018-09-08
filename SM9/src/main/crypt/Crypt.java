package main.crypt;

import main.OP_MODE;
import main.SM4;
import main.common.Tools;
import main.KGC.interfaces.SM9PrivateKey;
import main.KGC.interfaces.SM9PublicKey;
import main.wrap.Wrap;
import java.util.Arrays;

/**
 * 基于标识的密码
 * 这样可以省去协商加密秘钥的过程
 * Created by hellopw on 2018/8/28.
 */
public class Crypt {

    /**
     *   公钥加密  先封装产生对称的加密秘钥 和 mac秘钥 和 封装结果 C1，然后加密得到 C2, 对C2进行mac得到 C3
     * @param pub     用户公钥
     * @param id      用户标识
     * @param data     明文数据
     * @param block_seq    流加密还是分组加密
     * @return        返回密文   (C1 (128byte) ,C3 (16byte),C2 (不定长))  3部分
     */
    public static byte[] encrypt(SM9PublicKey pub,String id,byte[] data, byte block_seq){
        byte[] key = Wrap.wrap(pub,id);

        byte[] C1 = new byte[128];
        byte[] C3 = new byte[16];
        byte[] C2;

        SM4 sm4 = new SM4();

        byte[] enckey = new byte[16];
        byte[] mackey = new byte[32];
        System.arraycopy(key, 0, C1, 0, 128);
        System.arraycopy(key, 128, enckey, 0, 16);
        System.arraycopy(key, 144, mackey, 0, 32);

        switch (block_seq) {
            case 1:     //cbc
                C2 = sm4.encodeSMS4(data, enckey, OP_MODE.CBC);
                break;
            case 2:    //ecb
                C2 = sm4.encodeSMS4(data, enckey,OP_MODE.ECB);
                break;
            default:      //默认cbc
                C2 = sm4.encodeSMS4(data, enckey,OP_MODE.CBC);
        }

        C3 = MACCoder.encodeHmacMD2(C2, mackey);

        return Tools.join(C1, C3, C2);

    }

    /**
     *  私钥解密  先从密文中提取 C1，再解封装得到对称的加密秘钥，和 mac秘钥，然后验证mac, 最后解密C2
     * @param pri     用户私钥
     * @param id      用户标识
     * @param CipherText       密文  (C1 (128byte) ,C3 (16byte),C2 (不定长))  3部分
     * @param block_seq       流加密还是分组加密
     * @return          返回明文
     */
    public static byte[] decrypt(SM9PrivateKey pri,String id,byte[] CipherText, byte block_seq){
        byte[] C1 = new byte[128];
        byte[] C3 = new byte[16];
        byte[] C2;

        System.arraycopy(CipherText, 0, C1, 0, C1.length);

        byte[] key = Wrap.unwrap(pri,id,C1);

        SM4 sm4 = new SM4();

        byte[] result_data;


        System.arraycopy(CipherText, C1.length, C3, 0, C3.length);

        byte[] enckey = new byte[16];
        byte[] mackey = new byte[32];
        System.arraycopy(key, 0, enckey, 0, 16);
        System.arraycopy(key, 16, mackey, 0, 32);

        C2 = new byte[CipherText.length - C1.length - C3.length];
        System.arraycopy(CipherText, C1.length + C3.length, C2, 0, C2.length);

        byte[] C3_1 = MACCoder.encodeHmacMD2(C2, mackey);

        if (Arrays.equals(C3, C3_1)) {
            switch (block_seq) {
                case 1:     //cbc
                    result_data = sm4.decodeSMS4(C2, enckey,OP_MODE.CBC);
                    break;
                case 2:    //ecb
                    result_data = sm4.decodeSMS4(C2, enckey,OP_MODE.ECB);
                    break;
                default:      //默认ecb
                    result_data = sm4.decodeSMS4(C2, enckey,OP_MODE.CBC);
            }
        } else {
            throw new RuntimeException("mac错误");
        }

        return result_data;

    }
}


