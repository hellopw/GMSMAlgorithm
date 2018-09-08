package main.common;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import main.SM3;
import main.KGC.keyImpl.SM9Parameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Created by hellopw on 2018/8/27.
 */
public class Tools {

    /**
     * 秘钥派生函数    把秘钥压缩成klen个byte
     * @param Z         待压缩秘钥
     * @param klen       压缩后长度
     * @return
     */
    public static byte[] KDF(byte[] Z, int klen) {
        int ct = 1;
        int end = (int) Math.ceil(klen * 1.0 / 32);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            for (int i = 1; i < end; i++) {
                baos.write(sm3hash(Z, SM3.toByteArray(ct)));
                ct++;
            }
            byte[] last = sm3hash(Z, SM3.toByteArray(ct));
            if (klen % 32 == 0) {
                baos.write(last);
            } else
                baos.write(last, 0, klen % 32);
            return baos.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * sm3摘要
     * @param params
     * @return
     */
    public static byte[] sm3hash(byte[]... params) {
        byte[] res = null;
        try {
            res = SM3.hash(join(params));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return res;
    }

    /**
     * byte数组的拼接
     * @param params     不定长参数
     * @return    拼接后的byte数组
     */
    public static byte[] join(byte[]... params) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] res = null;
        try {
            for (int i = 0; i < params.length; i++) {
                baos.write(params[i]);
            }
            res = baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return res;
    }

    /**
     * 检查  C是否是 群G的元素  即（曲线G上的点）
     * @param G 群
     * @param C 元素
     * @return 是，返回true  不是，返回false
     */
    public static boolean checkG1(Field G, Element C) {
        return C.getField().equals(G);
    }

    /**
     *
     * @param data
     * @return     长度恰为v比特的杂凑值
     */
    public static byte[] hash_v(byte[] data){
        byte[] res = null;
        try {
            res = SM3.hash(data);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return res;
    }

    /**
     *
     * @param p     p决定Zr
     * @param id     待哈希数据
     * @return      输出是群Zr中的元素
     */
    public static Element hash_id(SM9Parameter p, String id) {
        byte[] byte_identity = id.getBytes();
        byte[] hash = hash_v(byte_identity);
        return p.getPair().getZr().newElement().setFromHash(hash, 0, byte_identity.length);
    }

    /**
     *
     * @param p     p决定Zr
     * @param z     待哈希数据
     * @return      输出是群Zr中的元素
     */
    public static Element hash_1(SM9Parameter p, byte[] z){
        byte[] hash = hash_v(z);
        Element x;
        do{
            x = p.getZr().newElement().setFromHash(hash,0,z.length);
        }
        while(!x.getField().equals(p.getZr()));
        return x;
    }

    public static void printArray(byte[] c){
        for (byte aB : c) {
            System.out.print(Integer.toHexString(aB & 0xff) + " ");
        }
        System.out.println();
    }

}
