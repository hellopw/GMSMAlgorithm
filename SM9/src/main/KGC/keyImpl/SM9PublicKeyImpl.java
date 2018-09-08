package main.KGC.keyImpl;

import it.unisa.dia.gas.jpbc.Element;
import main.KGC.interfaces.SM9PublicKey;
import main.KGC.keyspec.SM9PublicKeySpec;

import java.io.*;

/**
 * Created by hellopw on 2018/9/4.
 */
public class SM9PublicKeyImpl extends SM9PublicKeySpec implements SM9PublicKey {

    Element ppub;
    SM9Parameter params;
    public SM9PublicKeyImpl(Element ppub, SM9Parameter params) {
        super(ppub, params);
    }

    @Override
    public String getAlgorithm() {
        return "SM9";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    /**
     * 仅返回 ppub的内容
     * params 的内容见 property 文件
     */
    public byte[] getEncoded() {
        byte[] b = null;
        if(ppub != null && params != null){
            b = ppub.toBytes();
        }
        return b;
    }

    /**
     * 导出公钥到文件
     * @param path
     */
    public void exportPublicKey(String path){
        try {
            FileOutputStream outputStream  =new FileOutputStream(new File(path));
            outputStream.write(this.getPpub().toBytes());
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 从文件获取公钥
     *    一般是先得到参数 然后在获取公钥
     * @param path
     * @param p
     * @return
     */
    public static SM9PublicKey importPublicKey(String path,SM9Parameter p){
        byte[] data;
        try {
            FileInputStream in =new FileInputStream(new File(path));
            //当文件没有结束时，每次读取一个字节显示
            data =new byte[in.available()];
            in.read(data);
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return  new SM9PublicKeyImpl(p.getG1().newElementFromBytes(data),p);
    }

}
