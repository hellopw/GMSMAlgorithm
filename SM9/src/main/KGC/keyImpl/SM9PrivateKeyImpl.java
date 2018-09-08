package main.KGC.keyImpl;

import it.unisa.dia.gas.jpbc.Element;
import main.KGC.interfaces.SM9PrivateKey;
import main.KGC.keyspec.SM9PrivateKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Created by hellopw on 2018/9/4.
 */
public class SM9PrivateKeyImpl extends SM9PrivateKeySpec implements SM9PrivateKey {
    Element s;
    SM9Parameter params;

    public SM9PrivateKeyImpl(Element s, SM9Parameter params) {
        super(s, params);
    }

    @Override
    public String getAlgorithm() {
        return "sm9";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        byte[] b = null;
        if(s != null && params != null){
            b = s.toBytes();
        }
        return b;
    }

    /**
     * 导出公钥到文件
     * @param path
     */
    public void exportPrivateKey(String path){
        try {
            FileOutputStream outputStream  =new FileOutputStream(new File(path));
            outputStream.write(this.getS().toBytes());
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
    public static SM9PrivateKey importPrivateKey(String path,SM9Parameter p){
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
        return  new SM9PrivateKeyImpl(p.getZr().newElementFromBytes(data),p);
    }
}
