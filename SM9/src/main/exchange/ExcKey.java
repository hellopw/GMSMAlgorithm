package main.exchange;


import it.unisa.dia.gas.jpbc.Element;
import main.common.Tools;
import main.KGC.interfaces.SM9PrivateKey;
import main.KGC.interfaces.SM9PublicKey;
import main.KGC.keyImpl.SM9Parameter;


import java.util.Arrays;



/**
 * 第12步生成
 * 第34步验证
 *
 * 1234不同时使用
 * 13步是1组
 * 24步是1组
 * 参数也分开使用，即a组参数赋值时，b组参数是null.b组参数赋值时，a组参数是null
 *
 * Created by hellopw on 2018/8/28.
 */

public class ExcKey {
    private final int klen = 48;    //kdf 压缩长度

    /**
     * a组参数
     */
    private Element ra;   //做发起者时用，第1步生成，第3步用
    private Element Ra;    //第1步生成，第3步用

    private byte[] Sb;       //验证用的，第2步生成，第3步时用
    private byte[] SKa;     //发起者协商好的秘钥  第3步生成

    public Element getRa() {
        return ra;
    }

    public byte[] getSb() {
        return Sb;
    }

    public byte[] getSKa() {
        return SKa;
    }

    public Element getRa1() {
        return Ra1;
    }

    public Element getRb() {
        return Rb;
    }

    public Element getG1() {
        return g1;
    }

    public Element getG2() {
        return g2;
    }

    public Element getG3() {
        return g3;
    }

    public byte[] getSa() {
        return Sa;
    }

    public byte[] getSKb() {
        return SKb;
    }

    /**
     * b组参数
     */
    private Element Ra1;       //第1步生成Ra，第2步赋值用Ra赋值，第4步用
    private Element Rb;      //第2步生成，第4步用
    private Element g1,g2,g3;      //响应者第2步生成   第4步用

    private byte[] Sa;       //验证用的，第3步生成，第4步时用
    private byte[] SKb;      //响应者协商好的秘钥  第2步生成


    /**
     * a是自己  b是对方
     * @param pub_b   对方公钥
     * @param idb    对方id
     * @return
     */
    public Element first(SM9PublicKey pub_b, String idb){
        SM9Parameter params = (SM9Parameter) pub_b.getParams();
        Element Ppub = pub_b.getPpub();

        Element Qb = params.getP1().duplicate().mulZn(Tools.hash_id(params,idb)).duplicate().add(Ppub);

        Element ra = params.getZr().newRandomElement();
        this.ra = ra;

        Element Ra = Qb.duplicate().mulZn(ra);
        this.Ra = Ra;
        return Ra;
    }

    /**
     *  a是对方    b是自己
     * @param ida    对方id
     * @param idb     自己的id
     * @param pub_a    对方公钥
     * @param pri_b    自己的私钥
     * @param Ra       对方传过来的内容
     * @return
     */
    public Element second(String ida, String idb, SM9PublicKey pub_a, SM9PrivateKey pri_b, Element Ra){
        SM9Parameter params = (SM9Parameter) pub_a.getParams();
        Element Ppub = pub_a.getPpub();
        Element s = pri_b.getS();
        this.Ra1 = Ra;

        Element t1 = s.duplicate().add(Tools.hash_id(params,idb));   //t1未检查是否是1
        Element t2 = s.duplicate().mul(t1.invert());
        Element Su = params.getP2().duplicate().mulZn(t2);         //加密私钥

        Element Qa = params.getP1().duplicate().mulZn(Tools.hash_id(params,ida)).duplicate().add(Ppub);

        Element rb = params.getZr().newRandomElement();

        Element Rb = Qa.duplicate().mulZn(rb);
        this.Rb = Rb;

        if(!Tools.checkG1(params.getG1(),Ra)){
            throw new RuntimeException("xie shang shi bai  2");
        }

        g1 = params.getPair().pairing(Ra,Su);
        g2 = params.getPair().pairing(Ppub,params.getP2()).duplicate().powZn(rb);
        g3 = g1.duplicate().powZn(rb);


        byte[] SKb = Tools.KDF(Tools.join(ida.getBytes(),idb.getBytes(),Ra.toBytes(),Rb.toBytes(),g1.toBytes(),g2.toBytes(),g3.toBytes()),klen);
        this.SKb = SKb;

        byte[] tmp1 = {(byte)0x82};
        byte[] tmp = Tools.sm3hash(Tools.join(g2.toBytes(),g3.toBytes(),ida.getBytes(),idb.getBytes(),Ra.toBytes(),Rb.toBytes()));
        byte[] Sb = Tools.sm3hash(tmp1,g1.toBytes(),tmp);
        this.Sb = Sb;



        return Rb;
    }

    /**
     * 接first  a是自己   b是对方
     * @param pub_b
     * @param pri_a
     * @param Rb
     * @param ida
     * @param idb
     */
    public void third(String ida,String idb,SM9PublicKey pub_b,SM9PrivateKey pri_a,Element Rb,byte[] Sb) {
        SM9Parameter params = (SM9Parameter) pub_b.getParams();
        Element Ppub = pub_b.getPpub();
        Element s = pri_a.getS();

        Element t1 = s.duplicate().add(Tools.hash_id(params,ida));   //pri是a,则id是a,  pri是b,则id是b
        Element t2 = s.duplicate().mul(t1.invert());
        Element Su = params.getP2().duplicate().mulZn(t2);


        if(!Tools.checkG1(params.getG1(),Rb)){
            throw new RuntimeException("xie shang shi bai  3  can shu bu dui ");
        }

        Element g1 = params.getPair().pairing(Ppub,params.getP2()).duplicate().powZn(ra);
        Element g2 = params.getPair().pairing(Rb,Su);
        Element g3 = g2.duplicate().powZn(ra);

        byte[] tmp2 = {(byte)0x82};
        byte[] mmm = Tools.join(g2.toBytes(),g3.toBytes(),ida.getBytes(),idb.getBytes(),Ra.toBytes(),Rb.toBytes());
        byte[] tmp3 = Tools.sm3hash(mmm);
        byte[] S1 = Tools.sm3hash(tmp2,g1.toBytes(),tmp3);


        if(!Arrays.equals(S1,Sb)){
            throw new RuntimeException("xie shagn shi abi   3");
        }

        byte[] SKa = Tools.KDF(Tools.join(ida.getBytes(),idb.getBytes(),Ra.toBytes(),Rb.toBytes(),g1.toBytes(),g2.toBytes(),g3.toBytes()),klen);
        this.SKa = SKa;

        byte[] tmp1 = {(byte)0x83};
        byte[] tmp = Tools.sm3hash(Tools.join(g2.toBytes(),g3.toBytes(),ida.getBytes(),idb.getBytes(),Ra.toBytes(),Rb.toBytes()));
        byte[] Sa = Tools.sm3hash(tmp1,g1.toBytes(),tmp);
        this.Sa = Sa;
    }

    /**
     * 接第2步  a是对方   b是自己
     * @param ida   对方id
     * @param idb   自己id
     * @param Sa    对方穿过来的信息
     */
    public void forth(String ida,String idb,byte[] Sa){
        byte[] tmp1 = {(byte)0x83};
        byte[] tmp = Tools.sm3hash(Tools.join(g2.toBytes(),g3.toBytes(),ida.getBytes(),idb.getBytes(),Ra1.toBytes(),Rb.toBytes()));
        byte[] S2 = Tools.sm3hash(tmp1,g1.toBytes(),tmp);

        if(!Arrays.equals(S2,Sa)){
            throw new RuntimeException("xie shang shi aba  4");
        }
    }

}
