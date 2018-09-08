package main.KGC.keyImpl;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Created by hellopw on 2018/9/4.
 */
public class SM9Parameter implements AlgorithmParameterSpec,Serializable{

    static final long serialVersionUID = -789639495692560944L;

    /**
     * 必要的参数
     */
    private Pairing pair;     //pair
    private Element P1;          //两个随机的基点
    private Element P2;

    /**
     * 这3个参数为了方便使用
     * 可以由pairing唯一确定
     */
    private Field G1,G2,Zr;         //两个群

    /**
     * 利用给定的参数生成一个参数类
     * pairing和P1和P2 都是给定的
     * @param p
     * @param P1
     * @param P2
     */
    public SM9Parameter(Pairing p, Element P1, Element P2){
        if(p == null){
            throw new NullPointerException("pairing is null");
        }
        if (P1 == null) {
            throw new NullPointerException("P1 is null");
        }
        if (P2 == null) {
            throw new NullPointerException("P2 is null");
        }

        /**
         * 判断配对是否为对称配对，不对称则输出错误信息
         *
         * @param pairing
         */
        if(!p.isSymmetric()){
            throw new IllegalArgumentException("秘钥不对称");
        }
        init(p);
        this.P1 = P1;
        this.P2 = P2;
    }

    /**
     * 给定pairing
     * 随机生成P1和P2
     * @param p
     */
    public SM9Parameter(Pairing p){
        if(p == null){
            throw new NullPointerException("p is null");
        }
        if(!p.isSymmetric()){
            throw new IllegalArgumentException("秘钥不对称");
        }
        init(p);
        P1 = p.getG1().newRandomElement();
        P2 = p.getG2().newRandomElement();
    }

    /**
     * pairing 由 文件获取
     * P1和P2随机生成
     */
    public SM9Parameter(String path){
        Pairing p = PairingFactory.getPairing(path);//
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if(p == null){
            throw new NullPointerException("p is null");
        }
        if(!p.isSymmetric()){
            throw new IllegalArgumentException("秘钥不对称");
        }
        init(p);
        P1 = p.getG1().newRandomElement();
        P2 = p.getG2().newRandomElement();
    }

    /**
     * pairing 动态产生 有rbit 和 qbit决定
     * P1和P2 随机产生
     */
    public SM9Parameter(int rBit, int qBit){
        TypeACurveGenerator pg = new TypeACurveGenerator(rBit, qBit);
        //TypeA1CurveGenerator pg = new TypeA1CurveGenerator(rBit, qBit);
        PairingParameters typeAParams = pg.generate();
        Pairing p = PairingFactory.getPairing(typeAParams);

        if(p == null){
            throw new NullPointerException("p is null");
        }
        if(!p.isSymmetric()){
            throw new IllegalArgumentException("秘钥不对称");
        }
        init(p);
        P1 = p.getG1().newRandomElement();
        P2 = p.getG2().newRandomElement();
    }

    private void init(Pairing p){
        this.pair = p;

        G1 = pair.getG1();
        G2 = pair.getG2();
        Zr = pair.getZr();

    }

    public Field getZr() {
        return Zr;
    }

    public Field getG1() {
        return G1;
    }

    public Field getG2() {
        return G2;
    }

    public Pairing getPair() {
        return pair;
    }

    public Element getP1() {
        return P1;
    }

    public Element getP2() {
        return P2;
    }

}
