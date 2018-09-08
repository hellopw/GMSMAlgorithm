package main.sign;


import it.unisa.dia.gas.jpbc.Element;

import main.common.Tools;
import main.KGC.interfaces.SM9PrivateKey;
import main.KGC.interfaces.SM9PublicKey;
import main.KGC.keyImpl.SM9Parameter;

/**
 * Created by hellopw on 2018/8/31.
 */
public class Sign {

    /**
     * 公私钥签名
     * @param M        待签名数据
     * @param pub      公钥
     * @param pri       私钥
     * @param ID        id
     * @return         返回签名
     */
    public static Signature sign(byte[] M, SM9PublicKey pub, SM9PrivateKey pri, String ID){

        SM9Parameter p = (SM9Parameter) pub.getParams();
        Element Ppub = pub.getPpub();
        Element s = pri.getS();

        Element g = p.getPair().pairing(p.getP1().duplicate(),Ppub.duplicate());

        Element l;
        Element h;
        do {
            Element r = p.getZr().newRandomElement();
            Element w = g.duplicate().powZn(r.duplicate());

            byte[] b = Tools.join(M, w.toBytes());
            h = Tools.hash_1(p,b);

            l = r.duplicate().sub(h.duplicate());
        }while(l.isZero());

        Element t1 = s.duplicate().add(Tools.hash_id(p,ID));   //t1未检查是否是1
        Element t2 = s.duplicate().mul(t1.invert());
        Element Su = p.getP1().duplicate().mulZn(t2);         //加密私钥

        Element S = Su.duplicate().mulZn(l);

        return new Signature(h,S);
    }

    /**
     * 公钥验签
     * @param M    待签名数据
     * @param s       签名
     * @param pub      公钥
     * @param ID        id
     * @return     验证成功，返回true。失败，返回false
     */
    public static boolean verify(byte[] M, Signature s, SM9PublicKey pub,String ID){
        SM9Parameter p = (SM9Parameter) pub.getParams();
        Element Ppub = pub.getPpub();

        if(!s.getH().getField().equals(p.getZr())){
            return false;
        }
        if(!s.getS().getField().equals(p.getG1())){
            return false;
        }

        Element g = p.getPair().pairing(p.getP1(),Ppub);
        Element t = g.duplicate().powZn(s.getH());
        Element h1 = Tools.hash_1(p,ID.getBytes());

        Element P = p.getP2().duplicate().mulZn(h1.duplicate()).duplicate().add(Ppub.duplicate());
        Element u = p.getPair().pairing(s.getS(),P);
        Element w1 = u.duplicate().mul(t);

        Element h2 = Tools.hash_1(p,Tools.join(M,w1.toBytes()));
        if(h2.equals(s.getH())){
            return true;
        }
        return false;
    }

}

