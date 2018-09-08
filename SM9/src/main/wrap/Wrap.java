package main.wrap;

import it.unisa.dia.gas.jpbc.Element;
import main.common.Tools;
import main.KGC.interfaces.SM9PrivateKey;
import main.KGC.interfaces.SM9PublicKey;
import main.KGC.keyImpl.SM9Parameter;

/**
 * Created by hellopw on 2018/9/4.
 */

public class Wrap {

    /**
     *
     * @param pub     对方公钥
     * @param id       对方id
     * @return   前128个字节是 C   中间16个字节是 enckey   最后32个字节是mackey
     */
    public static byte[] wrap(SM9PublicKey pub, String id) {
        SM9Parameter params = (SM9Parameter) pub.getParams();
        Element Ppub = pub.getPpub();

        Element tmp = Tools.hash_id(params,id);
        Element Qb = params.getP1().duplicate().mulZn(tmp).duplicate().add(Ppub);

        Element r = params.getPair().getZr().newRandomElement().getImmutable();
        Element C = Qb.duplicate().mulZn(r);

        Element g = params.getPair().pairing(Ppub, params.getP2());
        Element w = g.duplicate().powZn(r.duplicate());

        byte[] b = Tools.join(C.toBytes(), w.toBytes(), id.getBytes());
        byte[] c = Tools.KDF(b, 48);       //这是封装后的秘钥

        return Tools.join(C.toBytes(),c);    //顺序一定不能反     这个是要发给另一方的C和秘钥

    }

    /**
     *
     * @param pri     自己的私钥
     * @param id       自己id
     * @param result     wrap 后的结果
     * @return          前16个字节是 enckey   最后32个字节是mackey
     */
    public static byte[] unwrap(SM9PrivateKey pri, String id, byte[] result) {
        SM9Parameter params = (SM9Parameter) pri.getParams();
        Element s = pri.getS();

        byte[] cbyte = new byte[128];
        System.arraycopy(result,0,cbyte,0,128);
        Element C = params.getG1().newElementFromBytes(cbyte);

        Element t1 = s.duplicate().add(Tools.hash_id(params,id));   //t1未检查是否是1
        Element t2 = s.duplicate().mul(t1.invert());
        Element Su = params.getP2().duplicate().mulZn(t2);         //加密私钥


        if (Tools.checkG1(params.getG1(), C)) {
            Element w1 = params.getPair().pairing(C, Su);
            byte[] b = Tools.join(C.toBytes(), w1.toBytes(), id.getBytes());
            return Tools.KDF(b, 48);       //返回的是封装的秘钥
        } else {
            throw new RuntimeException("秘钥验证错误!");
        }

    }

}
