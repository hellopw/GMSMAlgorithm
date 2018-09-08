package main.KGC.keyImpl;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.*;

/**
 * pair 不同   两次生成的公私钥和参数都不同
 * pair 相同  id和hid不同  两次生成的参数相同，公私钥不同
 * Created by hellopw on 2018/9/4.
 */
public class SM9KeyPairGenerator extends KeyPairGeneratorSpi{

    private SM9Parameter p;
    private Element Ppub;
    private Element s;

    private String ID;

    public SM9KeyPairGenerator(String paramspath, String ID,byte hid){
        Pairing pair = PairingFactory.getPairing(paramspath);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        if (!pair.isSymmetric()) {
            throw new RuntimeException("密钥不对称!");
        }

        this.p = new SM9Parameter(pair);
        this.ID = ID;

        switch(hid){
            case 0x3:     //03表示密钥解封和解密的私钥
                enc_generate(ID);
                break;
            case 0x1:      //01表示签名私钥
                sign_generate(ID);
                break;
            case 0x2:     //02表示密钥交换的私钥
                KeyExc_generate(ID);
                break;
            default:
                throw new RuntimeException("没有秘钥类型");
        }
    }

    /**
     * 生成公私钥
     */
    private void enc_generate(String id){
        s = p.getPair().getZr().newRandomElement().getImmutable();    //加密主私钥   秘密保存
        Ppub = p.getP1().duplicate().mulZn(s);        //公开   加密主公钥
    }

    private void sign_generate(String id){
        s = p.getPair().getZr().newRandomElement().getImmutable();    //加密主私钥   秘密保存
        Ppub = p.getP2().duplicate().mulZn(s);        //公开   加密主公钥
    }

    private void KeyExc_generate(String id){
        s = p.getPair().getZr().newRandomElement().getImmutable();    //加密主私钥   秘密保存
        Ppub = p.getP2().duplicate().mulZn(s);        //公开   加密主公钥

    }

    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    public KeyPair generateKeyPair(){
        SM9PublicKeyImpl pub = new SM9PublicKeyImpl(Ppub,p);
        SM9PrivateKeyImpl pri = new SM9PrivateKeyImpl(s,p);
        return new KeyPair(pub,pri);
    }

}
