package main.KGC.interfaces;


import it.unisa.dia.gas.jpbc.Element;
import java.security.PrivateKey;


/**
 * Created by hellopw on 2018/9/4.
 */
public interface SM9PrivateKey extends PrivateKey, SM9Key {
    /**
     * The class fingerprint that is set to indicate
     * serialization compatibility.
     */
    static final long serialVersionUID = -7896394956925609184L;

    /**
     * Returns the private value S.
     * @return the private value S.
     */
    Element getS();

}
