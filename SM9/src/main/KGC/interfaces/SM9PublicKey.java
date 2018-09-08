package main.KGC.interfaces;



import it.unisa.dia.gas.jpbc.Element;

import java.security.PublicKey;

/**
 * Created by hellopw on 2018/9/4.
 */
public interface SM9PublicKey extends PublicKey,SM9Key{
    /**
     * The class fingerprint that is set to indicate
     * serialization compatibility.
     */
    static final long serialVersionUID = -3314988629879632826L;

    /**
     * Returns the public point W.
     * @return the public point W.
     */
    Element getPpub();

}
