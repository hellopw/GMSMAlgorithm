package main.KGC.keyspec;


import it.unisa.dia.gas.jpbc.Element;
import main.KGC.keyImpl.SM9Parameter;

import java.security.spec.KeySpec;

/**
 * Created by hellopw on 2018/9/4.
 */
public class SM9PublicKeySpec implements KeySpec {
    Element Ppub;
    SM9Parameter params;

    public SM9PublicKeySpec(Element ppub, SM9Parameter params) {
        if (ppub == null) {
            throw new NullPointerException("ppub is null");
        }
        if (params == null) {
            throw new NullPointerException("params is null");
        }
        if (!ppub.getField().equals(params.getG1())) {
            throw new IllegalArgumentException("ppub is the element of field of the field G1 of the pairing");
        }
        Ppub = ppub;
        this.params = params;
    }

    public Element getPpub() {
        return Ppub;
    }

    public SM9Parameter getParams() {
        return params;
    }

}
