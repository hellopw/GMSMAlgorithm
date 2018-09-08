package main.KGC.keyspec;


import it.unisa.dia.gas.jpbc.Element;
import main.KGC.keyImpl.SM9Parameter;

import java.security.spec.KeySpec;

/**
 * Created by hellopw on 2018/9/4.
 */
public class SM9PrivateKeySpec implements KeySpec{
    Element s;
    SM9Parameter params;

    public SM9PrivateKeySpec(Element s, SM9Parameter params) {
        if (s == null) {
            throw new NullPointerException("s is null");
        }
        if (params == null) {
            throw new NullPointerException("params is null");
        }
        if(!s.getField().equals(params.getZr())){
            throw new IllegalArgumentException("s is not the element of the  field Zr of pairing");
        }
        this.s = s;
        this.params = params;
    }

    public Element getS() {
        return s;
    }

    public SM9Parameter getParams() {
        return params;
    }

}
