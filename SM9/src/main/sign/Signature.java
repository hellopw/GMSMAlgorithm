package main.sign;

import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by hellopw on 2018/9/5.
 */
public class Signature{
    Element h;
    Element S;

    public Signature(Element h, Element s) {
        this.h = h;
        S = s;
    }

    public Element getH() {
        return h;
    }

    public void setH(Element h) {
        this.h = h;
    }

    public Element getS() {
        return S;
    }

    public void setS(Element s) {
        S = s;
    }
}
