package main.KGC.interfaces;

import main.KGC.keyImpl.SM9Parameter;

/**
 * Created by hellopw on 2018/9/4.
 */
public interface SM9Key {
    /**
     * Returns the domain parameters associated
     * with this key. The domain parameters are
     * either explicitly specified or implicitly
     * created during key generation.
     * @return the associated domain parameters.
     */
    SM9Parameter getParams();

}
