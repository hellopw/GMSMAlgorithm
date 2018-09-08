package test.main.wrap;

import main.crypt.MACCoder;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

/**
 * MACCoder Tester.
 *
 * @author <auther name>
 * @version 1.0
 * @since <pre>08/28/2018</pre>
 */
public class MACCoderTest {
    MACCoder mc = new MACCoder();

    @Before
    public void before() throws Exception {
        System.out.println("start: ");
    }

    @After
    public void after() throws Exception {
        System.out.println();
        System.out.println("end!");
        System.out.println();
    }

    /**
     * Method: encodeHmacMD2(byte[] data, byte[] key)
     */
    @Test
    public void testEncodeHmacMD2() throws Exception {
//TODO: Test goes here...
        String s = "dddddddd";
        String key = "ssss";
        for (byte aC : mc.encodeHmacMD2(s.getBytes(), key.getBytes())) {
            System.out.print(Integer.toHexString(aC & 0xff) + " ");
        }
    }

    /**
     * Method: encodeHmacMD4(byte[] data, byte[] key)
     */
    @Test
    public void testEncodeHmacMD4() throws Exception {
//TODO: Test goes here...
        String s = "dddddddd";
        String key = "ssss";
        for (byte aC : mc.encodeHmacMD4(s.getBytes(), key.getBytes())) {
            System.out.print(Integer.toHexString(aC & 0xff) + " ");
        }
    }

    /**
     * Method: encodeHmacSHA224(byte[] data, byte[] key)
     */
    @Test
    public void testEncodeHmacSHA224() throws Exception {
//TODO: Test goes here...
        String s = "dddddddd";
        String key = "ssss";
        for (byte aC : mc.encodeHmacSHA224(s.getBytes(), key.getBytes())) {
            System.out.print(Integer.toHexString(aC & 0xff) + " ");
        }
    }

} 
